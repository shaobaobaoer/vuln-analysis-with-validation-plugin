"""
Pipeline orchestrator for end-to-end vulnerability analysis.

Coordinates all stages of the analysis workflow:

    1. Load configuration and manifest
    2. Build / start Docker environment
    3. Wait for target health
    4. Discover PoC scripts
    5. Execute PoCs against the target
    6. Validate results with type-specific validators
    7. Generate reports (Markdown + JSON)
    8. Tear down Docker environment

Includes state persistence (pipeline_state.json) and a retry loop
with a configurable maximum retry count.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .reporters.json_summary import generate_summary, write_summary
from .reporters.markdown import generate_report
from .runner import ExecutionResult, PoCRunner
from .runners.docker_manager import ContainerInfo, DockerManager
from .validators.registry import get_validator

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Pipeline state management
# ------------------------------------------------------------------

class PipelineStage(str, Enum):
    """Enumeration of pipeline stages in execution order."""

    INIT = "init"
    BUILD_ENV = "build_env"
    START_ENV = "start_env"
    HEALTH_CHECK = "health_check"
    DISCOVER_POCS = "discover_pocs"
    EXECUTE_POCS = "execute_pocs"
    VALIDATE = "validate"
    REPORT = "report"
    TEARDOWN = "teardown"
    COMPLETED = "completed"

@dataclass
class PipelineState:
    """Serialisable pipeline execution state for resume / audit."""

    current_stage: str = PipelineStage.INIT.value
    completed_stages: list[str] = field(default_factory=list)
    retry_count: int = 0
    container_id: Optional[str] = None
    image_tag: Optional[str] = None
    errors: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def save(self, path: str) -> None:
        """Persist state to a JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, default=str)

    @classmethod
    def load(cls, path: str) -> PipelineState:
        """Load state from a JSON file. Returns fresh state if missing."""
        p = Path(path)
        if not p.exists():
            return cls()
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(**data)


# ------------------------------------------------------------------
# Pipeline configuration
# ------------------------------------------------------------------

@dataclass
class PipelineConfig:
    """All tuneable knobs for a pipeline run."""

    # Target
    target_name: str = "target"
    target_url: str = "http://localhost:8080"
    target_version: str = ""

    # Docker
    docker_context: str = "."
    dockerfile: str = "Dockerfile"
    image_tag: str = "vuln-target:latest"
    container_name: str = "vuln-target"
    ports: dict[str, str] = field(default_factory=lambda: {"8080": "8080"})
    env_vars: dict[str, str] = field(default_factory=dict)
    health_url: str = "http://localhost:8080/"
    health_timeout: int = 60

    # PoCs
    scripts_dir: str = "./pocs"
    poc_timeout: int = 30
    parallel_execution: bool = False
    max_workers: int = 4

    # Pipeline
    max_retries: int = 5
    output_dir: str = "./output"
    state_file: str = "./output/pipeline_state.json"

    # Environment metadata (for reports)
    environment: dict[str, str] = field(default_factory=dict)


# ------------------------------------------------------------------
# Main pipeline
# ------------------------------------------------------------------

class VulnPipeline:
    """Orchestrates the full vulnerability analysis workflow.

    Usage::

        config = PipelineConfig(
            target_url="http://localhost:8080",
            scripts_dir="./pocs",
            docker_context="./targets/webapp",
        )
        pipeline = VulnPipeline(config)
        pipeline.run()
    """

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self.docker = DockerManager()
        self.state = PipelineState.load(config.state_file)
        self._container: Optional[ContainerInfo] = None
        self._runner: Optional[PoCRunner] = None
        self._execution_results: list[ExecutionResult] = []
        self._validated_results: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> list[dict[str, Any]]:
        """Execute the full pipeline with retry logic.

        Returns:
            The list of validated result dicts.
        """
        self.state.started_at = _now_iso()
        self._save_state()

        stages = [
            (PipelineStage.BUILD_ENV, self._stage_build_env),
            (PipelineStage.START_ENV, self._stage_start_env),
            (PipelineStage.HEALTH_CHECK, self._stage_health_check),
            (PipelineStage.DISCOVER_POCS, self._stage_discover_pocs),
            (PipelineStage.EXECUTE_POCS, self._stage_execute_pocs),
            (PipelineStage.VALIDATE, self._stage_validate),
            (PipelineStage.REPORT, self._stage_report),
            (PipelineStage.TEARDOWN, self._stage_teardown),
        ]

        for stage, handler in stages:
            # Skip already-completed stages (resume support)
            if stage.value in self.state.completed_stages:
                logger.info("Skipping already-completed stage: %s", stage.value)
                continue

            success = self._run_stage_with_retry(stage, handler)
            if not success:
                logger.error(
                    "Stage %s failed after %d retries. Aborting pipeline.",
                    stage.value,
                    self.config.max_retries,
                )
                # Ensure teardown still happens
                self._stage_teardown()
                break

        self.state.current_stage = PipelineStage.COMPLETED.value
        self.state.finished_at = _now_iso()
        self._save_state()

        return self._validated_results

    # ------------------------------------------------------------------
    # Retry wrapper
    # ------------------------------------------------------------------

    def _run_stage_with_retry(
        self,
        stage: PipelineStage,
        handler: Any,
    ) -> bool:
        """Run a pipeline stage, retrying up to max_retries on failure."""
        self.state.current_stage = stage.value
        self._save_state()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                logger.info(
                    "Running stage %s (attempt %d/%d)",
                    stage.value,
                    attempt,
                    self.config.max_retries,
                )
                handler()
                self.state.completed_stages.append(stage.value)
                self.state.retry_count = 0
                self._save_state()
                return True

            except Exception as exc:
                self.state.retry_count = attempt
                self.state.errors.append(
                    {
                        "stage": stage.value,
                        "attempt": attempt,
                        "error": str(exc),
                        "timestamp": _now_iso(),
                    }
                )
                self._save_state()
                logger.warning(
                    "Stage %s attempt %d failed: %s",
                    stage.value,
                    attempt,
                    exc,
                )
                if attempt < self.config.max_retries:
                    backoff = min(2 ** attempt, 30)
                    logger.info("Retrying in %ds...", backoff)
                    time.sleep(backoff)

        return False

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _stage_build_env(self) -> None:
        """Stage 1: Build the Docker image for the target environment."""
        tag = self.docker.build_image(
            context_path=self.config.docker_context,
            tag=self.config.image_tag,
            dockerfile=self.config.dockerfile,
        )
        self.state.image_tag = tag

    def _stage_start_env(self) -> None:
        """Stage 2: Start the target container."""
        self._container = self.docker.start_container(
            image=self.config.image_tag,
            name=self.config.container_name,
            ports=self.config.ports,
            env_vars=self.config.env_vars or None,
        )
        self.state.container_id = self._container.container_id

    def _stage_health_check(self) -> None:
        """Stage 3: Wait for the target to become healthy."""
        container_id = self.state.container_id
        if not container_id:
            raise RuntimeError("No container ID -- was start_env skipped?")

        healthy = self.docker.wait_for_health(
            container_id=container_id,
            url=self.config.health_url,
            timeout=self.config.health_timeout,
        )
        if not healthy:
            logs = self.docker.get_container_logs(container_id, tail=50)
            raise RuntimeError(
                f"Container {container_id} did not become healthy "
                f"within {self.config.health_timeout}s.\nLogs:\n{logs}"
            )

    def _stage_discover_pocs(self) -> None:
        """Stage 4: Discover PoC scripts from the scripts directory."""
        self._runner = PoCRunner(self.config.scripts_dir, max_workers=self.config.max_workers)
        scripts = self._runner.discover()
        if not scripts:
            raise RuntimeError(
                f"No PoC scripts found in {self.config.scripts_dir}"
            )
        logger.info("Discovered %d PoC scripts", len(scripts))

    def _stage_execute_pocs(self) -> None:
        """Stage 5: Execute all PoC scripts against the target."""
        if self._runner is None:
            # Runner may be None when resuming a pipeline that already completed
            # the discover stage. Re-discover without raising on empty (discover
            # already validated that scripts exist).
            self._runner = PoCRunner(self.config.scripts_dir, max_workers=self.config.max_workers)
            self._runner.discover()
        self._execution_results = self._runner.execute(
            target=self.config.target_url,
            timeout=self.config.poc_timeout,
            parallel=self.config.parallel_execution,
        )
        logger.info("Executed %d PoC scripts", len(self._execution_results))

    def _stage_validate(self) -> None:
        """Stage 6: Validate each execution result with its type-specific validator."""
        self._validated_results = []

        for exec_result in self._execution_results:
            result_dict = exec_result.to_dict()
            validator = get_validator(exec_result.vuln_type)

            if validator is None:
                logger.warning(
                    "No validator for vuln_type '%s'; marking as ERROR",
                    exec_result.vuln_type,
                )
                result_dict["validation"] = {
                    "status": "ERROR",
                    "evidence": "",
                    "details": {"error": f"No validator for type '{exec_result.vuln_type}'"},
                }
            else:
                validation = validator.validate(result_dict)
                result_dict["validation"] = validation.to_dict()

            self._validated_results.append(result_dict)

        self.state.results = self._validated_results
        logger.info("Validated %d results", len(self._validated_results))

    def _stage_report(self) -> None:
        """Stage 7: Generate Markdown and JSON reports."""
        target_meta = {
            "name": self.config.target_name,
            "url": self.config.target_url,
            "version": self.config.target_version,
            "environment": self.config.environment,
        }

        # Markdown report
        md_path = generate_report(
            target=target_meta,
            vulns=[],
            results=self._validated_results,
            output_dir=self.config.output_dir,
        )
        logger.info("Markdown report written to %s", md_path)

        # JSON summary
        summary = generate_summary(
            target=target_meta,
            vulns=[],
            results=self._validated_results,
        )
        json_path = str(Path(self.config.output_dir) / "summary.json")
        write_summary(summary, json_path)
        logger.info("JSON summary written to %s", json_path)

    def _stage_teardown(self) -> None:
        """Stage 8: Stop and remove Docker resources."""
        container_id = self.state.container_id
        if container_id:
            try:
                self.docker.cleanup(container_id, remove_image=False)
                logger.info("Container %s cleaned up", container_id)
            except Exception as exc:
                logger.warning("Teardown error: %s", exc)
        else:
            logger.info("No container to tear down")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        """Persist the current pipeline state to disk."""
        self.state.save(self.config.state_file)


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()
