"""
PoC execution runner for authorized vulnerability analysis.

Discovers, loads, and executes Proof-of-Concept scripts against
targets in legitimate pentesting, CTF, and research contexts.

IMPORTANT — Host execution warning
-----------------------------------
This module runs PoC scripts as local subprocesses (``python3 script.py``).
It is intended for use ONLY when the runner itself executes *inside* a
Docker container (e.g. via ``docker exec``), making the "host" from the
runner's perspective the container interior, not the analyst's machine.

Do NOT invoke this module directly on the analyst's workstation to run
exploit code against a Docker-hosted target. The correct workflow is:

    1. Copy PoC scripts into the running container.
    2. Run ``docker exec <container> python3 /workspace/pocs/poc_rce_001.py``

See ``agents/orchestrator/AGENT.md §Safety Invariants`` for the full policy.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class PoCScript:
    """Represents a single PoC script and its metadata."""

    path: str
    vuln_type: str
    name: str
    description: str = ""
    timeout: int = 30
    args: list[str] = field(default_factory=list)

    @classmethod
    def from_manifest_entry(cls, entry: dict[str, Any], base_dir: str) -> PoCScript:
        script_path = str(Path(base_dir) / entry["script"])
        return cls(
            path=script_path,
            vuln_type=entry.get("vuln_type", "unknown"),
            name=entry.get("name", Path(script_path).stem),
            description=entry.get("description", ""),
            timeout=entry.get("timeout", 30),
            args=entry.get("args", []),
        )


@dataclass
class ExecutionResult:
    """Structured result of a single PoC execution."""

    script_name: str
    script_path: str
    vuln_type: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    success: bool
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PoCRunner:
    """Discovers, loads, and executes PoC scripts from a directory.

    Expected directory layout:
        scripts_dir/
            poc_manifest.json
            script_a.py
            script_b.py
            ...

    The manifest (poc_manifest.json) lists each script with metadata:
        {
            "scripts": [
                {
                    "script": "script_a.py",
                    "vuln_type": "rce",
                    "name": "RCE via eval",
                    "description": "...",
                    "timeout": 30,
                    "args": ["--extra-flag"]
                }
            ]
        }
    """

    MANIFEST_FILENAME = "poc_manifest.json"

    def __init__(self, scripts_dir: str, max_workers: int = 4) -> None:
        self.scripts_dir = Path(scripts_dir)
        self.max_workers = max_workers
        self._scripts: list[PoCScript] = []

    # ------------------------------------------------------------------
    # Discovery & loading
    # ------------------------------------------------------------------

    def discover(self) -> list[PoCScript]:
        """Discover PoC scripts from the manifest file."""
        manifest_path = self.scripts_dir / self.MANIFEST_FILENAME
        if not manifest_path.exists():
            logger.warning("No manifest found at %s; falling back to auto-discovery", manifest_path)
            return self._auto_discover()

        return self._load_manifest(manifest_path)

    def _load_manifest(self, manifest_path: Path) -> list[PoCScript]:
        """Load scripts from a poc_manifest.json file."""
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        scripts: list[PoCScript] = []
        for entry in data.get("scripts", []):
            poc = PoCScript.from_manifest_entry(entry, str(self.scripts_dir))
            if not Path(poc.path).exists():
                logger.warning("Script listed in manifest does not exist: %s", poc.path)
                continue
            scripts.append(poc)

        self._scripts = scripts
        logger.info("Loaded %d scripts from manifest", len(scripts))
        return scripts

    def _auto_discover(self) -> list[PoCScript]:
        """Fall back to discovering any .py / .sh scripts in the directory."""
        scripts: list[PoCScript] = []
        for ext in ("*.py", "*.sh"):
            for p in sorted(self.scripts_dir.glob(ext)):
                if p.name.startswith("_"):
                    continue
                scripts.append(
                    PoCScript(
                        path=str(p),
                        vuln_type="unknown",
                        name=p.stem,
                    )
                )
        self._scripts = scripts
        logger.info("Auto-discovered %d scripts", len(scripts))
        return scripts

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        target: str,
        timeout: Optional[int] = None,
        parallel: bool = False,
    ) -> list[ExecutionResult]:
        """Execute all discovered scripts against *target*.

        Args:
            target: The target URL or host for the PoC scripts.
            timeout: Global timeout override (per-script). Falls back to
                     each script's own timeout if not provided.
            parallel: If True, execute scripts concurrently.

        Returns:
            A list of ExecutionResult objects.
        """
        if not self._scripts:
            self.discover()

        if parallel:
            return self._execute_parallel(target, timeout)
        return self._execute_sequential(target, timeout)

    def _execute_sequential(
        self, target: str, timeout: Optional[int]
    ) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []
        for poc in self._scripts:
            effective_timeout = timeout if timeout is not None else poc.timeout
            result = run_single(poc.path, target, effective_timeout, poc)
            results.append(result)
        return results

    def _execute_parallel(
        self, target: str, timeout: Optional[int]
    ) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {}
            for poc in self._scripts:
                effective_timeout = timeout if timeout is not None else poc.timeout
                fut = pool.submit(run_single, poc.path, target, effective_timeout, poc)
                future_map[fut] = poc

            for fut in as_completed(future_map):
                poc = future_map[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    logger.error("Unexpected error running %s: %s", poc.name, exc)
                    results.append(
                        ExecutionResult(
                            script_name=poc.name,
                            script_path=poc.path,
                            vuln_type=poc.vuln_type,
                            target=target,
                            exit_code=-1,
                            stdout="",
                            stderr=str(exc),
                            duration_seconds=0.0,
                            timed_out=False,
                            success=False,
                            error=str(exc),
                        )
                    )
        return results


# ------------------------------------------------------------------
# Module-level convenience functions
# ------------------------------------------------------------------


def run_single(
    script_path: str,
    target: str,
    timeout: int = 30,
    poc: Optional[PoCScript] = None,
) -> ExecutionResult:
    """Execute a single PoC script and return a structured result.

    The script is invoked as::

        python <script_path> --target <target> [extra_args...]

    or, for shell scripts::

        bash <script_path> --target <target> [extra_args...]
    """
    script = Path(script_path)
    name = poc.name if poc else script.stem
    vuln_type = poc.vuln_type if poc else "unknown"
    extra_args = poc.args if poc else []

    if script.suffix == ".py":
        cmd = ["python3", str(script), "--target", target] + extra_args
    elif script.suffix == ".sh":
        cmd = ["bash", str(script), "--target", target] + extra_args
    else:
        cmd = [str(script), "--target", target] + extra_args

    logger.info("Running: %s (timeout=%ds)", " ".join(cmd), timeout)

    timed_out = False
    start = time.monotonic()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.monotonic() - start
        return ExecutionResult(
            script_name=name,
            script_path=str(script),
            vuln_type=vuln_type,
            target=target,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_seconds=round(duration, 3),
            timed_out=False,
            success=proc.returncode == 0,
        )

    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        timed_out = True
        return ExecutionResult(
            script_name=name,
            script_path=str(script),
            vuln_type=vuln_type,
            target=target,
            exit_code=-1,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
            duration_seconds=round(duration, 3),
            timed_out=True,
            success=False,
            error=f"Timed out after {timeout}s",
        )

    except Exception as exc:
        duration = time.monotonic() - start
        return ExecutionResult(
            script_name=name,
            script_path=str(script),
            vuln_type=vuln_type,
            target=target,
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            duration_seconds=round(duration, 3),
            timed_out=False,
            success=False,
            error=str(exc),
        )


def run_all(
    scripts_dir: str,
    target: str,
    timeout: int = 30,
    parallel: bool = False,
    max_workers: int = 4,
) -> list[ExecutionResult]:
    """Convenience wrapper: discover and run every PoC in *scripts_dir*."""
    runner = PoCRunner(scripts_dir, max_workers=max_workers)
    runner.discover()
    return runner.execute(target, timeout=timeout, parallel=parallel)
