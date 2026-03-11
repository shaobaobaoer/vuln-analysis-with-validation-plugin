"""
Docker environment manager for vulnerability analysis targets.

Manages container lifecycle (build, start, health-check, exec, stop,
cleanup) entirely through subprocess calls -- no Docker SDK required.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ContainerInfo:
    """Metadata about a running container."""

    container_id: str
    name: str
    image: str
    ports: dict[str, str] = field(default_factory=dict)
    status: str = "unknown"


class DockerManager:
    """Manages Docker containers for vulnerability analysis environments.

    All Docker operations are performed via ``subprocess.run`` to avoid
    a hard dependency on the Docker SDK.

    Typical usage::

        dm = DockerManager()
        dm.build_image("./targets/webapp", tag="vuln-webapp:latest")
        container = dm.start_container(
            image="vuln-webapp:latest",
            name="vuln-webapp-test",
            ports={"8080": "8080"},
        )
        dm.wait_for_health(container.container_id, url="http://localhost:8080/health")
        # ... run PoCs ...
        dm.stop_container(container.container_id)
        dm.cleanup(container.container_id, remove_image=True)
    """

    def __init__(self, docker_bin: str = "docker") -> None:
        self.docker_bin = docker_bin
        self._containers: dict[str, ContainerInfo] = {}

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def build_image(
        self,
        context_path: str,
        tag: str,
        dockerfile: str = "Dockerfile",
        build_args: Optional[dict[str, str]] = None,
    ) -> str:
        """Build a Docker image from a Dockerfile.

        Args:
            context_path: Path to the build context directory.
            tag: Image tag (e.g. ``myapp:latest``).
            dockerfile: Dockerfile filename relative to context_path.
            build_args: Optional ``--build-arg`` key-value pairs.

        Returns:
            The image tag string.

        Raises:
            RuntimeError: If the build fails.
        """
        cmd = [
            self.docker_bin,
            "build",
            "-t",
            tag,
            "-f",
            str(Path(context_path) / dockerfile),
        ]

        if build_args:
            for key, value in build_args.items():
                cmd.extend(["--build-arg", f"{key}={value}"])

        cmd.append(context_path)

        logger.info("Building image %s from %s", tag, context_path)
        result = self._run(cmd)
        if result.returncode != 0:
            raise RuntimeError(
                f"Docker build failed (exit {result.returncode}): {result.stderr}"
            )
        logger.info("Image %s built successfully", tag)
        return tag

    # ------------------------------------------------------------------
    # Container lifecycle
    # ------------------------------------------------------------------

    def start_container(
        self,
        image: str,
        name: Optional[str] = None,
        ports: Optional[dict[str, str]] = None,
        env_vars: Optional[dict[str, str]] = None,
        volumes: Optional[dict[str, str]] = None,
        extra_args: Optional[list[str]] = None,
        detach: bool = True,
    ) -> ContainerInfo:
        """Start a Docker container.

        Args:
            image: Image tag or ID.
            name: Container name (auto-generated if None).
            ports: Host-to-container port mapping (e.g. ``{"8080": "80"}``).
            env_vars: Environment variables to set inside the container.
            volumes: Host-to-container volume mounts (e.g. ``{"/tmp/data": "/data"}``).
            extra_args: Additional ``docker run`` arguments.
            detach: Run in detached mode (default True).

        Returns:
            A ContainerInfo with the new container's metadata.

        Raises:
            RuntimeError: If the container fails to start.
        """
        cmd = [self.docker_bin, "run"]

        if detach:
            cmd.append("-d")

        if name:
            cmd.extend(["--name", name])

        if ports:
            for host_port, container_port in ports.items():
                cmd.extend(["-p", f"{host_port}:{container_port}"])

        if env_vars:
            for key, value in env_vars.items():
                cmd.extend(["-e", f"{key}={value}"])

        if volumes:
            for host_path, container_path in volumes.items():
                cmd.extend(["-v", f"{host_path}:{container_path}"])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(image)

        logger.info("Starting container from image %s", image)
        result = self._run(cmd)
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to start container (exit {result.returncode}): {result.stderr}"
            )

        container_id = result.stdout.strip()[:12]
        container_name = name or container_id

        info = ContainerInfo(
            container_id=container_id,
            name=container_name,
            image=image,
            ports=ports or {},
            status="running",
        )
        self._containers[container_id] = info
        logger.info("Container %s started (id=%s)", container_name, container_id)
        return info

    def stop_container(self, container_id: str, timeout: int = 10) -> None:
        """Stop a running container.

        Args:
            container_id: Container ID or name.
            timeout: Seconds to wait before sending SIGKILL.
        """
        logger.info("Stopping container %s", container_id)
        result = self._run(
            [self.docker_bin, "stop", "-t", str(timeout), container_id]
        )
        if result.returncode != 0:
            logger.warning("Failed to stop container %s: %s", container_id, result.stderr)
        else:
            if container_id in self._containers:
                self._containers[container_id].status = "stopped"

    def remove_container(self, container_id: str, force: bool = False) -> None:
        """Remove a container."""
        cmd = [self.docker_bin, "rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_id)

        logger.info("Removing container %s", container_id)
        result = self._run(cmd)
        if result.returncode != 0:
            logger.warning("Failed to remove container %s: %s", container_id, result.stderr)
        else:
            self._containers.pop(container_id, None)

    def remove_image(self, image: str, force: bool = False) -> None:
        """Remove a Docker image."""
        cmd = [self.docker_bin, "rmi"]
        if force:
            cmd.append("-f")
        cmd.append(image)

        logger.info("Removing image %s", image)
        result = self._run(cmd)
        if result.returncode != 0:
            logger.warning("Failed to remove image %s: %s", image, result.stderr)

    def cleanup(
        self,
        container_id: str,
        remove_image: bool = False,
    ) -> None:
        """Stop and remove a container, optionally removing its image.

        Args:
            container_id: Container ID or name.
            remove_image: If True, also remove the container's image.
        """
        info = self._containers.get(container_id)
        self.stop_container(container_id)
        self.remove_container(container_id, force=True)

        if remove_image and info:
            self.remove_image(info.image, force=True)

    def cleanup_all(self, remove_images: bool = False) -> None:
        """Stop and remove all tracked containers."""
        for cid in list(self._containers):
            self.cleanup(cid, remove_image=remove_images)

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def wait_for_health(
        self,
        container_id: str,
        url: Optional[str] = None,
        timeout: int = 60,
        interval: int = 2,
    ) -> bool:
        """Wait until a container is healthy.

        Health is determined by one of:
        1. An HTTP 200 from *url* (if provided).
        2. The container's Docker health status (if a HEALTHCHECK is defined).
        3. The container being in ``running`` state.

        Args:
            container_id: Container ID or name.
            url: Optional HTTP endpoint to probe.
            timeout: Maximum seconds to wait.
            interval: Seconds between retries.

        Returns:
            True if the container is healthy before *timeout*, False otherwise.
        """
        import urllib.request
        import urllib.error

        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            # Try HTTP health check first
            if url:
                try:
                    req = urllib.request.Request(url, method="GET")
                    resp = urllib.request.urlopen(req, timeout=interval)
                    if resp.status == 200:
                        logger.info("Health check passed: %s returned 200", url)
                        return True
                except (urllib.error.URLError, OSError):
                    pass
            else:
                # Inspect container state via docker
                if self._is_container_running(container_id):
                    docker_health = self._get_docker_health(container_id)
                    if docker_health in ("healthy", "none"):
                        logger.info(
                            "Container %s is running (health=%s)",
                            container_id,
                            docker_health,
                        )
                        return True

            time.sleep(interval)

        logger.warning("Health check timed out after %ds for %s", timeout, container_id)
        return False

    # ------------------------------------------------------------------
    # Exec inside containers
    # ------------------------------------------------------------------

    def exec_command(
        self,
        container_id: str,
        command: list[str],
        timeout: int = 30,
        workdir: Optional[str] = None,
        env_vars: Optional[dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command inside a running container.

        Args:
            container_id: Container ID or name.
            command: The command and arguments to run.
            timeout: Maximum seconds for the command.
            workdir: Working directory inside the container.
            env_vars: Extra environment variables for the command.

        Returns:
            A CompletedProcess with stdout and stderr.
        """
        cmd = [self.docker_bin, "exec"]

        if workdir:
            cmd.extend(["-w", workdir])

        if env_vars:
            for key, value in env_vars.items():
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(container_id)
        cmd.extend(command)

        logger.info("Exec in %s: %s", container_id, " ".join(command))
        return self._run(cmd, timeout=timeout)

    # ------------------------------------------------------------------
    # Inspection helpers
    # ------------------------------------------------------------------

    def get_container_logs(
        self, container_id: str, tail: int = 100
    ) -> str:
        """Retrieve recent logs from a container."""
        result = self._run(
            [self.docker_bin, "logs", "--tail", str(tail), container_id]
        )
        return result.stdout + result.stderr

    def list_containers(self, all_: bool = False) -> list[dict[str, str]]:
        """List containers as a list of dicts with id, name, image, status."""
        cmd = [self.docker_bin, "ps", "--format", "{{json .}}"]
        if all_:
            cmd.append("-a")

        result = self._run(cmd)
        containers = []
        for line in result.stdout.strip().splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    containers.append(
                        {
                            "id": data.get("ID", ""),
                            "name": data.get("Names", ""),
                            "image": data.get("Image", ""),
                            "status": data.get("Status", ""),
                        }
                    )
                except json.JSONDecodeError:
                    continue
        return containers

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(
        self,
        cmd: list[str],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        """Run a command via subprocess."""
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("Command timed out: %s", " ".join(cmd))
            return subprocess.CompletedProcess(
                args=cmd, returncode=-1, stdout="", stderr="Command timed out"
            )

    def _is_container_running(self, container_id: str) -> bool:
        """Check if a container is in the running state."""
        result = self._run(
            [
                self.docker_bin,
                "inspect",
                "-f",
                "{{.State.Running}}",
                container_id,
            ]
        )
        return result.stdout.strip().lower() == "true"

    def _get_docker_health(self, container_id: str) -> str:
        """Get the Docker HEALTHCHECK status, or 'none' if not configured."""
        result = self._run(
            [
                self.docker_bin,
                "inspect",
                "-f",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                container_id,
            ]
        )
        return result.stdout.strip().lower() or "unknown"
