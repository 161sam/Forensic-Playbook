"""Guarded Codex operations exposed via the forensic CLI."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

DEFAULT_WORKSPACE = Path("/mnt/usb_rw")
DEFAULT_CODEX_HOME = DEFAULT_WORKSPACE / "codex_home"
DEFAULT_LOG_DIR = DEFAULT_WORKSPACE / "codex_logs"
DEFAULT_REPO_URL = "https://github.com/Wh0am123/MCP-Kali-Server.git"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DEFAULT_NODE_DIR = DEFAULT_WORKSPACE / "codex_npm"

MINIMAL_PIP_PACKAGES: tuple[str, ...] = ("flask", "flask-cors", "requests")

_CommandRunner = Callable[[List[str], Dict[str, Any]], subprocess.CompletedProcess]


@dataclass(slots=True)
class CodexPaths:
    """Resolved paths for Codex operations."""

    workspace: Path
    log_dir: Path
    codex_home: Path
    repo_dir: Path
    venv_dir: Path
    node_dir: Path
    pid_file: Path
    stdout_file: Path
    stderr_file: Path
    control_log: Path
    config_dir: Path
    config_file: Path
    config_checksum: Path

    def as_dict(self) -> Dict[str, str]:
        raw = asdict(self)
        return {key: str(value) for key, value in raw.items()}

    @property
    def venv_python(self) -> Path:
        if sys.platform.startswith("win"):
            candidate = self.venv_dir / "Scripts" / "python"
        else:
            candidate = self.venv_dir / "bin" / "python"
        return candidate

    @property
    def mcp_script(self) -> Path:
        return self.repo_dir / "kali_server.py"


@dataclass(slots=True)
class CodexOperationResult:
    """Lightweight container describing the outcome of an operation."""

    status: str
    message: str
    details: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_status_payload(self, command: str) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "command": command,
            "status": self.status,
            "message": self.message,
        }
        if self.details:
            payload["details"] = self.details
        if self.warnings:
            payload["warnings"] = self.warnings
        if self.errors:
            payload["errors"] = self.errors
        if self.data:
            payload["data"] = self.data
        return payload


class OperationLogger:
    """Helper to keep audit logs for Codex operations."""

    def __init__(self, log_file: Path, *, dry_run: bool = False) -> None:
        self.log_file = log_file
        self.dry_run = dry_run
        self._stream = None
        self.lines: list[str] = []
        if not dry_run:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            self._stream = log_file.open("a", encoding="utf-8")

    def __enter__(self) -> OperationLogger:
        return self

    def __exit__(
        self, exc_type, exc, tb
    ) -> None:  # pragma: no cover - context manager protocol
        if self._stream:
            self._stream.close()

    def _emit(self, prefix: str, message: str) -> str:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        line = f"[{timestamp}] {prefix}{message}"
        self.lines.append(line)
        if self._stream:
            self._stream.write(line + "\n")
            self._stream.flush()
        return line

    def info(self, message: str) -> str:
        return self._emit("", message)

    def action(self, message: str) -> str:
        return self._emit("ACTION: ", message)

    def warning(self, message: str) -> str:
        return self._emit("WARN: ", message)

    def error(self, message: str) -> str:
        return self._emit("ERROR: ", message)


def resolve_paths(
    workspace: str | Path | None = None,
    *,
    codex_home: str | Path | None = None,
    log_dir: str | Path | None = None,
    node_dir: str | Path | None = None,
) -> CodexPaths:
    base = Path(workspace) if workspace else DEFAULT_WORKSPACE
    logs = Path(log_dir) if log_dir else base / DEFAULT_LOG_DIR.name
    home = Path(codex_home) if codex_home else base / DEFAULT_CODEX_HOME.name
    node = Path(node_dir) if node_dir else base / DEFAULT_NODE_DIR.name
    repo_dir = base / "MCP-Kali-Server"
    venv_dir = repo_dir / ".venv"
    pid_file = logs / "mcp.pid"
    stdout_file = logs / "mcp_stdout.log"
    stderr_file = logs / "mcp_stderr.log"
    control_log = logs / "codex_control.log"
    config_dir = home / ".codex"
    config_file = config_dir / "config.toml"
    config_checksum = logs / "config.sha256"
    return CodexPaths(
        workspace=base,
        log_dir=logs,
        codex_home=home,
        repo_dir=repo_dir,
        venv_dir=venv_dir,
        node_dir=node,
        pid_file=pid_file,
        stdout_file=stdout_file,
        stderr_file=stderr_file,
        control_log=control_log,
        config_dir=config_dir,
        config_file=config_file,
        config_checksum=config_checksum,
    )


def _default_runner(
    args: List[str], kwargs: Dict[str, Any]
) -> subprocess.CompletedProcess:
    kwargs.setdefault("check", False)
    kwargs.setdefault("capture_output", True)
    text = kwargs.get("text")
    if text is None:
        kwargs["text"] = True
    return subprocess.run(args, **kwargs)


def _ensure_directory(
    path: Path, logger: OperationLogger, *, dry_run: bool, mode: int | None = None
) -> None:
    if dry_run:
        logger.action(f"Would ensure directory exists: {path}")
        return
    path.mkdir(parents=True, exist_ok=True)
    if mode is not None:
        try:
            os.chmod(path, mode)
        except PermissionError:  # pragma: no cover - platform specific
            logger.warning(f"Could not set permissions on {path}")


def _git_available() -> bool:
    return shutil.which("git") is not None


def _maybe_clone_repo(
    paths: CodexPaths,
    *,
    repo_url: str,
    dry_run: bool,
    logger: OperationLogger,
    runner: _CommandRunner,
) -> None:
    if paths.repo_dir.exists():
        logger.info(f"MCP repo already exists at {paths.repo_dir}")
        if not _git_available():
            logger.warning("git executable not found -> skipping git pull")
            return
        if dry_run:
            logger.action(f"Would pull latest changes in {paths.repo_dir}")
            return
        result = runner(["git", "-C", str(paths.repo_dir), "pull", "--ff-only"], {})
        if result.returncode != 0:
            logger.warning(f"git pull failed: {result.stderr.strip()}")
        else:
            logger.info("git pull completed")
        return

    if not _git_available():
        logger.warning(
            "git executable not available -> please clone MCP-Kali-Server manually"
        )
        return

    if dry_run:
        logger.action(f"Would clone {repo_url} into {paths.repo_dir}")
        return

    result = runner(["git", "clone", repo_url, str(paths.repo_dir)], {})
    if result.returncode != 0:
        logger.warning(f"git clone failed: {result.stderr.strip()}")
    else:
        logger.info("git clone completed")


def _create_venv(paths: CodexPaths, *, dry_run: bool, logger: OperationLogger) -> None:
    if paths.venv_dir.exists():
        logger.info(f"Virtual environment already present at {paths.venv_dir}")
        return
    if dry_run:
        logger.action(f"Would create virtual environment at {paths.venv_dir}")
        return
    import venv

    builder = venv.EnvBuilder(with_pip=True)
    builder.create(paths.venv_dir)
    logger.info("Created virtual environment")


def _pip_install(
    paths: CodexPaths, *, dry_run: bool, logger: OperationLogger, runner: _CommandRunner
) -> None:
    python_bin = (
        paths.venv_python if paths.venv_python.exists() else Path(sys.executable)
    )
    upgrade_cmd = [
        str(python_bin),
        "-m",
        "pip",
        "install",
        "--upgrade",
        "pip",
        "setuptools",
        "wheel",
    ]
    if dry_run:
        logger.action(f"Would run: {' '.join(upgrade_cmd)}")
    else:
        runner(upgrade_cmd, {})

    requirements = paths.repo_dir / "requirements.txt"
    if requirements.exists() and requirements.stat().st_size > 0:
        install_cmd = [str(python_bin), "-m", "pip", "install", "-r", str(requirements)]
        description = f"requirements from {requirements}"
    else:
        install_cmd = [str(python_bin), "-m", "pip", "install", *MINIMAL_PIP_PACKAGES]
        description = "minimal MCP dependencies"

    if dry_run:
        logger.action(f"Would install {description} via: {' '.join(install_cmd)}")
        return

    result = runner(install_cmd, {})
    if result.returncode != 0:
        logger.warning(f"pip install reported issues: {result.stderr.strip()}")
    else:
        logger.info(f"Installed {description}")


def _ensure_node_packages(
    paths: CodexPaths, *, dry_run: bool, logger: OperationLogger
) -> None:
    npm_path = shutil.which("npm")
    if npm_path is None:
        logger.warning(
            "npm executable not found -> skip installing @openai/codex (install manually if needed)"
        )
        return

    ensure_cmd = [
        npm_path,
        "--prefix",
        str(paths.node_dir),
        "install",
        "@openai/codex",
        "--no-audit",
        "--no-fund",
    ]
    if dry_run:
        logger.action(f"Would install @openai/codex using: {' '.join(ensure_cmd)}")
        return

    paths.node_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(ensure_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.warning(f"npm install produced warnings: {result.stderr.strip()}")
    else:
        logger.info("npm install completed (@openai/codex)")


def _write_config(
    paths: CodexPaths,
    *,
    host: str,
    port: int,
    dry_run: bool,
    logger: OperationLogger,
) -> None:
    config_body = (
        textwrap.dedent(
            f"""
        [core]
        # default_model = "gpt-5-codex"

        [mcp_servers.kali_mcp]
        command = "python3"
        args = ["{paths.repo_dir.as_posix()}/mcp_server.py", "http://{host}:{port}"]
        env = {{ MCP_ALLOW_EXEC = "true" }}
        """
        ).strip()
        + "\n"
    )

    if dry_run:
        logger.action(f"Would write Codex config to {paths.config_file}")
        return

    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(config_body, encoding="utf-8")
    checksum = hashlib.sha256(config_body.encode("utf-8")).hexdigest()
    paths.config_checksum.write_text(
        json.dumps({"sha256": checksum, "file": str(paths.config_file)})
    )
    logger.info(f"Codex config written to {paths.config_file}")


def install_codex_environment(
    paths: CodexPaths,
    *,
    repo_url: str = DEFAULT_REPO_URL,
    dry_run: bool = False,
    enable_mount: bool = False,
    enable_host_patch: bool = False,
    runner: Optional[_CommandRunner] = None,
) -> CodexOperationResult:
    """Install or update the Codex forensic environment."""

    runner = runner or _default_runner
    warnings: list[str] = []
    details: list[str] = []

    with OperationLogger(paths.log_dir / "install.log", dry_run=dry_run) as logger:
        logger.info(
            "Starting Codex install (dry-run)" if dry_run else "Starting Codex install"
        )
        _ensure_directory(paths.workspace, logger, dry_run=dry_run)
        _ensure_directory(paths.log_dir, logger, dry_run=dry_run, mode=0o700)
        _ensure_directory(paths.codex_home, logger, dry_run=dry_run, mode=0o700)

        if enable_mount:
            warnings.append(
                "Automatic mounting requires elevated privileges and is skipped in the Python port."
            )
            logger.warning(
                "Mount automation is not supported in this guarded port -> please mount manually if needed"
            )
        else:
            logger.info(
                "Mount automation disabled (use --enable-mount to see guidance)"
            )

        _maybe_clone_repo(
            paths,
            repo_url=repo_url,
            dry_run=dry_run,
            logger=logger,
            runner=runner,
        )

        if not paths.repo_dir.exists():
            warnings.append(
                "MCP repository not present. Clone manually or re-run after enabling git."
            )
            logger.warning("MCP repository missing -> install cannot continue fully")
        else:
            _create_venv(paths, dry_run=dry_run, logger=logger)
            _pip_install(paths, dry_run=dry_run, logger=logger, runner=runner)

        _ensure_node_packages(paths, dry_run=dry_run, logger=logger)
        _write_config(
            paths, host=DEFAULT_HOST, port=DEFAULT_PORT, dry_run=dry_run, logger=logger
        )

        if enable_host_patch:
            warnings.append(
                "Host patch requires root permissions. Review documentation before applying manually."
            )
            logger.warning(
                "Host patch is not performed automatically. Use system tooling if necessary."
            )
        else:
            logger.info("Host patch skipped (use --enable-host-patch for instructions)")

        details.extend(logger.lines)

    status = "success" if not warnings else "warning"
    if dry_run:
        message = "Codex install dry-run completed"
    else:
        message = "Codex install completed"
    if warnings:
        message += " with warnings"
    return CodexOperationResult(
        status=status,
        message=message,
        details=details,
        warnings=warnings,
        data={"paths": paths.as_dict(), "dry_run": dry_run},
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_pid(pid_file: Path) -> Optional[int]:
    if not pid_file.exists():
        return None
    try:
        value = pid_file.read_text(encoding="utf-8").strip()
        if not value:
            return None
        return int(value)
    except (ValueError, OSError):
        return None


def _write_pid(
    pid_file: Path, pid: int, *, dry_run: bool, logger: OperationLogger
) -> None:
    if dry_run:
        logger.action(f"Would write PID {pid} to {pid_file}")
        return
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(pid), encoding="utf-8")


def _stop_existing_process(
    paths: CodexPaths, *, dry_run: bool, logger: OperationLogger
) -> Optional[int]:
    pid = _read_pid(paths.pid_file)
    if not pid:
        return None
    if dry_run:
        logger.action(f"Would stop MCP server with PID {pid}")
        return pid
    try:
        os.kill(pid, signal.SIGTERM)
        logger.info(f"Sent SIGTERM to MCP server (PID {pid})")
    except ProcessLookupError:
        logger.warning("PID file found but process not running")
        paths.pid_file.unlink(missing_ok=True)
        return None
    return pid


def _start_background(
    paths: CodexPaths,
    *,
    host: str,
    port: int,
    dry_run: bool,
    logger: OperationLogger,
    runner_env: Optional[Dict[str, str]] = None,
) -> Optional[int]:
    if dry_run:
        python_bin = (
            paths.venv_python if paths.venv_python.exists() else Path(sys.executable)
        )
        logger.action(f"Would start MCP server in background using {python_bin}")
        return 99999

    python_bin = (
        paths.venv_python if paths.venv_python.exists() else Path(sys.executable)
    )
    command = [
        str(python_bin),
        str(paths.mcp_script),
        "--host",
        host,
        "--port",
        str(port),
    ]
    env = os.environ.copy()
    if runner_env:
        env.update(runner_env)
    env.setdefault("MCP_ALLOW_EXEC", "true")
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    stdout_handle = paths.stdout_file.open("a", encoding="utf-8")
    stderr_handle = paths.stderr_file.open("a", encoding="utf-8")
    process = subprocess.Popen(
        command,
        cwd=str(paths.repo_dir),
        stdout=stdout_handle,
        stderr=stderr_handle,
        env=env,
        start_new_session=True,
    )
    time.sleep(1.0)
    if process.poll() is not None:
        logger.warning("MCP server exited immediately -> check logs")
        return None
    _write_pid(paths.pid_file, process.pid, dry_run=False, logger=logger)
    logger.info(f"MCP server started with PID {process.pid}")
    return process.pid


def _start_foreground(
    paths: CodexPaths,
    *,
    host: str,
    port: int,
    dry_run: bool,
    logger: OperationLogger,
    runner_env: Optional[Dict[str, str]] = None,
) -> Optional[int]:
    python_bin = (
        paths.venv_python if paths.venv_python.exists() else Path(sys.executable)
    )
    command = [
        str(python_bin),
        str(paths.mcp_script),
        "--host",
        host,
        "--port",
        str(port),
    ]
    if dry_run:
        logger.action(f"Would run MCP server in foreground: {' '.join(command)}")
        return 0

    env = os.environ.copy()
    if runner_env:
        env.update(runner_env)
    env.setdefault("MCP_ALLOW_EXEC", "true")
    logger.info("Starting MCP server in foreground (Ctrl+C to stop)")
    subprocess.run(command, cwd=str(paths.repo_dir), env=env, check=False)
    return 0


def start_codex_server(
    paths: CodexPaths,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    dry_run: bool = False,
    foreground: bool = False,
    enable_host_patch: bool = False,
    runner_env: Optional[Dict[str, str]] = None,
) -> CodexOperationResult:
    """Start the MCP server using guarded defaults."""

    warnings: list[str] = []
    details: list[str] = []

    with OperationLogger(paths.control_log, dry_run=dry_run) as logger:
        logger.info(
            "Starting Codex MCP server (dry-run)"
            if dry_run
            else "Starting Codex MCP server"
        )
        if not paths.repo_dir.exists():
            warning = (
                "MCP repository missing at"
                f" {paths.repo_dir}. Run 'forensic-cli codex install' first."
            )
            warnings.append(warning)
            logger.warning(warning)
            details.extend(logger.lines)
            return CodexOperationResult(
                status="warning",
                message="MCP repository missing",
                details=details,
                warnings=warnings,
                data={"paths": paths.as_dict(), "dry_run": dry_run},
            )

        _ensure_directory(paths.log_dir, logger, dry_run=dry_run, mode=0o700)
        _ensure_directory(paths.codex_home, logger, dry_run=dry_run, mode=0o700)

        if enable_host_patch:
            if os.name != "posix":
                warnings.append("Host patch not supported on this platform")
                logger.warning("Host patch skipped (non-posix platform)")
            elif os.geteuid() != 0:  # type: ignore[attr-defined]
                warnings.append("Run with sudo to modify /etc/hosts or patch manually")
                logger.warning(
                    "Host patch requested but not running as root -> skipping"
                )
            else:
                hosts_file = Path("/etc/hosts")
                if dry_run:
                    logger.action(f"Would ensure localhost entry in {hosts_file}")
                else:
                    content = hosts_file.read_text(encoding="utf-8")
                    if "localhost" not in content:
                        hosts_file.write_text(
                            content + "\n127.0.0.1 localhost\n", encoding="utf-8"
                        )
                        logger.info("Added localhost entry to /etc/hosts")
                    else:
                        logger.info("/etc/hosts already contains localhost entry")
        else:
            logger.info("Host patch disabled (use --enable-host-patch if required)")

        pid = _read_pid(paths.pid_file)
        if pid and _pid_alive(pid):
            logger.info(f"MCP server already running with PID {pid}")
            _write_config(paths, host=host, port=port, dry_run=dry_run, logger=logger)
            details.extend(logger.lines)
            return CodexOperationResult(
                status="success",
                message="MCP server already running",
                details=details,
                warnings=warnings,
                data={"pid": pid, "paths": paths.as_dict(), "dry_run": dry_run},
            )

        if not paths.mcp_script.exists():
            warnings.append(
                "kali_server.py not found in repository -> cannot start MCP server"
            )
            logger.warning("kali_server.py missing")
        else:
            if foreground:
                _start_foreground(
                    paths,
                    host=host,
                    port=port,
                    dry_run=dry_run,
                    logger=logger,
                    runner_env=runner_env,
                )
            else:
                pid = _start_background(
                    paths,
                    host=host,
                    port=port,
                    dry_run=dry_run,
                    logger=logger,
                    runner_env=runner_env,
                )
                if pid:
                    logger.info(f"Background MCP server PID: {pid}")

        _write_config(paths, host=host, port=port, dry_run=dry_run, logger=logger)
        details.extend(logger.lines)

    status = "success" if not warnings else "warning"
    if dry_run:
        message = "MCP server dry-run"
    else:
        message = "MCP server command executed"
    if warnings:
        message += " with warnings"
    return CodexOperationResult(
        status=status,
        message=message,
        details=details,
        warnings=warnings,
        data={"paths": paths.as_dict(), "dry_run": dry_run, "foreground": foreground},
    )


def stop_codex_server(
    paths: CodexPaths,
    *,
    dry_run: bool = False,
    wait_seconds: float = 2.0,
) -> CodexOperationResult:
    """Stop the MCP server if it is currently running."""

    warnings: list[str] = []
    errors: list[str] = []
    details: list[str] = []

    with OperationLogger(paths.control_log, dry_run=dry_run) as logger:
        pid = _read_pid(paths.pid_file)
        if not pid:
            logger.info("No PID file found -> MCP server not running")
            details.extend(logger.lines)
            return CodexOperationResult(
                status="success",
                message="MCP server already stopped",
                details=details,
                warnings=warnings,
                data={"paths": paths.as_dict(), "dry_run": dry_run},
            )

        logger.info(f"Stopping MCP server with PID {pid}")
        if dry_run:
            logger.action(f"Would send SIGTERM to PID {pid}")
            details.extend(logger.lines)
            return CodexOperationResult(
                status="success",
                message="Dry-run stop completed",
                details=details,
                warnings=warnings,
                data={"pid": pid, "dry_run": True, "paths": paths.as_dict()},
            )

        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("SIGTERM sent")
        except ProcessLookupError:
            warnings.append("Process not running; removing stale PID file")
            logger.warning("PID file stale")
            paths.pid_file.unlink(missing_ok=True)
            details.extend(logger.lines)
            return CodexOperationResult(
                status="warning",
                message="PID file stale",
                details=details,
                warnings=warnings,
                data={"paths": paths.as_dict()},
            )

        time.sleep(wait_seconds)
        if _pid_alive(pid):
            warnings.append(
                "Process still running after SIGTERM. Send SIGKILL manually if needed."
            )
            logger.warning("Process still running after wait")
        else:
            paths.pid_file.unlink(missing_ok=True)
            logger.info("PID file removed")

        details.extend(logger.lines)

    status = "success" if not warnings else "warning"
    message = "MCP server stop completed"
    if warnings:
        message += " with warnings"
    return CodexOperationResult(
        status=status,
        message=message,
        details=details,
        warnings=warnings,
        errors=errors,
        data={"paths": paths.as_dict(), "dry_run": dry_run},
    )


def get_codex_status(
    paths: CodexPaths,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 1.0,
) -> CodexOperationResult:
    """Return health information for the Codex MCP server."""

    details: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []

    pid = _read_pid(paths.pid_file)
    running = bool(pid and _pid_alive(pid))
    details.append(
        f"PID file: {paths.pid_file if paths.pid_file.exists() else 'missing'}"
    )
    if pid:
        details.append(f"Recorded PID: {pid}")
        details.append(f"Process running: {running}")
    else:
        details.append("No recorded PID")

    port_open = False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            port_open = True
    except OSError:
        port_open = False
    details.append(f"Port {port} reachable: {port_open}")

    http_status: Optional[int] = None
    if port_open:
        try:
            import urllib.request

            with urllib.request.urlopen(
                f"http://{host}:{port}/", timeout=timeout
            ) as response:
                http_status = response.status
        except Exception as exc:  # pragma: no cover - depends on network state
            warnings.append(f"HTTP probe failed: {exc}")
    else:
        warnings.append("Port closed -> HTTP probe skipped")

    if http_status is not None:
        details.append(f"HTTP status: {http_status}")
    else:
        details.append("HTTP status: unavailable")

    result_data = {
        "paths": paths.as_dict(),
        "pid": pid,
        "running": running,
        "port_open": port_open,
        "http_status": http_status,
    }

    status = "success" if running or port_open else "warning"
    message = "MCP server status reported"
    return CodexOperationResult(
        status=status,
        message=message,
        details=details,
        warnings=warnings,
        errors=errors,
        data=result_data,
    )


def read_codex_logs(
    paths: CodexPaths,
    *,
    target: str = "control",
    lines: int = 40,
) -> CodexOperationResult:
    """Return a tail excerpt from one of the Codex log files."""

    target_normalised = target.lower().strip()
    available_targets = {
        "control": paths.control_log,
        "stdout": paths.stdout_file,
        "stderr": paths.stderr_file,
    }

    data: Dict[str, Any] = {
        "paths": paths.as_dict(),
        "requested_target": target,
        "target": target_normalised,
        "available_targets": sorted(available_targets.keys()),
        "lines_requested": lines,
    }

    if target_normalised not in available_targets:
        message = f"Unknown log target: {target}"
        details = [
            "Available targets:",
            *(f"  - {name}" for name in sorted(available_targets.keys())),
        ]
        return CodexOperationResult(
            status="error",
            message=message,
            details=details,
            errors=[message],
            data=data,
        )

    log_path = available_targets[target_normalised]
    data["log_path"] = str(log_path)

    details = [
        f"Target: {target_normalised}",
        f"Log path: {log_path}",
        f"Lines requested: {max(lines, 0)}",
    ]

    if not log_path.exists():
        warning = f"Log file does not exist yet: {log_path}"
        details.append(
            "Log file missing -> run 'forensic-cli codex start' to populate it."
        )
        data["log_excerpt"] = []
        data["lines_returned"] = 0
        return CodexOperationResult(
            status="warning",
            message="Log file not found",
            details=details,
            warnings=[warning],
            data=data,
        )

    excerpt: list[str]
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as stream:
            if lines > 0:
                excerpt = [line.rstrip("\n") for line in deque(stream, maxlen=lines)]
            else:
                excerpt = [line.rstrip("\n") for line in stream]
    except OSError as exc:
        return CodexOperationResult(
            status="error",
            message="Unable to read log file",
            details=details,
            errors=[str(exc)],
            data=data,
        )

    data["log_excerpt"] = excerpt
    data["lines_returned"] = len(excerpt)

    if excerpt:
        details.append("Log excerpt (latest entries):")
        details.extend(excerpt)
        message = "Log excerpt retrieved"
        status = "success"
    else:
        details.append("Log excerpt: <empty>")
        message = "Log file empty"
        status = "warning"

    return CodexOperationResult(
        status=status,
        message=message,
        details=details,
        data=data,
    )
