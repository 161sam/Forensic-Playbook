#!/usr/bin/env python3
"""
Forensic Logging System
Centralized logging with forensic-specific features
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from forensic.core.time_utils import utc_isoformat, utc_slug


class ForensicFormatter(logging.Formatter):
    """Custom formatter with color support for console"""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def __init__(self, use_color: bool = True):
        super().__init__(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.use_color = use_color

    def format(self, record):
        if self.use_color and sys.stdout.isatty():
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = (
                    f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
                )
        return super().format(record)


def setup_logging(
    log_dir: Optional[Path] = None,
    level: str = "INFO",
    log_to_file: bool = True,
    log_to_console: bool = True,
    case_id: Optional[str] = None,
) -> logging.Logger:
    """
    Setup forensic logging

    Args:
        log_dir: Directory for log files
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Enable file logging
        log_to_console: Enable console logging
        case_id: Optional case ID for log filename

    Returns:
        Logger instance
    """
    # Create logger
    logger = logging.getLogger("forensic")
    logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_handler.setFormatter(ForensicFormatter(use_color=True))
        logger.addHandler(console_handler)

    # File handler
    if log_to_file and log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        timestamp = utc_slug()
        if case_id:
            log_file = log_dir / f"{case_id}_{timestamp}.log"
        else:
            log_file = log_dir / f"forensic_{timestamp}.log"

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Always DEBUG for file
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)

        logger.info(f"Logging to file: {log_file}")

    return logger


class AuditLogger:
    """
    Separate audit logger for security-critical events

    Audit logs are:
    - Always written to file (never just console)
    - Never modified or deleted
    - Include detailed context
    """

    def __init__(self, audit_log_path: Path):
        """
        Initialize audit logger

        Args:
            audit_log_path: Path to audit log file
        """
        self.audit_log_path = audit_log_path
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Create dedicated audit logger
        self.logger = logging.getLogger("forensic.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to parent

        # File handler (append mode, never truncate)
        handler = logging.FileHandler(self.audit_log_path, mode="a")
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s - AUDIT - %(message)s", datefmt="%Y-%m-%d %H:%M:%S UTC"
            )
        )
        self.logger.addHandler(handler)

    def log(self, event: str, details: dict = None):
        """
        Log audit event

        Args:
            event: Event description
            details: Additional event details
        """
        import json

        message = f"{event}"
        if details:
            message += f" | Details: {json.dumps(details, sort_keys=True)}"

        self.logger.info(message)

    def log_access(self, resource: str, action: str, actor: str, success: bool = True):
        """Log resource access"""
        self.log(
            f"ACCESS: {action} {resource}",
            {"actor": actor, "success": success, "timestamp": utc_isoformat()},
        )

    def log_modification(
        self,
        resource: str,
        action: str,
        actor: str,
        before_hash: str = None,
        after_hash: str = None,
    ):
        """Log resource modification"""
        self.log(
            f"MODIFICATION: {action} {resource}",
            {
                "actor": actor,
                "before_hash": before_hash,
                "after_hash": after_hash,
                "timestamp": utc_isoformat(),
            },
        )

    def log_security_event(
        self, event_type: str, description: str, severity: str = "INFO"
    ):
        """Log security event"""
        self.log(
            f"SECURITY[{severity}]: {event_type}",
            {"description": description, "timestamp": utc_isoformat()},
        )


def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get logger for a specific module

    Args:
        module_name: Module name

    Returns:
        Logger instance
    """
    return logging.getLogger(f"forensic.{module_name}")
