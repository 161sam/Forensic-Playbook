"""Configuration helpers for the MCP integration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

DEFAULT_ENDPOINT = "http://127.0.0.1:5000/"
DEFAULT_TIMEOUT = 5.0


@dataclass(slots=True)
class MCPConfig:
    """Configuration container for MCP client connections."""

    endpoint: str = DEFAULT_ENDPOINT
    auth_token: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    @property
    def headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    @classmethod
    def from_sources(
        cls,
        *,
        framework_config: Optional[Dict[str, Any]] = None,
        endpoint: Optional[str] = None,
        token: Optional[str] = None,
        timeout: Optional[float] = None,
        env_prefix: str = "FORENSIC_MCP_",
    ) -> MCPConfig:
        """Merge configuration from CLI flags, config files and environment."""

        config_section = (framework_config or {}).get("mcp", {})

        env_endpoint = os.getenv(f"{env_prefix}ENDPOINT")
        env_token = os.getenv(f"{env_prefix}TOKEN")
        env_timeout = os.getenv(f"{env_prefix}TIMEOUT")

        resolved_endpoint = endpoint or env_endpoint or config_section.get("endpoint")
        resolved_token = token or env_token or config_section.get("auth_token")
        resolved_timeout: float = DEFAULT_TIMEOUT

        candidate_timeout = timeout if timeout is not None else env_timeout or config_section.get("timeout")
        if candidate_timeout is not None:
            try:
                resolved_timeout = float(candidate_timeout)
            except (TypeError, ValueError):
                resolved_timeout = DEFAULT_TIMEOUT

        return cls(
            endpoint=resolved_endpoint or DEFAULT_ENDPOINT,
            auth_token=resolved_token,
            timeout=resolved_timeout,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration to a dictionary."""

        return {
            "endpoint": self.endpoint,
            "auth_token": self.auth_token,
            "timeout": self.timeout,
        }
