"""Build a deterministic MCP tool catalogue for Forensic Playbook."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Mapping

from ..core.framework import ForensicFramework
from .adapters import iter_tool_names
from .tools import PROMPT_PATH, PROMPT_RESOURCE, get_tool_catalog

_CATEGORY_PREFIXES: Mapping[str, str] = OrderedDict(
    [
        ("diagnostics", "diagnostics."),
        ("cases", "cases."),
        ("modules", "modules."),
        ("reports", "reports."),
        ("router", "router."),
    ]
)


def _serialise_tool(tool) -> Dict[str, Any]:  # type: ignore[no-untyped-def]
    descriptor = tool.to_descriptor()
    arguments: List[Dict[str, Any]] = descriptor.get("arguments", [])
    descriptor["arguments"] = sorted(arguments, key=lambda item: item["name"])
    metadata = descriptor.get("metadata")
    if isinstance(metadata, dict):
        descriptor["metadata"] = OrderedDict(sorted(metadata.items(), key=lambda item: item[0]))
    return descriptor


def _categorise(tool_name: str) -> str:
    for category, prefix in _CATEGORY_PREFIXES.items():
        if tool_name.startswith(prefix):
            return category
    return "other"


def build_catalog(framework: ForensicFramework) -> Dict[str, Any]:
    """Return a deterministic mapping describing all MCP tools."""

    tools = sorted(get_tool_catalog(framework), key=lambda tool: tool.name)
    groups: Dict[str, List[Dict[str, Any]]] = OrderedDict()
    for category in list(_CATEGORY_PREFIXES) + ["other"]:
        groups[category] = []

    for tool in tools:
        descriptor = _serialise_tool(tool)
        groups[_categorise(tool.name)].append(descriptor)

    for group in groups.values():
        group.sort(key=lambda item: item["name"])

    all_names = list(iter_tool_names(framework))
    catalog: Dict[str, Any] = OrderedDict(
        [
            (
                "version",
                "1.1",
            ),
            (
                "prompt",
                {
                    "name": "forensic_mode",
                    "resource": PROMPT_RESOURCE,
                    "path": str(PROMPT_PATH.resolve()),
                },
            ),
            ("tools", groups),
            (
                "metadata",
                OrderedDict(
                    [
                        ("total_tools", len(all_names)),
                        ("categories", OrderedDict((key, len(value)) for key, value in groups.items())),
                        ("tool_names", all_names),
                    ]
                ),
            ),
        ]
    )
    return catalog
