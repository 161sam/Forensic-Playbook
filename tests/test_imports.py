"""Smoke tests ensuring critical modules are importable."""

import importlib

import pytest

MODULE_PATHS = [
    "forensic.core.evidence",
    "forensic.core.chain_of_custody",
    "forensic.core.logger",
    "forensic.modules.triage.quick_triage",
]


@pytest.mark.parametrize("module_path", MODULE_PATHS)
def test_module_importable(module_path):
    """Ensure the migrated modules can be imported without errors."""
    module = importlib.import_module(module_path)
    assert module is not None
