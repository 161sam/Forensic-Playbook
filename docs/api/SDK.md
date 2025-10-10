# Forensic SDK Quickstart (Forensic Mode)

The Python SDK mirrors the guarded behaviour of `forensic-cli`. All examples respect Forensic Mode guardrails: prefer dry-runs, record provenance, and keep outputs deterministic.

## Initialization
```python
from pathlib import Path
from forensic import ForensicFramework

workspace = Path("./forensic_workspace_demo")
framework = ForensicFramework(workspace=workspace)
```
- The workspace is created automatically (read/write within the demo path).
- Logs live under `workspace / "logs"` and the case database under `workspace / "cases.db"`.

## Create or Load a Case
```python
case = framework.create_case(
    name="Demo Incident",
    description="Guarded SDK quickstart",
    investigator="Analyst Alice",
)
# Subsequent runs can reuse the case via framework.load_case(case.case_id)
```
Every case creation is logged to the chain-of-custody database.

## Register and Execute Modules
Built-in modules are already registered when using the CLI, but the SDK allows custom modules:
```python
from forensic.core.module import ForensicModule, ModuleResult

class HelloModule(ForensicModule):
    def run(self, evidence, params):
        return ModuleResult(
            result_id="hello-0001",
            module_name="hello",
            status="success",
            timestamp=self._timestamp(),
            findings=[{"message": "Hello from Forensic Mode"}],
            metadata={"dry_run": bool(params.get("dry_run", False))},
        )

framework.register_module("hello", HelloModule)
framework.load_case(case.case_id)
result = framework.execute_module("hello", params={"dry_run": True})
```
- Always load the target case before execution.
- Include dry-run metadata so downstream tooling can report it.

## Generate Reports Programmatically
```python
from forensic.modules.reporting.generator import ReportGenerator

framework.load_case(case.case_id)
reporter = ReportGenerator(case_dir=case.case_dir, config=framework.config)
report_result = reporter.run(None, {"format": "html", "dry_run": True})
```
- Dry-run mode plans file outputs without writing them. Inspect `report_result.metadata["planned_output"]` for the intended path.

## MCP Client Shortcuts
The SDK exposes a guarded MCP client for integrating with Codex:
```python
from forensic import MCPClient, MCPConfig, build_mcp_tool_payload, run_mcp_tool

config = MCPConfig(endpoint="http://127.0.0.1:5000/", timeout=5.0)
client = MCPClient(config)
status = client.status()
print(status.to_dict())
client.close()

# Local execution without HTTP
framework.load_case(case.case_id)
local_result = run_mcp_tool(framework, "diagnostics.ping", {})
print(local_result.to_dict())
```
- Use `build_mcp_tool_payload(framework)` to fetch the current tool catalogue (mirrors `forensic-cli mcp expose`).
- Prefer local execution during testing; remote execution should target a guarded MCP server started via `forensic-cli codex start --dry-run` first.

## Codex Helpers
Codex automation is available via high-level helpers:
```python
from forensic import install_codex_environment, start_codex_server, stop_codex_server, get_codex_status
from forensic.ops.codex import resolve_paths

paths = resolve_paths()
install_codex_environment(paths, dry_run=True)
start_codex_server(paths, dry_run=True)
status = get_codex_status(paths)
print(status.to_status_payload("sdk.status"))
stop_codex_server(paths, dry_run=True)
```
- Always begin with `dry_run=True` to verify planned actions and log locations under `<workspace>/codex_logs/`.

## Next Steps
- Consult `docs/Getting-Started.md` for end-to-end workflows covering CLI and MCP interactions.
- Use `tests/` as references for writing deterministic unit tests with mocks/fixtures.

Stay within Forensic Mode guardrails: log provenance, highlight dry-run vs execution, and decline unsafe requests.
