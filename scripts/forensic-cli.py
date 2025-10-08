#!/usr/bin/env python3
"""
Forensic Framework CLI
Command-line interface for the forensic framework
"""

import shutil
import sys
from pathlib import Path

import click

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from forensic.core.evidence import EvidenceType
from forensic.core.framework import ForensicFramework
from forensic.modules.acquisition.disk_imaging import DiskImagingModule
from forensic.modules.acquisition.live_response import LiveResponseModule
from forensic.modules.acquisition.memory_dump import MemoryDumpModule
from forensic.modules.acquisition.network_capture import NetworkCaptureModule
from forensic.modules.analysis.filesystem import FilesystemAnalysisModule
from forensic.modules.analysis.malware import MalwareAnalysisModule
from forensic.modules.analysis.timeline import TimelineModule
from forensic.modules.triage.persistence import PersistenceModule
from forensic.modules.triage.quick_triage import QuickTriageModule
from forensic.modules.triage.system_info import SystemInfoModule

try:  # pragma: no cover - optional legacy module
    from forensic.modules.analysis.ioc_scanning import IoCScanner
except ModuleNotFoundError:  # pragma: no cover - optional legacy module
    IoCScanner = None


@click.group()
@click.option(
    "--workspace", type=click.Path(), default=None, help="Workspace directory"
)
@click.option(
    "--config", type=click.Path(exists=True), default=None, help="Config file"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.pass_context
def cli(ctx, workspace, config, verbose):
    """Forensic Framework CLI"""
    ctx.ensure_object(dict)

    workspace_path = Path(workspace) if workspace else None
    config_path = Path(config) if config else None

    ctx.obj["framework"] = ForensicFramework(
        config_file=config_path, workspace=workspace_path
    )
    ctx.obj["verbose"] = verbose

    # Register modules
    framework = ctx.obj["framework"]
    ctx.obj["skipped_modules"] = {}

    def register(name, module_class, required_tools=None):
        if required_tools:
            if not any(shutil.which(tool) for tool in required_tools):
                ctx.obj["skipped_modules"][
                    name
                ] = f"missing tools: {', '.join(required_tools)}"
                return
        framework.register_module(name, module_class)

    register("disk_imaging", DiskImagingModule)
    register(
        "memory_dump", MemoryDumpModule, required_tools=["avml", "lime", "winpmem"]
    )
    register(
        "network_capture", NetworkCaptureModule, required_tools=["tcpdump", "dumpcap"]
    )
    register("live_response", LiveResponseModule)
    register("filesystem_analysis", FilesystemAnalysisModule)
    if IoCScanner is not None:
        register("ioc_scan", IoCScanner)
    else:
        ctx.obj["skipped_modules"]["ioc_scan"] = "module unavailable"
    register("timeline", TimelineModule)
    register("malware_analysis", MalwareAnalysisModule, required_tools=["yara"])
    register("quick_triage", QuickTriageModule)
    register("system_info", SystemInfoModule)
    register("persistence", PersistenceModule)


# ============================================================================
# Case Management
# ============================================================================


@cli.group()
def case():
    """Case management commands"""
    pass


@case.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Case description")
@click.option("--investigator", "-i", required=True, help="Investigator name")
@click.option("--case-id", default=None, help="Custom case ID")
@click.pass_context
def create_case(ctx, name, description, investigator, case_id):
    """Create new case"""
    framework: ForensicFramework = ctx.obj["framework"]

    case = framework.create_case(
        name=name, description=description, investigator=investigator, case_id=case_id
    )

    click.echo(f"✓ Case created: {case.case_id}")
    click.echo(f"  Name: {case.name}")
    click.echo(f"  Directory: {case.case_dir}")


@case.command("list")
@click.pass_context
def list_cases(ctx):
    """List all cases"""
    framework: ForensicFramework = ctx.obj["framework"]
    cases = framework.list_cases()

    if not cases:
        click.echo("No cases found")
        return

    click.echo("\nCases:")
    for case in cases:
        click.echo(f"  {case['case_id']}: {case['name']}")
        click.echo(f"    Investigator: {case['investigator']}")
        click.echo(f"    Created: {case['created_at']}")
        click.echo()


@case.command("load")
@click.argument("case_id")
@click.pass_context
def load_case(ctx, case_id):
    """Load existing case"""
    framework: ForensicFramework = ctx.obj["framework"]

    try:
        case = framework.load_case(case_id)
        click.echo(f"✓ Case loaded: {case.case_id}")
        click.echo(f"  Name: {case.name}")
        click.echo(f"  Directory: {case.case_dir}")
    except ValueError as e:
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)


# ============================================================================
# Evidence Management
# ============================================================================


@cli.group()
def evidence():
    """Evidence management commands"""
    pass


@evidence.command("add")
@click.argument("source_path", type=click.Path(exists=True))
@click.option(
    "--type",
    "-t",
    "evidence_type",
    type=click.Choice(["disk", "memory", "network", "file", "log", "other"]),
    required=True,
    help="Evidence type",
)
@click.option("--description", "-d", required=True, help="Evidence description")
@click.pass_context
def add_evidence(ctx, source_path, evidence_type, description):
    """Add evidence to current case"""
    framework: ForensicFramework = ctx.obj["framework"]

    if not framework.current_case:
        click.echo("✗ No active case. Load or create a case first.", err=True)
        sys.exit(1)

    evidence_type_enum = EvidenceType[evidence_type.upper()]

    evidence = framework.add_evidence(
        evidence_type=evidence_type_enum,
        source_path=Path(source_path),
        description=description,
    )

    click.echo(f"✓ Evidence added: {evidence.evidence_id}")
    click.echo(f"  Type: {evidence.evidence_type.value}")
    click.echo(f"  Hash: {evidence.hash_sha256}")


# ============================================================================
# Module Execution
# ============================================================================


@cli.group()
def module():
    """Module execution commands"""
    pass


@module.command("list")
@click.pass_context
def list_modules(ctx):
    """List available modules"""
    framework: ForensicFramework = ctx.obj["framework"]
    modules = framework.list_modules()

    click.echo("\nAvailable modules:")
    for name in sorted(modules):
        click.echo(f"  • {name}")

    skipped = ctx.obj.get("skipped_modules", {})
    if skipped:
        click.echo("\nUnavailable modules:")
        for name, reason in sorted(skipped.items()):
            click.echo(f"  • {name} ({reason})")


@module.command("run")
@click.argument("module_name")
@click.option("--param", "-p", multiple=True, help="Module parameter (key=value)")
@click.pass_context
def run_module(ctx, module_name, param):
    """Execute a module"""
    framework: ForensicFramework = ctx.obj["framework"]

    if not framework.current_case:
        click.echo("✗ No active case. Load or create a case first.", err=True)
        sys.exit(1)

    # Parse parameters
    params = {}
    for p in param:
        if "=" not in p:
            click.echo(f"✗ Invalid parameter format: {p}", err=True)
            sys.exit(1)
        key, value = p.split("=", 1)
        params[key] = value

    click.echo(f"Executing module: {module_name}")

    try:
        result = framework.execute_module(module_name, params=params)

        click.echo("\n✓ Module execution complete")
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Findings: {len(result.findings)}")
        if result.output_path:
            click.echo(f"  Output: {result.output_path}")

        if result.errors:
            click.echo("\n⚠ Errors:")
            for error in result.errors:
                click.echo(f"  • {error}")

    except Exception as e:
        click.echo(f"\n✗ Module execution failed: {e}", err=True)
        sys.exit(1)


# ============================================================================
# Pipeline Execution
# ============================================================================


@cli.command("pipeline")
@click.argument("pipeline_file", type=click.Path(exists=True))
@click.pass_context
def run_pipeline(ctx, pipeline_file):
    """Execute a forensic pipeline"""
    framework: ForensicFramework = ctx.obj["framework"]

    if not framework.current_case:
        click.echo("✗ No active case. Load or create a case first.", err=True)
        sys.exit(1)

    click.echo(f"Executing pipeline: {pipeline_file}")

    try:
        results = framework.execute_pipeline(Path(pipeline_file))

        click.echo("\n✓ Pipeline execution complete")
        click.echo(f"  Modules executed: {len(results)}")

        for result in results:
            status_symbol = "✓" if result.status == "success" else "✗"
            click.echo(f"  {status_symbol} {result.module_name}: {result.status}")

    except Exception as e:
        click.echo(f"\n✗ Pipeline execution failed: {e}", err=True)
        sys.exit(1)


# ============================================================================
# Reporting
# ============================================================================


@cli.command("report")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["html", "pdf", "json"]),
    default="html",
    help="Report format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
def generate_report(ctx, format, output):
    """Generate case report"""
    framework: ForensicFramework = ctx.obj["framework"]

    if not framework.current_case:
        click.echo("✗ No active case. Load or create a case first.", err=True)
        sys.exit(1)

    click.echo(f"Generating {format} report...")

    output_path = Path(output) if output else None
    framework.generate_report(output_path=output_path, format=format)

    click.echo("✓ Report generated")


# ============================================================================
# Quick Commands
# ============================================================================


@cli.command("quick-triage")
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--name", default="Quick Triage", help="Case name")
@click.option("--investigator", "-i", required=True, help="Investigator name")
@click.pass_context
def quick_triage(ctx, target_path, name, investigator):
    """Quick triage of a system or disk image"""
    framework: ForensicFramework = ctx.obj["framework"]

    # Create case
    click.echo("Creating case...")
    case = framework.create_case(
        name=name, description="Quick triage investigation", investigator=investigator
    )

    # Add evidence
    click.echo("Adding evidence...")
    evidence = framework.add_evidence(
        evidence_type=EvidenceType.DISK,
        source_path=Path(target_path),
        description="Target system/image",
    )

    # Run quick triage
    click.echo("Running quick triage...")
    result = framework.execute_module("quick_triage", evidence=evidence)

    click.echo("\n✓ Quick triage complete")
    click.echo(f"  Case: {case.case_id}")
    click.echo(f"  Findings: {len(result.findings)}")
    click.echo(f"  Output: {result.output_path}")


@cli.command("ioc-scan")
@click.argument("target_path", type=click.Path(exists=True))
@click.argument("ioc_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv", "text"]),
    default="json",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
def ioc_scan(ctx, target_path, ioc_file, format, output):
    """Quick IoC scan without case context"""
    click.echo(f"Scanning {target_path} for IoCs...")

    # Direct execution without case context
    from forensic.modules.analysis.ioc_scanning import ioc_scan_standalone

    result = ioc_scan_standalone(
        scan_path=Path(target_path),
        ioc_file=Path(ioc_file),
        output_format=format,
        output_file=Path(output) if output else None,
    )

    click.echo("\n✓ IoC scan complete")
    click.echo(f"  Matches: {result.get('total_matches', 0)}")
    if output:
        click.echo(f"  Output: {output}")


# ============================================================================
# Utility Commands
# ============================================================================


@cli.command("version")
def version():
    """Show version information"""
    click.echo("Forensic Framework v2.0.0")
    click.echo("Python Forensic Investigation Toolkit")


@cli.command("check-tools")
def check_tools():
    """Check if required forensic tools are installed"""
    import shutil

    tools = {
        "Core": ["dd", "sha256sum", "tar", "gzip"],
        "Disk Forensics": ["ddrescue", "ewfacquire", "fls", "icat", "mmls"],
        "Memory Forensics": ["volatility", "vol.py"],
        "Network Forensics": ["tcpdump", "tshark", "wireshark"],
        "Analysis": ["strings", "binwalk", "foremost", "bulk_extractor"],
        "Malware": ["yara", "clamav", "clamscan"],
        "Timeline": ["log2timeline.py", "psort.py"],
    }

    click.echo("\nChecking installed forensic tools:\n")

    for category, tool_list in tools.items():
        click.echo(f"{category}:")
        for tool in tool_list:
            installed = shutil.which(tool) is not None
            symbol = "✓" if installed else "✗"
            status = "installed" if installed else "not found"
            click.echo(f"  {symbol} {tool}: {status}")
        click.echo()


if __name__ == "__main__":
    cli()
