"""Click-based CLI entry point for mcp_audit.

This module provides the ``mcp-audit`` command-line tool that orchestrates
the scanning pipeline, formats results, and exits with appropriate codes
for CI/CD integration.

Usage examples::

    # Scan a directory with rich terminal output
    mcp-audit scan ~/.config/claude

    # Scan a specific file
    mcp-audit scan claude_desktop_config.json

    # Output machine-readable JSON
    mcp-audit scan ~/.config/claude --json

    # Emit JSON to a file
    mcp-audit scan . --json --output report.json

    # Only run specific checks
    mcp-audit scan . --no-supply-chain --no-env

    # Increase verbosity (show evidence + remediation)
    mcp-audit scan . --verbose

    # Compact output (summary table only, no details)
    mcp-audit scan . --compact

    # Fail only on critical/high findings
    mcp-audit scan . --fail-on high
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from mcp_audit import __version__
from mcp_audit.models import AuditReport, Severity
from mcp_audit.reporter import create_console, print_json_report, print_report
from mcp_audit.scanner import exit_code_for_report, scan

# ---------------------------------------------------------------------------
# Severity threshold mapping for --fail-on
# ---------------------------------------------------------------------------

_FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "info", "never")

_FAIL_ON_SEVERITY_MAP: dict[str, Severity | None] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "never": None,
}


def _compute_exit_code(
    report: AuditReport,
    fail_on: str,
) -> int:
    """Compute the process exit code based on report findings and --fail-on threshold.

    When ``fail_on`` is ``'never'``, always returns 0 (success), which is useful
    for audit-only runs that must not block pipelines.

    When ``fail_on`` is a severity level, returns a non-zero code only if at
    least one finding meets or exceeds that severity; otherwise returns 0.

    If ``fail_on`` is ``'auto'`` (or not matched), falls back to the scanner's
    default exit code logic.

    Args:
        report: The completed AuditReport.
        fail_on: One of the ``_FAIL_ON_CHOICES`` strings.

    Returns:
        Integer exit code where 0 = success (no qualifying findings).
    """
    if fail_on == "never":
        return 0

    threshold = _FAIL_ON_SEVERITY_MAP.get(fail_on)
    if threshold is None:
        # Fallback to default scanner exit code
        return exit_code_for_report(report)

    # Build the ordered list of severities at or above threshold
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    threshold_idx = severity_order.index(threshold)
    qualifying_severities = set(severity_order[:threshold_idx + 1])

    has_qualifying = any(
        f.severity in qualifying_severities for f in report.findings
    )

    if not has_qualifying:
        return 0

    # Return the standard severity-based exit code
    return exit_code_for_report(report)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version=__version__, prog_name="mcp-audit")
def main() -> None:
    """mcp-audit: Security scanner for MCP server configurations.

    Scans MCP (Model Context Protocol) server configuration files and
    startup directories for pre-initialization injection risks including:

    \b
    • Permission vulnerabilities (world-writable config files)
    • Pre-sandbox hook injection (preExec, onInit, lifecycle scripts)
    • Environment variable injection (LD_PRELOAD, PATH manipulation)
    • Supply chain risks (unversioned packages, unknown registries)

    Use 'mcp-audit scan --help' for scanning options.
    """


# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------


@main.command(name="scan")
@click.argument(
    "target",
    default=".",
    type=click.Path(exists=False, file_okay=True, dir_okay=True, path_type=Path),
    metavar="TARGET",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Emit machine-readable JSON output instead of rich terminal tables.",
)
@click.option(
    "--output", "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write output to FILE instead of stdout. Implies --json if the "
         "file has a .json extension.",
)
@click.option(
    "--no-recursive",
    is_flag=True,
    default=False,
    help="Do not recurse into subdirectories.",
)
@click.option(
    "--max-depth",
    type=click.IntRange(min=1, max=50),
    default=8,
    show_default=True,
    help="Maximum directory recursion depth.",
)
@click.option(
    "--no-permissions",
    is_flag=True,
    default=False,
    help="Skip file and directory permission checks.",
)
@click.option(
    "--no-hooks",
    is_flag=True,
    default=False,
    help="Skip pre-sandbox hook injection checks.",
)
@click.option(
    "--no-env",
    is_flag=True,
    default=False,
    help="Skip environment variable injection checks.",
)
@click.option(
    "--no-supply-chain",
    is_flag=True,
    default=False,
    help="Skip supply chain risk checks.",
)
@click.option(
    "--follow-symlinks",
    is_flag=True,
    default=False,
    help="Follow symbolic links during directory traversal.",
)
@click.option(
    "--fail-on",
    type=click.Choice(_FAIL_ON_CHOICES, case_sensitive=False),
    default="info",
    show_default=True,
    help="Minimum severity level that causes a non-zero exit code. "
         "Use 'never' to always exit 0 (audit-only mode).",
)
@click.option(
    "--min-severity",
    type=click.Choice(
        [s.value for s in Severity], case_sensitive=False
    ),
    default=None,
    help="Only display findings at or above this severity level.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Show detailed finding descriptions, evidence, and remediation advice.",
)
@click.option(
    "--compact",
    is_flag=True,
    default=False,
    help="Show only the findings summary table without per-finding detail panels.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored output (useful when piping to other tools).",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress all output except errors. Useful in CI when only the "
         "exit code matters.",
)
@click.pass_context
def scan_command(
    ctx: click.Context,
    target: Path,
    output_json: bool,
    output_file: Optional[Path],
    no_recursive: bool,
    max_depth: int,
    no_permissions: bool,
    no_hooks: bool,
    no_env: bool,
    no_supply_chain: bool,
    follow_symlinks: bool,
    fail_on: str,
    min_severity: Optional[str],
    verbose: bool,
    compact: bool,
    no_color: bool,
    quiet: bool,
) -> None:
    """Scan TARGET for MCP security vulnerabilities.

    TARGET can be a file (e.g., claude_desktop_config.json) or a directory
    (e.g., ~/.config/claude or the current directory '.'). When TARGET is a
    directory, it is searched recursively for MCP configuration files and
    package manifests.

    Exit codes:

    \b
      0 - No findings (or --fail-on never)
      1 - Only LOW / INFO findings
      2 - At least one MEDIUM finding
      3 - At least one HIGH finding
      4 - At least one CRITICAL finding
      5 - Scan errors with no findings
    """
    # ------------------------------------------------------------------
    # Resolve output mode
    # ------------------------------------------------------------------
    # If writing to a .json file, implicitly enable JSON mode
    if output_file is not None and output_file.suffix.lower() == ".json":
        output_json = True

    # ------------------------------------------------------------------
    # Validate target exists
    # ------------------------------------------------------------------
    stderr_console = create_console(stderr=True, no_color=no_color)

    if not target.exists():
        stderr_console.print(
            f"[error]Error:[/error] Target path does not exist: [file_path]{target}[/file_path]"
        )
        ctx.exit(1)
        return

    # ------------------------------------------------------------------
    # Run the scan
    # ------------------------------------------------------------------
    if not quiet and not output_json:
        stderr_console.print(
            f"[muted]Scanning [file_path]{target}[/file_path]...[/muted]"
        )

    try:
        report = scan(
            target,
            recursive=not no_recursive,
            max_depth=max_depth,
            include_supply_chain=not no_supply_chain,
            include_permissions=not no_permissions,
            include_hooks=not no_hooks,
            include_env_injection=not no_env,
            follow_symlinks=follow_symlinks,
        )
    except KeyboardInterrupt:
        stderr_console.print("\n[warning]Scan interrupted by user.[/warning]")
        ctx.exit(130)
        return
    except Exception as exc:
        stderr_console.print(
            f"[error]Fatal error during scan:[/error] {type(exc).__name__}: {exc}"
        )
        ctx.exit(1)
        return

    # ------------------------------------------------------------------
    # Filter findings by minimum severity if requested
    # ------------------------------------------------------------------
    if min_severity is not None:
        min_sev = Severity(min_severity.lower())
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        min_idx = severity_order.index(min_sev)
        qualifying = set(severity_order[:min_idx + 1])
        report.findings = [
            f for f in report.findings if f.severity in qualifying
        ]

    # ------------------------------------------------------------------
    # Compute exit code (before output, in case we need to reference it)
    # ------------------------------------------------------------------
    code = _compute_exit_code(report, fail_on)

    # ------------------------------------------------------------------
    # Produce output
    # ------------------------------------------------------------------
    if quiet:
        # No output in quiet mode; just exit with the code
        pass
    elif output_json:
        _write_json_output(report, output_file, stderr_console)
    else:
        _write_terminal_output(
            report=report,
            output_file=output_file,
            no_color=no_color,
            verbose=verbose,
            compact=compact,
            stderr_console=stderr_console,
        )

    # ------------------------------------------------------------------
    # Exit with computed code
    # ------------------------------------------------------------------
    sys.exit(code)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _write_json_output(
    report: AuditReport,
    output_file: Optional[Path],
    stderr_console: Console,
) -> None:
    """Write JSON output to stdout or a file.

    Args:
        report: The AuditReport to serialize.
        output_file: Optional file path to write to. If None, writes to stdout.
        stderr_console: Console for error messages.
    """
    json_str = report.to_json(indent=2)

    if output_file is not None:
        try:
            output_file.write_text(json_str + "\n", encoding="utf-8")
            stderr_console.print(
                f"[muted]JSON report written to [file_path]{output_file}[/file_path][/muted]"
            )
        except OSError as exc:
            stderr_console.print(
                f"[error]Failed to write output file '{output_file}': {exc}[/error]"
            )
            sys.stdout.write(json_str + "\n")
    else:
        sys.stdout.write(json_str + "\n")


def _write_terminal_output(
    report: AuditReport,
    output_file: Optional[Path],
    no_color: bool,
    verbose: bool,
    compact: bool,
    stderr_console: Console,
) -> None:
    """Write rich terminal output to stdout or a file.

    Args:
        report: The AuditReport to render.
        output_file: Optional file path to write plain text output to.
            When writing to a file, colors are disabled.
        no_color: Whether to disable color output.
        verbose: Whether to show full evidence and remediation.
        compact: Whether to show only the summary table.
        stderr_console: Console for error messages.
    """
    if output_file is not None:
        # Write to file as plain text (no ANSI escape codes)
        try:
            with output_file.open("w", encoding="utf-8") as f:
                file_console = Console(
                    file=f,
                    theme=None,
                    highlight=False,
                    no_color=True,
                )
                print_report(
                    report,
                    console=file_console,
                    show_evidence=verbose,
                    show_remediation=verbose,
                    compact=compact,
                )
            stderr_console.print(
                f"[muted]Report written to [file_path]{output_file}[/file_path][/muted]"
            )
        except OSError as exc:
            stderr_console.print(
                f"[error]Failed to write output file '{output_file}': {exc}[/error]"
            )
    else:
        con = create_console(no_color=no_color)
        print_report(
            report,
            console=con,
            show_evidence=verbose,
            show_remediation=verbose,
            compact=compact,
        )


# ---------------------------------------------------------------------------
# Additional subcommands
# ---------------------------------------------------------------------------


@main.command(name="version")
def version_command() -> None:
    """Print the mcp-audit version and exit."""
    click.echo(f"mcp-audit version {__version__}")


@main.command(name="checks")
@click.option(
    "--json", "output_json",
    is_flag=True,
    default=False,
    help="Output check list as JSON.",
)
def checks_command(output_json: bool) -> None:
    """List all available security checks and their IDs."""
    check_catalog: list[dict] = [
        # Permissions
        {"id": "PERM-001", "category": "permissions",
         "severity": "critical",
         "title": "World-writable config file or directory"},
        {"id": "PERM-002", "category": "permissions",
         "severity": "high",
         "title": "Group-writable config file or directory"},
        {"id": "PERM-003", "category": "permissions",
         "severity": "high",
         "title": "World-readable sensitive config file"},
        {"id": "PERM-004", "category": "permissions",
         "severity": "critical",
         "title": "World-writable directory without sticky bit"},
        {"id": "PERM-005", "category": "permissions",
         "severity": "high",
         "title": "Root-owned config file writable by current user"},
        {"id": "PERM-006", "category": "permissions",
         "severity": "medium",
         "title": "Config file has executable permission bits"},
        # Hooks
        {"id": "HOOK-001", "category": "hooks",
         "severity": "critical",
         "title": "MCP server uses shell as command"},
        {"id": "HOOK-002", "category": "hooks",
         "severity": "high",
         "title": "Shell execution pattern in hook or server args"},
        {"id": "HOOK-003", "category": "hooks",
         "severity": "low",
         "title": "Lifecycle hook key detected (informational)"},
        {"id": "HOOK-004", "category": "hooks",
         "severity": "medium",
         "title": "Suspicious path reference in hook"},
        {"id": "HOOK-006", "category": "hooks",
         "severity": "high",
         "title": "Dynamic code execution in hook"},
        {"id": "HOOK-007", "category": "hooks",
         "severity": "critical",
         "title": "Network fetch in hook or command context"},
        {"id": "HOOK-008", "category": "hooks",
         "severity": "high",
         "title": "Command substitution pattern detected"},
        # Environment injection
        {"id": "ENV-001", "category": "env_injection",
         "severity": "critical",
         "title": "Suspicious directory prepended to PATH"},
        {"id": "ENV-002", "category": "env_injection",
         "severity": "critical",
         "title": "LD_PRELOAD or LD_LIBRARY_PATH injection"},
        {"id": "ENV-003", "category": "env_injection",
         "severity": "high",
         "title": "PYTHONPATH or PYTHONSTARTUP injection"},
        {"id": "ENV-004", "category": "env_injection",
         "severity": "high",
         "title": "NODE_OPTIONS or NODE_PATH injection"},
        {"id": "ENV-005", "category": "env_injection",
         "severity": "critical",
         "title": "DYLD_INSERT_LIBRARIES injection (macOS)"},
        {"id": "ENV-006", "category": "env_injection",
         "severity": "high",
         "title": "Shell init file override (BASH_ENV, ENV, ZDOTDIR)"},
        {"id": "ENV-007", "category": "env_injection",
         "severity": "medium",
         "title": "Temp/world-writable path in environment variable"},
        {"id": "ENV-008", "category": "env_injection",
         "severity": "critical",
         "title": "LD_AUDIT or LD_DEBUG linker injection"},
        {"id": "ENV-009", "category": "env_injection",
         "severity": "medium",
         "title": "Ruby/Perl interpreter injection variable"},
        {"id": "ENV-010", "category": "env_injection",
         "severity": "medium",
         "title": "JVM options injection (JAVA_TOOL_OPTIONS, etc.)"},
        {"id": "ENV-011", "category": "env_injection",
         "severity": "critical",
         "title": "Command substitution in environment variable value"},
        {"id": "ENV-012", "category": "env_injection",
         "severity": "critical",
         "title": "Multiple dangerous environment variables configured"},
        # Supply chain
        {"id": "SC-001", "category": "supply_chain",
         "severity": "high",
         "title": "Unversioned npm package dependency"},
        {"id": "SC-002", "category": "supply_chain",
         "severity": "medium",
         "title": "Unversioned pip/Python package dependency"},
        {"id": "SC-003", "category": "supply_chain",
         "severity": "medium",
         "title": "Overly broad version range"},
        {"id": "SC-004", "category": "supply_chain",
         "severity": "medium",
         "title": "Missing dependency lockfile"},
        {"id": "SC-005", "category": "supply_chain",
         "severity": "high",
         "title": "Non-standard npm registry"},
        {"id": "SC-006", "category": "supply_chain",
         "severity": "high",
         "title": "Non-standard pip index URL"},
        {"id": "SC-007", "category": "supply_chain",
         "severity": "high",
         "title": "Packages missing integrity hashes in lockfile"},
        {"id": "SC-008", "category": "supply_chain",
         "severity": "high",
         "title": "Package referenced via git URL"},
        {"id": "SC-009", "category": "supply_chain",
         "severity": "medium",
         "title": "Package referenced via local path"},
        {"id": "SC-010", "category": "supply_chain",
         "severity": "high",
         "title": "Possible typosquatted package name"},
        {"id": "SC-011", "category": "supply_chain",
         "severity": "high",
         "title": "npx invocation with unversioned package"},
        {"id": "SC-012", "category": "supply_chain",
         "severity": "medium",
         "title": "uvx/pipx invocation with unversioned package"},
    ]

    if output_json:
        import json
        click.echo(json.dumps(check_catalog, indent=2))
    else:
        con = Console(highlight=False)
        from rich.table import Table
        from rich import box as rich_box

        table = Table(
            title="Available Security Checks",
            box=rich_box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold white",
        )
        table.add_column("Check ID", style="bold magenta", width=12)
        table.add_column("Category", width=16)
        table.add_column("Severity", width=10)
        table.add_column("Title")

        _severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "cyan",
        }
        from rich.text import Text as RichText
        for check in check_catalog:
            sev = check["severity"]
            sev_text = RichText(sev.upper(), style=_severity_colors.get(sev, ""))
            table.add_row(
                check["id"],
                check["category"],
                sev_text,
                check["title"],
            )

        con.print(table)
        con.print(f"\n[dim]Total: {len(check_catalog)} checks[/dim]")


# ---------------------------------------------------------------------------
# Entry point guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    main()
