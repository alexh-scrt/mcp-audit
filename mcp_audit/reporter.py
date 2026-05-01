"""Rich-powered terminal reporter for mcp_audit findings.

This module provides functions to render AuditReport findings as:
- Colored, formatted Rich terminal tables with severity indicators
- Plain text summaries for simple output
- JSON serialization for CI/CD pipeline integration

The reporter is designed to be visually clear, with severity-coded colors,
emoji indicators, and structured tables that make it easy to triage findings
quickly in a terminal or read programmatically in JSON form.

Typical usage::

    from mcp_audit.reporter import print_report, print_json_report
    from mcp_audit.scanner import scan
    from pathlib import Path

    report = scan(Path("/home/user/.config/claude"))
    print_report(report)         # Colored terminal output
    print_json_report(report)    # JSON output to stdout
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from mcp_audit.models import AuditReport, Finding, Severity

# ---------------------------------------------------------------------------
# Rich theme and console setup
# ---------------------------------------------------------------------------

_THEME = Theme({
    "severity.critical": "bold red",
    "severity.high": "red",
    "severity.medium": "yellow",
    "severity.low": "blue",
    "severity.info": "cyan",
    "heading": "bold white",
    "muted": "dim white",
    "success": "bold green",
    "error": "bold red",
    "warning": "yellow",
    "check_id": "bold magenta",
    "file_path": "dim cyan",
    "evidence": "italic dim white",
    "remediation": "dim green",
})

# Default console writes to stdout with the custom theme.
# A stderr console is provided for error/status messages.
_STDOUT_CONSOLE = Console(theme=_THEME, highlight=False)
_STDERR_CONSOLE = Console(stderr=True, theme=_THEME, highlight=False)


# ---------------------------------------------------------------------------
# Severity display helpers
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "severity.critical",
    Severity.HIGH: "severity.high",
    Severity.MEDIUM: "severity.medium",
    Severity.LOW: "severity.low",
    Severity.INFO: "severity.info",
}

_SEVERITY_EMOJIS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "ℹ️ ",
}


def _severity_text(severity: Severity) -> Text:
    """Return a Rich Text object for a severity level with appropriate styling.

    Args:
        severity: The Severity enum value to render.

    Returns:
        A Rich Text object with the severity label styled and an emoji prefix.
    """
    emoji = _SEVERITY_EMOJIS.get(severity, "")
    label = severity.value.upper()
    style = _SEVERITY_STYLES.get(severity, "")
    t = Text()
    t.append(emoji + " ", style="")
    t.append(label, style=style)
    return t


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def print_report(
    report: AuditReport,
    *,
    console: Console | None = None,
    show_evidence: bool = True,
    show_remediation: bool = True,
    show_errors: bool = True,
    compact: bool = False,
) -> None:
    """Render an AuditReport as a rich formatted terminal report.

    Prints a header banner, a summary panel, a findings table, per-finding
    detail sections (unless compact mode is on), and a scan metadata footer.

    Args:
        report: The AuditReport to render.
        console: The Rich Console to write to. Defaults to the module-level
            stdout console.
        show_evidence: If True, include the evidence snippet for each finding.
            Defaults to True.
        show_remediation: If True, include remediation advice for each finding.
            Defaults to True.
        show_errors: If True, show a list of scan errors at the end if any
            were encountered. Defaults to True.
        compact: If True, skip detailed per-finding descriptions and print
            only the summary table. Useful for large result sets.
    """
    con = console or _STDOUT_CONSOLE

    # ----------------------------------------------------------------
    # Header
    # ----------------------------------------------------------------
    _print_header(report, con)

    # ----------------------------------------------------------------
    # Summary panel
    # ----------------------------------------------------------------
    _print_summary_panel(report, con)

    # ----------------------------------------------------------------
    # Findings table
    # ----------------------------------------------------------------
    if report.finding_count > 0:
        _print_findings_table(report, con)

        if not compact:
            _print_findings_detail(report, con, show_evidence=show_evidence,
                                   show_remediation=show_remediation)
    else:
        con.print()
        con.print("  [success]✓ No findings detected.[/success]")
        con.print()

    # ----------------------------------------------------------------
    # Errors section
    # ----------------------------------------------------------------
    if show_errors and report.errors:
        _print_errors_section(report, con)

    # ----------------------------------------------------------------
    # Footer
    # ----------------------------------------------------------------
    _print_footer(report, con)


def print_json_report(
    report: AuditReport,
    *,
    indent: int = 2,
    file: IO[str] | None = None,
) -> None:
    """Print an AuditReport serialized as formatted JSON.

    This output is suitable for consumption by CI/CD pipelines, SIEM systems,
    or other automated tools.

    Args:
        report: The AuditReport to serialize.
        indent: Number of spaces for JSON indentation. Defaults to 2.
        file: File-like object to write to. Defaults to sys.stdout.
    """
    out = file or sys.stdout
    out.write(report.to_json(indent=indent))
    out.write("\n")


def format_finding_short(finding: Finding) -> str:
    """Format a single finding as a compact one-line string.

    Useful for simple list output or logging.

    Args:
        finding: The Finding to format.

    Returns:
        A single-line string summarizing the finding.
    """
    location = ""
    if finding.file_path:
        location = str(finding.file_path)
        if finding.line_number is not None:
            location += f":{finding.line_number}"
        location = f" [{location}]"

    return (
        f"[{finding.check_id}] {finding.severity.value.upper()}: "
        f"{finding.title}{location}"
    )


def create_console(
    *,
    stderr: bool = False,
    no_color: bool = False,
    width: int | None = None,
) -> Console:
    """Create a Rich Console with the mcp_audit theme.

    Args:
        stderr: If True, create a console that writes to stderr.
            Defaults to False (stdout).
        no_color: If True, disable color output (useful for piped output).
            Defaults to False.
        width: Optional fixed terminal width override.

    Returns:
        A configured Rich Console instance.
    """
    kwargs: dict = {
        "theme": _THEME,
        "highlight": False,
        "stderr": stderr,
    }
    if no_color:
        kwargs["no_color"] = True
        kwargs["highlight"] = False
    if width is not None:
        kwargs["width"] = width
    return Console(**kwargs)


# ---------------------------------------------------------------------------
# Internal rendering helpers
# ---------------------------------------------------------------------------


def _print_header(report: AuditReport, con: Console) -> None:
    """Print the report header banner.

    Args:
        report: The AuditReport being rendered.
        con: The Rich Console to write to.
    """
    con.print()
    con.print(
        Panel(
            Text.assemble(
                ("🔍 MCP Audit Security Report\n", "bold white"),
                (f"Target: ", "muted"),
                (str(report.scan_target), "file_path"),
            ),
            style="bold blue",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )


def _print_summary_panel(report: AuditReport, con: Console) -> None:
    """Print a summary panel with counts by severity.

    Args:
        report: The AuditReport to summarize.
        con: The Rich Console to write to.
    """
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column("Label", style="muted")
    table.add_column("Value", justify="right")

    # Severity counts
    severity_rows: list[tuple[str, int, str]] = [
        ("Critical", report.critical_count, "severity.critical"),
        ("High", report.high_count, "severity.high"),
        ("Medium", report.medium_count, "severity.medium"),
        ("Low", report.low_count, "severity.low"),
        ("Info", report.info_count, "severity.info"),
    ]
    for label, count, style in severity_rows:
        count_text = Text(str(count), style=style if count > 0 else "muted")
        table.add_row(f"{_SEVERITY_EMOJIS[Severity(label.lower())]} {label}:", count_text)

    table.add_row("", "")
    table.add_row(
        "Total Findings:",
        Text(str(report.finding_count), style="bold white"),
    )
    table.add_row(
        "Files Scanned:",
        Text(str(len(report.scanned_files)), style="bold white"),
    )
    if report.duration_seconds is not None:
        table.add_row(
            "Scan Duration:",
            Text(f"{report.duration_seconds:.2f}s", style="muted"),
        )
    if report.errors:
        table.add_row(
            "Errors:",
            Text(str(len(report.errors)), style="warning"),
        )

    # Status badge
    if report.finding_count == 0:
        status = Text(" PASS ✓ ", style="bold green on dark_green")
    elif report.has_critical_or_high():
        status = Text(" FAIL ✗ ", style="bold white on red")
    else:
        status = Text(" WARN ⚠ ", style="bold black on yellow")

    summary_content = Text()
    summary_content.append_text(status)
    summary_content.append("\n\n")

    # We'll use a nested layout: status on top, table below
    from rich.columns import Columns

    con.print()
    con.print(Panel(
        table,
        title=status,
        title_align="left",
        style="blue",
        box=box.ROUNDED,
        padding=(0, 1),
    ))


def _print_findings_table(report: AuditReport, con: Console) -> None:
    """Print a compact table summarizing all findings.

    Args:
        report: The AuditReport whose findings to tabulate.
        con: The Rich Console to write to.
    """
    con.print()
    con.print("[heading]Findings Summary[/heading]")
    con.print()

    table = Table(
        show_header=True,
        header_style="bold white",
        box=box.SIMPLE_HEAD,
        expand=True,
        padding=(0, 1),
    )
    table.add_column("#", style="muted", width=4, justify="right")
    table.add_column("Check ID", style="check_id", width=12)
    table.add_column("Severity", width=14)
    table.add_column("Title", ratio=3)
    table.add_column("Location", ratio=2, style="file_path", overflow="fold")

    for idx, finding in enumerate(report.findings_by_severity(), start=1):
        location = ""
        if finding.file_path:
            # Show only the last 2 path components for brevity
            parts = finding.file_path.parts
            if len(parts) > 2:
                location = "..." + str(Path(*parts[-2:]))
            else:
                location = str(finding.file_path)
            if finding.line_number is not None:
                location += f":{finding.line_number}"

        table.add_row(
            str(idx),
            finding.check_id,
            _severity_text(finding.severity),
            finding.title,
            location,
        )

    con.print(table)


def _print_findings_detail(  # noqa: C901
    report: AuditReport,
    con: Console,
    *,
    show_evidence: bool,
    show_remediation: bool,
) -> None:
    """Print detailed information for each finding.

    Each finding gets its own panel with description, evidence, and
    remediation advice.

    Args:
        report: The AuditReport whose findings to detail.
        con: The Rich Console to write to.
        show_evidence: Whether to include the evidence snippet.
        show_remediation: Whether to include remediation advice.
    """
    con.print()
    con.print("[heading]Finding Details[/heading]")

    for idx, finding in enumerate(report.findings_by_severity(), start=1):
        sev_style = _SEVERITY_STYLES.get(finding.severity, "")
        emoji = _SEVERITY_EMOJIS.get(finding.severity, "")

        # Build the panel title
        title_text = Text()
        title_text.append(f" {idx}. ", style="bold white")
        title_text.append(f"[{finding.check_id}] ", style="check_id")
        title_text.append(f"{emoji} ", style="")
        title_text.append(finding.severity.value.upper(), style=sev_style)
        title_text.append(f": {finding.title} ", style="bold white")

        # Build panel body
        body = Text()

        # Description
        body.append("Description:\n", style="bold white")
        body.append(f"  {finding.description}\n", style="white")

        # Location
        if finding.file_path:
            body.append("\nFile: ", style="bold white")
            location_str = str(finding.file_path)
            if finding.line_number is not None:
                location_str += f":{finding.line_number}"
            body.append(location_str + "\n", style="file_path")

        # Evidence
        if show_evidence and finding.evidence:
            body.append("\nEvidence:\n", style="bold white")
            body.append(f"  {finding.evidence}\n", style="evidence")

        # Remediation
        if show_remediation and finding.remediation:
            body.append("\nRemediation:\n", style="bold white")
            body.append(f"  {finding.remediation}\n", style="remediation")

        con.print()
        con.print(Panel(
            body,
            title=title_text,
            title_align="left",
            border_style=sev_style,
            box=box.ROUNDED,
            padding=(0, 1),
        ))


def _print_errors_section(report: AuditReport, con: Console) -> None:
    """Print a section listing scan errors.

    Args:
        report: The AuditReport whose errors to list.
        con: The Rich Console to write to.
    """
    con.print()
    con.print(f"[warning]⚠ Scan Errors ({len(report.errors)})[/warning]")
    con.print()

    for error in report.errors:
        con.print(f"  [error]•[/error] [muted]{error}[/muted]")


def _print_footer(report: AuditReport, con: Console) -> None:
    """Print the report footer with scan metadata.

    Args:
        report: The AuditReport to summarize in the footer.
        con: The Rich Console to write to.
    """
    con.print()

    footer_parts: list[str] = []
    if report.started_at:
        footer_parts.append(f"Scanned at: {report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if report.duration_seconds is not None:
        footer_parts.append(f"Duration: {report.duration_seconds:.2f}s")
    footer_parts.append(f"Files: {len(report.scanned_files)}")
    footer_parts.append(f"Findings: {report.finding_count}")

    con.print(
        Panel(
            Text("  |  ".join(footer_parts), style="muted"),
            style="dim blue",
            box=box.HORIZONTALS,
            padding=(0, 1),
        )
    )
    con.print()
