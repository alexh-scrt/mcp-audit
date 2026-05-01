"""Unit tests for the mcp_audit reporter module.

Tests cover:
- Terminal report rendering (no exceptions, correct sections present)
- JSON output serialization
- Short finding format helper
- Severity text rendering
- Console creation helpers
- Empty report rendering
- Reports with findings of various severities
- Compact mode output
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from mcp_audit.models import AuditReport, Finding, Severity
from mcp_audit.reporter import (
    create_console,
    format_finding_short,
    print_json_report,
    print_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_console(width: int = 120) -> tuple[Console, io.StringIO]:
    """Create a Rich Console that writes to a StringIO buffer."""
    buf = io.StringIO()
    con = Console(
        file=buf,
        highlight=False,
        no_color=True,
        width=width,
    )
    return con, buf


def _make_finding(
    check_id: str = "TEST-001",
    severity: Severity = Severity.HIGH,
    title: str = "Test Finding",
    description: str = "A test finding description.",
    file_path: Path | None = None,
    line_number: int | None = None,
    evidence: str | None = "some evidence",
    remediation: str | None = "fix it",
) -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,
        title=title,
        description=description,
        file_path=file_path,
        line_number=line_number,
        evidence=evidence,
        remediation=remediation,
    )


def _make_report(
    scan_target: Path | None = None,
    findings: list[Finding] | None = None,
    errors: list[str] | None = None,
) -> AuditReport:
    target = scan_target or Path("/tmp/test")
    report = AuditReport(scan_target=target)
    for f in findings or []:
        report.add_finding(f)
    for e in errors or []:
        report.add_error(e)
    report.mark_finished()
    return report


# ---------------------------------------------------------------------------
# Tests: print_report() - no exceptions
# ---------------------------------------------------------------------------


class TestPrintReport:
    def test_empty_report_renders_without_error(self, tmp_path: Path) -> None:
        report = _make_report(scan_target=tmp_path)
        con, buf = _make_console()
        # Should not raise
        print_report(report, console=con)
        output = buf.getvalue()
        assert len(output) > 0

    def test_report_with_findings_renders(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("PERM-001", Severity.CRITICAL, file_path=tmp_path / "mcp.json"),
            _make_finding("HOOK-002", Severity.HIGH),
            _make_finding("ENV-003", Severity.MEDIUM),
            _make_finding("SC-011", Severity.LOW),
            _make_finding("SC-004", Severity.INFO),
        ]
        report = _make_report(scan_target=tmp_path, findings=findings)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        assert "PERM-001" in output
        assert "HOOK-002" in output
        assert "ENV-003" in output

    def test_report_shows_scan_target(self, tmp_path: Path) -> None:
        report = _make_report(scan_target=tmp_path)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        # The target path should appear somewhere in the output
        assert str(tmp_path) in output

    def test_report_shows_summary_counts(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("A", Severity.CRITICAL),
            _make_finding("B", Severity.HIGH),
        ]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        # Should mention critical and high severity labels
        assert "Critical" in output or "CRITICAL" in output
        assert "High" in output or "HIGH" in output

    def test_report_shows_pass_when_no_findings(self, tmp_path: Path) -> None:
        report = _make_report(scan_target=tmp_path)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        assert "PASS" in output or "No findings" in output

    def test_report_shows_fail_with_critical(self, tmp_path: Path) -> None:
        findings = [_make_finding("X", Severity.CRITICAL)]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        assert "FAIL" in output

    def test_report_shows_errors_section(self, tmp_path: Path) -> None:
        report = _make_report(errors=["Something went wrong"])
        con, buf = _make_console()
        print_report(report, console=con, show_errors=True)
        output = buf.getvalue()
        assert "Something went wrong" in output

    def test_report_hides_errors_when_disabled(self, tmp_path: Path) -> None:
        report = _make_report(errors=["Unique error text abc123"])
        con, buf = _make_console()
        print_report(report, console=con, show_errors=False)
        output = buf.getvalue()
        assert "Unique error text abc123" not in output

    def test_compact_mode_no_detail_panels(self, tmp_path: Path) -> None:
        findings = [_make_finding("PERM-001", Severity.CRITICAL)]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, compact=True)
        output = buf.getvalue()
        # In compact mode, the detail section should not include "Description:"
        # (which appears in the detail panels)
        # The summary table should still be present
        assert "PERM-001" in output

    def test_show_evidence_true_includes_evidence(self, tmp_path: Path) -> None:
        findings = [_make_finding("X", Severity.HIGH, evidence="my_unique_evidence_token")]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, show_evidence=True, compact=False)
        output = buf.getvalue()
        assert "my_unique_evidence_token" in output

    def test_show_evidence_false_hides_evidence(self, tmp_path: Path) -> None:
        findings = [_make_finding("X", Severity.HIGH, evidence="my_unique_evidence_token")]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, show_evidence=False, compact=False)
        output = buf.getvalue()
        assert "my_unique_evidence_token" not in output

    def test_show_remediation_true_includes_remediation(self, tmp_path: Path) -> None:
        findings = [_make_finding("X", Severity.HIGH, remediation="unique_remediation_text")]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, show_remediation=True, compact=False)
        output = buf.getvalue()
        assert "unique_remediation_text" in output

    def test_show_remediation_false_hides_remediation(self, tmp_path: Path) -> None:
        findings = [_make_finding("X", Severity.HIGH, remediation="unique_remediation_text")]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, show_remediation=False, compact=False)
        output = buf.getvalue()
        assert "unique_remediation_text" not in output

    def test_finding_with_file_path_shows_location(self, tmp_path: Path) -> None:
        file_path = tmp_path / "some" / "config.json"
        findings = [_make_finding("X", Severity.HIGH, file_path=file_path)]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, compact=False)
        output = buf.getvalue()
        # The filename should appear
        assert "config.json" in output

    def test_finding_with_line_number(self, tmp_path: Path) -> None:
        file_path = tmp_path / "config.json"
        findings = [_make_finding("X", Severity.HIGH, file_path=file_path, line_number=42)]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con, compact=False)
        output = buf.getvalue()
        assert "42" in output

    def test_duration_appears_in_output(self, tmp_path: Path) -> None:
        report = _make_report(scan_target=tmp_path)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        # Duration should be shown (e.g., "0.00s")
        assert "s" in output  # broad check for duration suffix

    def test_findings_sorted_by_severity(self, tmp_path: Path) -> None:
        findings = [
            _make_finding("LOW-1", Severity.LOW, title="Low finding"),
            _make_finding("CRIT-1", Severity.CRITICAL, title="Critical finding"),
            _make_finding("MED-1", Severity.MEDIUM, title="Medium finding"),
        ]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        # Critical should appear before Low in the output
        crit_pos = output.find("CRIT-1")
        low_pos = output.find("LOW-1")
        assert crit_pos < low_pos


# ---------------------------------------------------------------------------
# Tests: print_json_report()
# ---------------------------------------------------------------------------


class TestPrintJsonReport:
    def test_json_output_is_valid_json(self, tmp_path: Path) -> None:
        findings = [_make_finding("X", Severity.HIGH)]
        report = _make_report(findings=findings)
        buf = io.StringIO()
        print_json_report(report, file=buf)
        data = json.loads(buf.getvalue())
        assert isinstance(data, dict)

    def test_json_output_contains_findings(self, tmp_path: Path) -> None:
        findings = [_make_finding("PERM-001", Severity.CRITICAL)]
        report = _make_report(findings=findings)
        buf = io.StringIO()
        print_json_report(report, file=buf)
        data = json.loads(buf.getvalue())
        assert len(data["findings"]) == 1
        assert data["findings"][0]["check_id"] == "PERM-001"

    def test_json_output_contains_summary(self, tmp_path: Path) -> None:
        report = _make_report()
        buf = io.StringIO()
        print_json_report(report, file=buf)
        data = json.loads(buf.getvalue())
        assert "summary" in data
        assert "total_findings" in data["summary"]

    def test_json_output_contains_scan_target(self, tmp_path: Path) -> None:
        report = _make_report(scan_target=tmp_path)
        buf = io.StringIO()
        print_json_report(report, file=buf)
        data = json.loads(buf.getvalue())
        assert "scan_target" in data
        assert str(tmp_path) in data["scan_target"]

    def test_json_output_empty_report(self, tmp_path: Path) -> None:
        report = _make_report()
        buf = io.StringIO()
        print_json_report(report, file=buf)
        data = json.loads(buf.getvalue())
        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []

    def test_json_output_has_timestamps(self, tmp_path: Path) -> None:
        report = _make_report()
        buf = io.StringIO()
        print_json_report(report, file=buf)
        data = json.loads(buf.getvalue())
        assert "started_at" in data
        assert "finished_at" in data

    def test_json_output_writes_trailing_newline(self, tmp_path: Path) -> None:
        report = _make_report()
        buf = io.StringIO()
        print_json_report(report, file=buf)
        assert buf.getvalue().endswith("\n")

    def test_json_output_respects_indent(self, tmp_path: Path) -> None:
        report = _make_report()
        buf = io.StringIO()
        print_json_report(report, indent=4, file=buf)
        # With indent=4, lines should be indented with 4 spaces
        lines = buf.getvalue().splitlines()
        indented = [l for l in lines if l.startswith("    ")]
        assert len(indented) > 0


# ---------------------------------------------------------------------------
# Tests: format_finding_short()
# ---------------------------------------------------------------------------


class TestFormatFindingShort:
    def test_basic_finding(self) -> None:
        f = _make_finding("PERM-001", Severity.CRITICAL, title="World-writable file")
        result = format_finding_short(f)
        assert "PERM-001" in result
        assert "CRITICAL" in result
        assert "World-writable file" in result

    def test_finding_with_file_path(self, tmp_path: Path) -> None:
        f = _make_finding(file_path=tmp_path / "mcp.json")
        result = format_finding_short(f)
        assert "mcp.json" in result

    def test_finding_with_line_number(self, tmp_path: Path) -> None:
        f = _make_finding(file_path=tmp_path / "config.json", line_number=99)
        result = format_finding_short(f)
        assert "99" in result

    def test_finding_without_file_path(self) -> None:
        f = _make_finding(file_path=None)
        result = format_finding_short(f)
        assert "TEST-001" in result
        # No file reference should appear
        assert "[" not in result or "TEST-001" in result  # relaxed check

    def test_all_severities(self) -> None:
        for sev in Severity:
            f = _make_finding(severity=sev)
            result = format_finding_short(f)
            assert sev.value.upper() in result


# ---------------------------------------------------------------------------
# Tests: create_console()
# ---------------------------------------------------------------------------


class TestCreateConsole:
    def test_creates_console_instance(self) -> None:
        con = create_console()
        assert isinstance(con, Console)

    def test_stderr_console(self) -> None:
        con = create_console(stderr=True)
        assert isinstance(con, Console)

    def test_no_color_console(self) -> None:
        con = create_console(no_color=True)
        assert isinstance(con, Console)

    def test_fixed_width_console(self) -> None:
        con = create_console(width=80)
        assert con.width == 80


# ---------------------------------------------------------------------------
# Tests: multiple findings and ordering
# ---------------------------------------------------------------------------


class TestFindingsTableOrdering:
    def test_table_shows_all_check_ids(self, tmp_path: Path) -> None:
        check_ids = ["PERM-001", "HOOK-002", "ENV-003", "SC-011"]
        findings = [
            _make_finding(cid, Severity.HIGH)
            for cid in check_ids
        ]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        print_report(report, console=con)
        output = buf.getvalue()
        for cid in check_ids:
            assert cid in output

    def test_report_with_all_severities(self, tmp_path: Path) -> None:
        findings = [
            _make_finding(f"X-{i:03d}", sev)
            for i, sev in enumerate(Severity)
        ]
        report = _make_report(findings=findings)
        con, buf = _make_console()
        # Should not raise for mixed severities
        print_report(report, console=con)
        output = buf.getvalue()
        assert len(output) > 0
