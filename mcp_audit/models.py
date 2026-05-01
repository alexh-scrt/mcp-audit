"""Core data models for mcp_audit findings and reports.

This module defines the dataclasses used throughout the mcp_audit package
to represent security findings, severity levels, and aggregated audit reports.
All checker modules produce findings using these models, and the reporter
consumes them to generate terminal output or JSON exports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity levels for security findings.

    Ordered from most to least severe. The string values are used
    directly in JSON output and terminal display.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_order(self) -> int:
        """Return a numeric sort order where lower numbers are more severe."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order[self]

    @property
    def rich_color(self) -> str:
        """Return the Rich markup color string for this severity level."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
        }
        return colors[self]

    @property
    def emoji(self) -> str:
        """Return an emoji indicator for this severity level."""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "ℹ️ ",
        }
        return emojis[self]


@dataclass
class Finding:
    """Represents a single security finding discovered during an audit.

    Attributes:
        check_id: A unique identifier for the check that produced this finding
            (e.g., "PERM-001", "HOOK-002").
        severity: The severity level of this finding.
        title: A short, descriptive title for the finding.
        description: A detailed description of what was found and why it is
            a security concern.
        file_path: The path to the file or directory where the finding was
            detected. May be None for findings not tied to a specific file.
        line_number: The line number within the file where the issue was
            detected, if applicable.
        evidence: The raw snippet or value that triggered the finding, if
            available. Useful for quick triage.
        remediation: Suggested steps to fix or mitigate the finding.
        extra: A dictionary for any additional metadata specific to the check.
    """

    check_id: str
    severity: Severity
    title: str
    description: str
    file_path: Path | None = None
    line_number: int | None = None
    evidence: str | None = None
    remediation: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this finding to a JSON-compatible dictionary.

        Returns:
            A dictionary representation of this finding with all fields
            serialized to JSON-compatible types.
        """
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": str(self.file_path) if self.file_path is not None else None,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize a finding from a dictionary.

        Args:
            data: A dictionary as produced by ``to_dict()``.

        Returns:
            A new Finding instance populated from the dictionary.

        Raises:
            KeyError: If required fields are missing from the dictionary.
            ValueError: If the severity value is not a valid Severity enum member.
        """
        return cls(
            check_id=data["check_id"],
            severity=Severity(data["severity"]),
            title=data["title"],
            description=data["description"],
            file_path=Path(data["file_path"]) if data.get("file_path") else None,
            line_number=data.get("line_number"),
            evidence=data.get("evidence"),
            remediation=data.get("remediation"),
            extra=data.get("extra", {}),
        )

    def __str__(self) -> str:
        """Return a human-readable string representation of this finding."""
        parts = [f"[{self.check_id}] {self.severity.value.upper()}: {self.title}"]
        if self.file_path:
            location = str(self.file_path)
            if self.line_number is not None:
                location += f":{self.line_number}"
            parts.append(f"  File: {location}")
        parts.append(f"  {self.description}")
        if self.evidence:
            parts.append(f"  Evidence: {self.evidence}")
        if self.remediation:
            parts.append(f"  Remediation: {self.remediation}")
        return "\n".join(parts)


@dataclass
class AuditReport:
    """Aggregated report produced by a complete audit run.

    Attributes:
        scan_target: The path that was scanned.
        started_at: UTC timestamp when the scan began.
        finished_at: UTC timestamp when the scan completed. None if the scan
            has not yet finished.
        findings: List of all findings discovered during the scan.
        scanned_files: List of all files that were examined.
        errors: List of error messages encountered during scanning (e.g.,
            permission errors reading files).
    """

    scan_target: Path
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Append a finding to this report.

        Args:
            finding: The Finding instance to add.
        """
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        """Append multiple findings to this report.

        Args:
            findings: A list of Finding instances to add.
        """
        self.findings.extend(findings)

    def add_error(self, error: str) -> None:
        """Record a non-fatal error encountered during scanning.

        Args:
            error: A descriptive error message string.
        """
        self.errors.append(error)

    def mark_finished(self) -> None:
        """Record the current UTC time as the scan completion time."""
        self.finished_at = datetime.now(timezone.utc)

    @property
    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Return the number of CRITICAL severity findings."""
        return self._count_by_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return the number of HIGH severity findings."""
        return self._count_by_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Return the number of MEDIUM severity findings."""
        return self._count_by_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Return the number of LOW severity findings."""
        return self._count_by_severity(Severity.LOW)

    @property
    def info_count(self) -> int:
        """Return the number of INFO severity findings."""
        return self._count_by_severity(Severity.INFO)

    def _count_by_severity(self, severity: Severity) -> int:
        """Count findings matching a specific severity level.

        Args:
            severity: The Severity level to count.

        Returns:
            The number of findings with the specified severity.
        """
        return sum(1 for f in self.findings if f.severity == severity)

    def findings_by_severity(self) -> list[Finding]:
        """Return findings sorted by severity (most severe first).

        Returns:
            A new list of findings sorted so that CRITICAL findings come
            first and INFO findings come last.
        """
        return sorted(self.findings, key=lambda f: f.severity.sort_order)

    def has_critical_or_high(self) -> bool:
        """Return True if any findings are CRITICAL or HIGH severity.

        This is useful for CI/CD integration where the pipeline should
        fail on high-severity issues.

        Returns:
            True if at least one CRITICAL or HIGH finding exists.
        """
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    @property
    def duration_seconds(self) -> float | None:
        """Return the scan duration in seconds, or None if not finished."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Serialize this report to a JSON-compatible dictionary.

        Returns:
            A dictionary with all report data serialized to JSON-compatible
            types, suitable for use with ``json.dumps()``.
        """
        return {
            "scan_target": str(self.scan_target),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total_findings": self.finding_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "scanned_files": len(self.scanned_files),
                "errors": len(self.errors),
            },
            "findings": [f.to_dict() for f in self.findings_by_severity()],
            "scanned_files": [str(p) for p in self.scanned_files],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize this report to a formatted JSON string.

        Args:
            indent: Number of spaces for JSON indentation. Defaults to 2.

        Returns:
            A formatted JSON string representation of this report.
        """
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditReport:
        """Deserialize an AuditReport from a dictionary.

        Args:
            data: A dictionary as produced by ``to_dict()``.

        Returns:
            A new AuditReport instance populated from the dictionary.

        Raises:
            KeyError: If required fields are missing.
            ValueError: If datetime strings cannot be parsed.
        """
        report = cls(
            scan_target=Path(data["scan_target"]),
            started_at=datetime.fromisoformat(data["started_at"]),
        )
        if data.get("finished_at"):
            report.finished_at = datetime.fromisoformat(data["finished_at"])
        report.findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        report.scanned_files = [Path(p) for p in data.get("scanned_files", [])]
        report.errors = data.get("errors", [])
        return report

    def __str__(self) -> str:
        """Return a concise human-readable summary of this report."""
        status = "PASS" if self.finding_count == 0 else "FAIL"
        return (
            f"AuditReport [{status}] target={self.scan_target} "
            f"findings={self.finding_count} "
            f"(critical={self.critical_count}, high={self.high_count}, "
            f"medium={self.medium_count}, low={self.low_count}, info={self.info_count})"
        )
