"""Unit tests for the mcp_audit supply chain risk checker.

Tests cover:
- SC-001: Unversioned npm package dependency
- SC-002: Unversioned pip/Python package dependency
- SC-003: Overly broad version range (npm and pip)
- SC-004: Missing dependency lockfile
- SC-005: Non-standard npm registry
- SC-006: Non-standard pip index URL
- SC-007: Missing integrity hashes in lockfile
- SC-008: Package referenced via git URL
- SC-009: Package referenced via local path
- SC-010: Typosquatted package name detection
- SC-011: npx with unversioned/latest package in MCP config
- SC-012: uvx/pipx with unversioned package in MCP config
- check_file() dispatch for package.json, requirements.txt, .npmrc, pip.conf, pyproject.toml, MCP JSON config
- check_files() with multiple paths
- check_directory() scanning manifest files in a directory
- Missing lockfile detection
- Benign configurations that should NOT trigger findings
- Deduplication of findings
- Finding structure and serialization
- Parsing utilities (_parse_pip_requirement, _split_npm_package_spec)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_audit.checks.supply_chain import (
    _deduplicate_findings,
    _is_git_url,
    _is_local_path,
    _is_npm_version_broad,
    _is_pip_version_broad,
    _parse_pip_requirement,
    _split_npm_package_spec,
    check_directory,
    check_file,
    check_files,
)
from mcp_audit.models import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> Path:
    """Write text content to a file, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_json(path: Path, data: Any) -> Path:
    """Serialize data as JSON and write to path."""
    return _write(path, json.dumps(data, indent=2))


def _check_ids(findings: list[Finding]) -> set[str]:
    """Extract all check IDs from a list of findings."""
    return {f.check_id for f in findings}


def _findings_for(check_id: str, findings: list[Finding]) -> list[Finding]:
    """Filter findings by check ID."""
    return [f for f in findings if f.check_id == check_id]


def _make_package_json(
    path: Path,
    dependencies: dict[str, str] | None = None,
    dev_dependencies: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Write a package.json file with given dependency specs."""
    data: dict[str, Any] = {"name": "test-package", "version": "1.0.0"}
    if dependencies is not None:
        data["dependencies"] = dependencies
    if dev_dependencies is not None:
        data["devDependencies"] = dev_dependencies
    if extra:
        data.update(extra)
    return _write_json(path, data)


def _make_mcp_config(
    path: Path,
    servers: dict[str, Any] | None = None,
) -> Path:
    """Write a minimal MCP JSON config."""
    data: dict[str, Any] = {"mcpServers": servers or {}}
    return _write_json(path, data)


def _make_requirements_txt(path: Path, lines: list[str]) -> Path:
    """Write a requirements.txt file with given dependency lines."""
    return _write(path, "\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Tests: check_file() edge cases
# ---------------------------------------------------------------------------


class TestCheckFileEdgeCases:
    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = check_file(tmp_path / "nonexistent.json")
        assert result == []

    def test_directory_path_returns_empty(self, tmp_path: Path) -> None:
        result = check_file(tmp_path)
        assert result == []

    def test_empty_file_returns_list(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "package.json", "")
        result = check_file(p)
        assert isinstance(result, list)

    def test_malformed_json_no_exception(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "package.json", "{ this is not valid json !!")
        result = check_file(p)
        assert isinstance(result, list)

    def test_returns_list_of_findings(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        result = check_file(p)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, Finding)

    def test_unknown_extension_returns_empty(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "random.xyz", "content")
        result = check_file(p)
        assert result == []

    def test_valid_package_json_no_deps_no_findings(self, tmp_path: Path) -> None:
        p = _make_package_json(tmp_path / "package.json")
        result = check_file(p)
        # May get SC-004 (missing lockfile) but no SC-001/SC-003 findings
        ids = _check_ids(result)
        assert "SC-001" not in ids
        assert "SC-003" not in ids


# ---------------------------------------------------------------------------
# Tests: SC-001 - Unversioned npm package dependency
# ---------------------------------------------------------------------------


class TestSc001UnversionedNpm:
    def test_empty_string_version_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-package": ""},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-001" in ids

    def test_sc001_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-package": ""},
        )
        findings = check_file(p)
        sc001 = _findings_for("SC-001", findings)
        assert len(sc001) >= 1
        assert sc001[0].severity == Severity.HIGH

    def test_sc001_has_package_name_in_evidence(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-unique-package": ""},
        )
        findings = check_file(p)
        sc001 = _findings_for("SC-001", findings)
        assert len(sc001) >= 1
        assert "my-unique-package" in (sc001[0].evidence or sc001[0].title or sc001[0].description)

    def test_sc001_has_remediation(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-package": ""},
        )
        findings = check_file(p)
        sc001 = _findings_for("SC-001", findings)
        assert len(sc001) >= 1
        assert sc001[0].remediation is not None and len(sc001[0].remediation) > 0

    def test_sc001_has_file_path(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"pkg": ""},
        )
        findings = check_file(p)
        sc001 = _findings_for("SC-001", findings)
        assert len(sc001) >= 1
        assert sc001[0].file_path == p

    def test_pinned_version_no_sc001(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-001" not in ids

    def test_caret_version_no_sc001(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"express": "^4.18.0"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-001" not in ids

    def test_multiple_unversioned_packages(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"pkg-a": "", "pkg-b": ""},
        )
        findings = check_file(p)
        sc001 = _findings_for("SC-001", findings)
        assert len(sc001) >= 2

    def test_dev_dependency_unversioned_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dev_dependencies={"jest": ""},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        # Empty version in devDependencies is caught as SC-001 or SC-003
        assert ids & {"SC-001", "SC-003"}


# ---------------------------------------------------------------------------
# Tests: SC-002 - Unversioned pip package dependency
# ---------------------------------------------------------------------------


class TestSc002UnversionedPip:
    def test_bare_package_name_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-002" in ids

    def test_sc002_severity_is_medium(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["flask"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) >= 1
        assert sc002[0].severity == Severity.MEDIUM

    def test_sc002_has_package_name_in_description(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["my-unique-lib"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) >= 1
        assert "my-unique-lib" in sc002[0].description

    def test_sc002_has_remediation(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) >= 1
        assert sc002[0].remediation is not None and len(sc002[0].remediation) > 0

    def test_sc002_has_file_path(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) >= 1
        assert sc002[0].file_path == p

    def test_sc002_has_line_number(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["# comment", "requests"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) >= 1
        assert sc002[0].line_number == 2

    def test_pinned_version_no_sc002(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests==2.28.0"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-002" not in ids

    def test_versioned_range_no_sc002(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests>=2.28.0,<3.0"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-002" not in ids

    def test_comment_lines_skipped(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["# requests", "# flask"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-002" not in ids

    def test_multiple_unversioned_packages(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests", "flask", "django"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) >= 3

    def test_package_with_extras_no_version_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests[security]"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-002" in ids

    def test_package_with_extras_pinned_no_sc002(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests[security]==2.28.0"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-002" not in ids

    def test_empty_requirements_txt_no_findings(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(tmp_path / "requirements.txt", [])
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) == 0

    def test_requirements_with_only_comments_no_findings(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["# This is a comment", "# Another comment"],
        )
        findings = check_file(p)
        sc002 = _findings_for("SC-002", findings)
        assert len(sc002) == 0


# ---------------------------------------------------------------------------
# Tests: SC-003 - Overly broad version range
# ---------------------------------------------------------------------------


class TestSc003BroadVersionRange:
    def test_npm_wildcard_version_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "*"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_npm_latest_tag_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"express": "latest"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_npm_next_tag_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"react": "next"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_npm_beta_tag_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-lib": "beta"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_npm_gte_zero_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"some-lib": ">=0.0.0"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_npm_sc003_severity_is_medium(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        sc003 = _findings_for("SC-003", findings)
        assert len(sc003) >= 1
        assert sc003[0].severity == Severity.MEDIUM

    def test_npm_sc003_has_package_name_in_title(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-special-pkg": "*"},
        )
        findings = check_file(p)
        sc003 = _findings_for("SC-003", findings)
        assert len(sc003) >= 1
        assert "my-special-pkg" in sc003[0].title

    def test_npm_sc003_has_evidence(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        sc003 = _findings_for("SC-003", findings)
        assert len(sc003) >= 1
        assert sc003[0].evidence is not None

    def test_npm_exact_version_no_sc003(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" not in ids

    def test_npm_caret_semver_no_sc003(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"express": "^4.18.0"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" not in ids

    def test_npm_tilde_semver_no_sc003(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"express": "~4.18.0"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" not in ids

    def test_pip_gte_zero_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests>=0.0.0"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_pip_sc003_severity_is_low(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests>=0.0.0"],
        )
        findings = check_file(p)
        sc003 = _findings_for("SC-003", findings)
        assert len(sc003) >= 1
        assert sc003[0].severity == Severity.LOW

    def test_pip_pinned_version_no_sc003(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests==2.28.0"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" not in ids


# ---------------------------------------------------------------------------
# Tests: SC-004 - Missing dependency lockfile
# ---------------------------------------------------------------------------


class TestSc004MissingLockfile:
    def test_missing_lockfile_detected_with_package_json(self, tmp_path: Path) -> None:
        _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        # No lockfile in tmp_path
        findings = check_file(tmp_path / "package.json")
        ids = _check_ids(findings)
        assert "SC-004" in ids

    def test_sc004_severity_is_medium(self, tmp_path: Path) -> None:
        _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        findings = check_file(tmp_path / "package.json")
        sc004 = _findings_for("SC-004", findings)
        assert len(sc004) >= 1
        assert sc004[0].severity == Severity.MEDIUM

    def test_sc004_has_remediation(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        findings = check_file(tmp_path / "package.json")
        sc004 = _findings_for("SC-004", findings)
        assert len(sc004) >= 1
        assert sc004[0].remediation is not None and len(sc004[0].remediation) > 0

    def test_lockfile_present_no_sc004(self, tmp_path: Path) -> None:
        _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        # Create a lockfile
        _write(tmp_path / "package-lock.json", json.dumps({"lockfileVersion": 2}))
        findings = check_file(tmp_path / "package.json")
        ids = _check_ids(findings)
        assert "SC-004" not in ids

    def test_yarn_lock_present_no_sc004(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        _write(tmp_path / "yarn.lock", "# yarn lockfile v1\n")
        findings = check_file(tmp_path / "package.json")
        ids = _check_ids(findings)
        assert "SC-004" not in ids

    def test_pnpm_lock_present_no_sc004(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        _write(tmp_path / "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")
        findings = check_file(tmp_path / "package.json")
        ids = _check_ids(findings)
        assert "SC-004" not in ids

    def test_poetry_lock_present_no_sc004_for_requirements(self, tmp_path: Path) -> None:
        """poetry.lock counts as a lockfile for Python projects."""
        _make_requirements_txt(tmp_path / "requirements.txt", ["requests"])
        _write(tmp_path / "poetry.lock", "# Generated by Poetry\n")
        # We check missing lockfile when calling check_file on package.json
        # For requirements.txt, the lockfile check is directory-based
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-004" not in ids

    def test_no_manifest_no_sc004(self, tmp_path: Path) -> None:
        """A directory without any manifest file should not trigger SC-004."""
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-004" not in ids

    def test_sc004_evidence_mentions_directory(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        findings = check_file(tmp_path / "package.json")
        sc004 = _findings_for("SC-004", findings)
        assert len(sc004) >= 1
        assert sc004[0].evidence is not None


# ---------------------------------------------------------------------------
# Tests: SC-005 - Non-standard npm registry
# ---------------------------------------------------------------------------


class TestSc005NonStandardNpmRegistry:
    def test_npmrc_with_private_registry_detected(self, tmp_path: Path) -> None:
        content = "registry=https://my-private-registry.example.com/\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" in ids

    def test_sc005_severity_is_high(self, tmp_path: Path) -> None:
        content = "registry=https://private.registry.example.com/\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        sc005 = _findings_for("SC-005", findings)
        assert len(sc005) >= 1
        assert sc005[0].severity == Severity.HIGH

    def test_sc005_has_registry_url_in_evidence(self, tmp_path: Path) -> None:
        url = "https://my.custom.registry.example.com/"
        content = f"registry={url}\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        sc005 = _findings_for("SC-005", findings)
        assert len(sc005) >= 1
        assert "my.custom.registry.example.com" in (sc005[0].evidence or "")

    def test_sc005_has_remediation(self, tmp_path: Path) -> None:
        content = "registry=https://private.registry.example.com/\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        sc005 = _findings_for("SC-005", findings)
        assert len(sc005) >= 1
        assert sc005[0].remediation is not None and len(sc005[0].remediation) > 0

    def test_npmrc_official_registry_no_sc005(self, tmp_path: Path) -> None:
        content = "registry=https://registry.npmjs.org\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" not in ids

    def test_npmrc_official_registry_with_slash_no_sc005(self, tmp_path: Path) -> None:
        content = "registry=https://registry.npmjs.org/\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" not in ids

    def test_npmrc_scoped_registry_detected(self, tmp_path: Path) -> None:
        content = "@myorg:registry=https://npm.pkg.github.com\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" in ids

    def test_package_json_publish_config_private_registry(self, tmp_path: Path) -> None:
        data = {
            "name": "my-pkg",
            "publishConfig": {
                "registry": "https://private.registry.example.com/"
            }
        }
        p = _write_json(tmp_path / "package.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" in ids

    def test_package_json_publish_config_official_registry_no_sc005(self, tmp_path: Path) -> None:
        data = {
            "name": "my-pkg",
            "publishConfig": {
                "registry": "https://registry.npmjs.org/"
            }
        }
        p = _write_json(tmp_path / "package.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" not in ids

    def test_npmrc_comment_lines_skipped(self, tmp_path: Path) -> None:
        content = "; registry=https://evil.registry.example.com\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-005" not in ids

    def test_sc005_has_file_path(self, tmp_path: Path) -> None:
        content = "registry=https://private.registry.example.com/\n"
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        sc005 = _findings_for("SC-005", findings)
        assert len(sc005) >= 1
        assert sc005[0].file_path == p


# ---------------------------------------------------------------------------
# Tests: SC-006 - Non-standard pip index URL
# ---------------------------------------------------------------------------


class TestSc006NonStandardPipIndex:
    def test_requirements_txt_custom_index_detected(self, tmp_path: Path) -> None:
        content = "--index-url https://my-private-pypi.example.com/simple\nrequests==2.28.0\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" in ids

    def test_requirements_txt_extra_index_url_detected(self, tmp_path: Path) -> None:
        content = "--extra-index-url https://my.custom.pypi.example.com/simple\nflask==2.0\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" in ids

    def test_sc006_severity_is_high(self, tmp_path: Path) -> None:
        content = "--index-url https://evil-pypi.example.com/simple\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        sc006 = _findings_for("SC-006", findings)
        assert len(sc006) >= 1
        assert sc006[0].severity == Severity.HIGH

    def test_sc006_has_url_in_evidence(self, tmp_path: Path) -> None:
        url = "https://custom.pypi.example.com/simple"
        content = f"--index-url {url}\nrequests==2.28.0\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        sc006 = _findings_for("SC-006", findings)
        assert len(sc006) >= 1
        assert "custom.pypi.example.com" in (sc006[0].evidence or "")

    def test_sc006_has_remediation(self, tmp_path: Path) -> None:
        content = "--index-url https://evil.example.com/simple\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        sc006 = _findings_for("SC-006", findings)
        assert len(sc006) >= 1
        assert sc006[0].remediation is not None and len(sc006[0].remediation) > 0

    def test_official_pypi_index_no_sc006(self, tmp_path: Path) -> None:
        content = "--index-url https://pypi.org/simple\nrequests==2.28.0\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" not in ids

    def test_official_pypi_index_with_slash_no_sc006(self, tmp_path: Path) -> None:
        content = "--index-url https://pypi.org/simple/\nrequests==2.28.0\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" not in ids

    def test_pip_conf_custom_index_detected(self, tmp_path: Path) -> None:
        content = "[global]\nindex-url = https://my-private-pypi.example.com/simple\n"
        p = _write(tmp_path / "pip.conf", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" in ids

    def test_pip_conf_official_index_no_sc006(self, tmp_path: Path) -> None:
        content = "[global]\nindex-url = https://pypi.org/simple\n"
        p = _write(tmp_path / "pip.conf", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" not in ids

    def test_pip_ini_custom_index_detected(self, tmp_path: Path) -> None:
        content = "[global]\nindex-url = https://my.custom.pypi.example.com/simple\n"
        p = _write(tmp_path / "pip.ini", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" in ids

    def test_sc006_has_file_path(self, tmp_path: Path) -> None:
        content = "--index-url https://evil.example.com/simple\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        sc006 = _findings_for("SC-006", findings)
        assert len(sc006) >= 1
        assert sc006[0].file_path == p

    def test_sc006_has_line_number(self, tmp_path: Path) -> None:
        content = "# comment\n--index-url https://evil.example.com/simple\nrequests==2.28.0\n"
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        sc006 = _findings_for("SC-006", findings)
        assert len(sc006) >= 1
        assert sc006[0].line_number == 2


# ---------------------------------------------------------------------------
# Tests: SC-007 - Missing integrity hashes in lockfile
# ---------------------------------------------------------------------------


class TestSc007MissingIntegrity:
    def test_package_lock_missing_integrity_detected(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "name": "test",
            "packages": {
                "": {"name": "test"},  # root package
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    # Missing 'integrity' field
                },
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-007" in ids

    def test_sc007_severity_is_high(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                },
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        sc007 = _findings_for("SC-007", findings)
        assert len(sc007) >= 1
        assert sc007[0].severity == Severity.HIGH

    def test_sc007_has_evidence_with_package_names(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                },
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        sc007 = _findings_for("SC-007", findings)
        assert len(sc007) >= 1
        assert "lodash" in (sc007[0].evidence or "")

    def test_sc007_has_remediation(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        sc007 = _findings_for("SC-007", findings)
        assert len(sc007) >= 1
        assert sc007[0].remediation is not None and len(sc007[0].remediation) > 0

    def test_package_lock_with_integrity_no_sc007(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZkFekkObUFyGjFnoDCA==",
                },
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-007" not in ids

    def test_root_package_skipped_in_integrity_check(self, tmp_path: Path) -> None:
        """The root package (empty string key) should not be checked for integrity."""
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "my-project", "version": "1.0.0"},  # root, no integrity needed
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-007" not in ids

    def test_multiple_packages_missing_integrity(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/react": {"version": "18.0.0"},
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        sc007 = _findings_for("SC-007", findings)
        assert len(sc007) == 1  # One aggregated finding for all missing
        assert sc007[0].extra.get("missing_count") == 3

    def test_sc007_extra_contains_missing_count(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/pkg-a": {"version": "1.0.0"},
                "node_modules/pkg-b": {"version": "2.0.0"},
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        sc007 = _findings_for("SC-007", findings)
        assert len(sc007) >= 1
        assert "missing_count" in sc007[0].extra
        assert sc007[0].extra["missing_count"] == 2

    def test_bundled_packages_skipped_in_integrity_check(self, tmp_path: Path) -> None:
        lockdata = {
            "lockfileVersion": 2,
            "packages": {
                "": {},
                "node_modules/bundled-pkg": {
                    "version": "1.0.0",
                    "bundled": True,
                    # No integrity needed for bundled packages
                },
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-007" not in ids


# ---------------------------------------------------------------------------
# Tests: SC-008 - Package referenced via git URL
# ---------------------------------------------------------------------------


class TestSc008GitUrlReference:
    def test_npm_git_plus_https_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "git+https://github.com/user/repo.git"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_npm_github_shorthand_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "github:user/repo#main"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_npm_user_repo_shorthand_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "user/repo#feature-branch"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_npm_gitlab_reference_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "gitlab:user/repo"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_sc008_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "git+https://github.com/user/repo.git"},
        )
        findings = check_file(p)
        sc008 = _findings_for("SC-008", findings)
        assert len(sc008) >= 1
        assert sc008[0].severity == Severity.HIGH

    def test_sc008_has_remediation(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "git+https://github.com/user/repo.git"},
        )
        findings = check_file(p)
        sc008 = _findings_for("SC-008", findings)
        assert len(sc008) >= 1
        assert sc008[0].remediation is not None and len(sc008[0].remediation) > 0

    def test_pip_git_url_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["git+https://github.com/user/my-lib.git"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_pip_git_url_with_egg_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["git+https://github.com/user/my-lib.git#egg=my-lib"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_regular_version_no_sc008(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" not in ids

    def test_sc008_has_file_path(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "git+https://github.com/user/repo.git"},
        )
        findings = check_file(p)
        sc008 = _findings_for("SC-008", findings)
        assert len(sc008) >= 1
        assert sc008[0].file_path == p

    def test_mcp_config_npx_git_url_detected(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["user/my-mcp-pkg#main"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids


# ---------------------------------------------------------------------------
# Tests: SC-009 - Package referenced via local path
# ---------------------------------------------------------------------------


class TestSc009LocalPath:
    def test_npm_file_protocol_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-local-pkg": "file:../my-local-pkg"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" in ids

    def test_npm_relative_path_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-local-pkg": "./packages/my-local-pkg"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" in ids

    def test_npm_parent_relative_path_detected(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-local-pkg": "../sibling-package"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" in ids

    def test_sc009_severity_is_medium(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-local-pkg": "file:../local"},
        )
        findings = check_file(p)
        sc009 = _findings_for("SC-009", findings)
        assert len(sc009) >= 1
        assert sc009[0].severity == Severity.MEDIUM

    def test_sc009_has_remediation(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-local-pkg": "file:../local"},
        )
        findings = check_file(p)
        sc009 = _findings_for("SC-009", findings)
        assert len(sc009) >= 1
        assert sc009[0].remediation is not None and len(sc009[0].remediation) > 0

    def test_pip_local_path_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["./my-local-lib"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" in ids

    def test_pip_absolute_path_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["/usr/local/src/my-lib"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" in ids

    def test_pip_file_protocol_detected(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["file:///home/user/my-lib"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" in ids

    def test_regular_package_no_sc009(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-009" not in ids

    def test_sc009_has_file_path(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-pkg": "file:../local"},
        )
        findings = check_file(p)
        sc009 = _findings_for("SC-009", findings)
        assert len(sc009) >= 1
        assert sc009[0].file_path == p


# ---------------------------------------------------------------------------
# Tests: SC-010 - Typosquatted package name
# ---------------------------------------------------------------------------


class TestSc010Typosquatting:
    def test_l0dash_detected_as_lodash_typosquat(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"l0dash": "4.17.21"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-010" in ids

    def test_sc010_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"l0dash": "4.17.21"},
        )
        findings = check_file(p)
        sc010 = _findings_for("SC-010", findings)
        assert len(sc010) >= 1
        assert sc010[0].severity == Severity.HIGH

    def test_sc010_mentions_legitimate_package(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"l0dash": "4.17.21"},
        )
        findings = check_file(p)
        sc010 = _findings_for("SC-010", findings)
        assert len(sc010) >= 1
        assert "lodash" in sc010[0].description

    def test_sc010_has_remediation(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"l0dash": "4.17.21"},
        )
        findings = check_file(p)
        sc010 = _findings_for("SC-010", findings)
        assert len(sc010) >= 1
        assert sc010[0].remediation is not None and len(sc010[0].remediation) > 0

    def test_exact_legitimate_package_no_sc010(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "4.17.21"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-010" not in ids

    def test_scoped_package_not_typosquatted(self, tmp_path: Path) -> None:
        """Scoped packages like @scope/name are not checked for typosquatting."""
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"@scope/l0dash": "1.0.0"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-010" not in ids

    def test_numy_detected_as_numpy_typosquat_in_pip(self, tmp_path: Path) -> None:
        """Pip-style typosquatting detection."""
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["numy==1.0"],
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-010" in ids

    def test_sc010_extra_contains_suspected_and_legitimate(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"l0dash": "4.17.21"},
        )
        findings = check_file(p)
        sc010 = _findings_for("SC-010", findings)
        assert len(sc010) >= 1
        extra = sc010[0].extra
        assert "suspected_typosquat" in extra
        assert "legitimate_package" in extra
        assert extra["legitimate_package"] == "lodash"

    def test_unrelated_package_no_sc010(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"my-completely-unique-package-xyz": "1.0.0"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-010" not in ids


# ---------------------------------------------------------------------------
# Tests: SC-011 - npx with unversioned/latest package in MCP config
# ---------------------------------------------------------------------------


class TestSc011NpxUnversioned:
    def test_npx_unversioned_package_detected(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "filesystem": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" in ids

    def test_npx_latest_tag_detected(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem@latest"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" in ids

    def test_npx_latest_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["my-mcp-server@latest"],
            }
        })
        findings = check_file(p)
        sc011 = _findings_for("SC-011", findings)
        assert len(sc011) >= 1
        assert sc011[0].severity == Severity.HIGH

    def test_npx_unversioned_severity_is_medium(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["my-mcp-server"],  # no version at all
            }
        })
        findings = check_file(p)
        sc011 = _findings_for("SC-011", findings)
        assert len(sc011) >= 1
        assert sc011[0].severity == Severity.MEDIUM

    def test_npx_pinned_version_no_sc011(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" not in ids

    def test_npx_caret_version_no_sc011(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["my-pkg@^1.2.3"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" not in ids

    def test_sc011_has_package_name_in_evidence(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["my-mcp-server"],
            }
        })
        findings = check_file(p)
        sc011 = _findings_for("SC-011", findings)
        assert len(sc011) >= 1
        assert "my-mcp-server" in (sc011[0].evidence or "")

    def test_sc011_has_remediation(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["my-mcp-server"],
            }
        })
        findings = check_file(p)
        sc011 = _findings_for("SC-011", findings)
        assert len(sc011) >= 1
        assert sc011[0].remediation is not None and len(sc011[0].remediation) > 0

    def test_sc011_has_extra_with_package_name(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["my-mcp-server"],
            }
        })
        findings = check_file(p)
        sc011 = _findings_for("SC-011", findings)
        assert len(sc011) >= 1
        assert "package" in sc011[0].extra
        assert sc011[0].extra["package"] == "my-mcp-server"

    def test_npx_cmd_exe_also_checked(self, tmp_path: Path) -> None:
        """npx.cmd (Windows) should also be detected."""
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx.cmd",
                "args": ["my-mcp-server"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" in ids

    def test_multiple_npx_servers_all_checked(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server1": {
                "command": "npx",
                "args": ["pkg-a"],  # unversioned
            },
            "server2": {
                "command": "npx",
                "args": ["pkg-b@latest"],  # latest
            },
        })
        findings = check_file(p)
        sc011 = _findings_for("SC-011", findings)
        assert len(sc011) >= 2

    def test_npx_with_y_flag_no_false_negative(self, tmp_path: Path) -> None:
        """The -y flag before package name should not cause false negatives."""
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["-y", "my-unversioned-pkg"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" in ids

    def test_npx_git_url_arg_triggers_sc008(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "npx",
                "args": ["user/my-mcp-pkg#main"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_non_npx_command_no_sc011(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "node",
                "args": ["server.js"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" not in ids


# ---------------------------------------------------------------------------
# Tests: SC-012 - uvx/pipx with unversioned package in MCP config
# ---------------------------------------------------------------------------


class TestSc012UvxPipxUnversioned:
    def test_uvx_unversioned_package_detected(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git"],  # no version
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-012" in ids

    def test_pipx_unversioned_package_detected(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "pipx",
                "args": ["mcp-server-fetch"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-012" in ids

    def test_sc012_severity_is_medium(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git"],
            }
        })
        findings = check_file(p)
        sc012 = _findings_for("SC-012", findings)
        assert len(sc012) >= 1
        assert sc012[0].severity == Severity.MEDIUM

    def test_uvx_pinned_version_no_sc012(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git==1.0.0"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-012" not in ids

    def test_sc012_has_remediation(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git"],
            }
        })
        findings = check_file(p)
        sc012 = _findings_for("SC-012", findings)
        assert len(sc012) >= 1
        assert sc012[0].remediation is not None and len(sc012[0].remediation) > 0

    def test_sc012_has_evidence(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git"],
            }
        })
        findings = check_file(p)
        sc012 = _findings_for("SC-012", findings)
        assert len(sc012) >= 1
        assert sc012[0].evidence is not None

    def test_sc012_has_extra_with_package(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git"],
            }
        })
        findings = check_file(p)
        sc012 = _findings_for("SC-012", findings)
        assert len(sc012) >= 1
        assert "package" in sc012[0].extra

    def test_uvx_git_url_triggers_sc008(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["git+https://github.com/user/mcp-server.git"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-008" in ids

    def test_node_command_no_sc012(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "node",
                "args": ["server.js"],
            }
        })
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-012" not in ids

    def test_sc012_has_file_path(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git"],
            }
        })
        findings = check_file(p)
        sc012 = _findings_for("SC-012", findings)
        assert len(sc012) >= 1
        assert sc012[0].file_path == p


# ---------------------------------------------------------------------------
# Tests: check_files() with multiple paths
# ---------------------------------------------------------------------------


class TestCheckFiles:
    def test_empty_list_returns_empty(self) -> None:
        result = check_files([])
        assert result == []

    def test_single_file_delegated(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        single = check_file(p)
        multi = check_files([p])
        assert _check_ids(single) == _check_ids(multi)

    def test_multiple_files_aggregated(self, tmp_path: Path) -> None:
        p1 = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        p2 = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_files([p1, p2])
        ids = _check_ids(findings)
        assert "SC-003" in ids  # from package.json
        assert "SC-002" in ids  # from requirements.txt

    def test_nonexistent_files_ignored(self, tmp_path: Path) -> None:
        paths = [tmp_path / "no1.json", tmp_path / "no2.json"]
        result = check_files(paths)
        assert result == []

    def test_mixed_existing_nonexistent(self, tmp_path: Path) -> None:
        p_exists = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        p_missing = tmp_path / "missing.txt"
        findings = check_files([p_exists, p_missing])
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_findings_reference_correct_files(self, tmp_path: Path) -> None:
        p1 = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        p2 = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_files([p1, p2])
        found_paths = {f.file_path for f in findings if f.file_path}
        assert p1 in found_paths
        assert p2 in found_paths


# ---------------------------------------------------------------------------
# Tests: check_directory()
# ---------------------------------------------------------------------------


class TestCheckDirectory:
    def test_nonexistent_directory_returns_empty(self, tmp_path: Path) -> None:
        result = check_directory(tmp_path / "nonexistent")
        assert result == []

    def test_file_path_returns_empty(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "file.txt", "content")
        result = check_directory(p)
        assert result == []

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        result = check_directory(tmp_path)
        assert result == []

    def test_directory_with_package_json_scanned(self, tmp_path: Path) -> None:
        _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-003" in ids

    def test_directory_with_requirements_txt_scanned(self, tmp_path: Path) -> None:
        _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-002" in ids

    def test_directory_with_npmrc_scanned(self, tmp_path: Path) -> None:
        _write(tmp_path / ".npmrc", "registry=https://private.example.com/\n")
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-005" in ids

    def test_directory_missing_lockfile_triggers_sc004(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-004" in ids

    def test_directory_with_lockfile_no_sc004(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        _write(tmp_path / "package-lock.json", json.dumps({"lockfileVersion": 2}))
        findings = check_directory(tmp_path)
        ids = _check_ids(findings)
        assert "SC-004" not in ids

    def test_directory_deduplicates_findings(self, tmp_path: Path) -> None:
        _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_directory(tmp_path)
        # Verify no exact duplicates
        keys = [
            (f.check_id, str(f.file_path), f.line_number, (f.evidence or "")[:100])
            for f in findings
        ]
        assert len(keys) == len(set(keys))

    def test_directory_returns_list_of_findings(self, tmp_path: Path) -> None:
        _make_package_json(tmp_path / "package.json")
        result = check_directory(tmp_path)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, Finding)


# ---------------------------------------------------------------------------
# Tests: Benign configurations - should NOT trigger findings
# ---------------------------------------------------------------------------


class TestBenignConfigs:
    def test_clean_package_json_pinned_versions(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={
                "lodash": "4.17.21",
                "express": "4.18.0",
            },
        )
        # Create a lockfile so SC-004 doesn't fire
        _write(tmp_path / "package-lock.json", json.dumps({"lockfileVersion": 2}))
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id in (
            "SC-001", "SC-003", "SC-004", "SC-005", "SC-007", "SC-008", "SC-009", "SC-010"
        )]
        assert len(sc_findings) == 0

    def test_clean_requirements_txt_pinned(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests==2.28.0", "flask==2.2.0", "django==4.0.0"],
        )
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id in (
            "SC-002", "SC-003", "SC-006", "SC-008", "SC-009"
        )]
        assert len(sc_findings) == 0

    def test_clean_mcp_config_pinned_npx(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
            }
        })
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id in ("SC-011", "SC-008")]
        assert len(sc_findings) == 0

    def test_clean_mcp_config_node_command(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "node",
                "args": ["/usr/local/lib/mcp-server/index.js"],
            }
        })
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id.startswith("SC-")]
        assert len(sc_findings) == 0

    def test_requirements_with_comments_no_extra_findings(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["# Production dependencies", "requests==2.28.0", "# Dev only", "pytest==7.0.0"],
        )
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id in ("SC-002", "SC-003")]
        assert len(sc_findings) == 0

    def test_npmrc_empty_file_no_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path / ".npmrc", "")
        findings = check_file(p)
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_clean_uvx_pinned(self, tmp_path: Path) -> None:
        p = _make_mcp_config(tmp_path / "mcp.json", servers={
            "server": {
                "command": "uvx",
                "args": ["mcp-server-git==1.2.3"],
            }
        })
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id in ("SC-012", "SC-008")]
        assert len(sc_findings) == 0


# ---------------------------------------------------------------------------
# Tests: Parsing utilities
# ---------------------------------------------------------------------------


class TestParsePipRequirement:
    def test_bare_package_name(self) -> None:
        name, version = _parse_pip_requirement("requests")
        assert name == "requests"
        assert version == ""

    def test_pinned_version(self) -> None:
        name, version = _parse_pip_requirement("requests==2.28.0")
        assert name == "requests"
        assert version == "==2.28.0"

    def test_gte_version(self) -> None:
        name, version = _parse_pip_requirement("requests>=2.28.0")
        assert name == "requests"
        assert version == ">=2.28.0"

    def test_range_version(self) -> None:
        name, version = _parse_pip_requirement("requests>=2.28.0,<3.0")
        assert name == "requests"
        assert version == ">=2.28.0,<3.0"

    def test_extras_with_version(self) -> None:
        name, version = _parse_pip_requirement("requests[security]==2.28.0")
        assert name == "requests"
        assert version == "==2.28.0"

    def test_extras_no_version(self) -> None:
        name, version = _parse_pip_requirement("requests[security]")
        assert name == "requests"
        assert version == ""

    def test_git_url(self) -> None:
        spec = "git+https://github.com/user/requests.git"
        name, version = _parse_pip_requirement(spec)
        # For git URLs, name and version will be the URL or egg name
        assert name != "" or version != ""  # Should not return both empty

    def test_git_url_with_egg(self) -> None:
        spec = "git+https://github.com/user/mylib.git#egg=mylib"
        name, version = _parse_pip_requirement(spec)
        assert name == "mylib"

    def test_local_relative_path(self) -> None:
        spec = "./my-local-package"
        name, version = _parse_pip_requirement(spec)
        # Local paths are returned as-is
        assert name != ""

    def test_empty_string_returns_empty(self) -> None:
        name, version = _parse_pip_requirement("")
        assert name == ""
        assert version == ""

    def test_whitespace_only_returns_empty(self) -> None:
        name, version = _parse_pip_requirement("   ")
        assert name == ""
        assert version == ""

    def test_with_environment_marker(self) -> None:
        name, version = _parse_pip_requirement(
            "requests==2.28.0 ; python_version >= '3.6'"
        )
        assert name == "requests"
        assert "==2.28.0" in version

    def test_hyphenated_package_name(self) -> None:
        name, version = _parse_pip_requirement("my-package==1.0.0")
        assert name == "my-package"
        assert version == "==1.0.0"


class TestSplitNpmPackageSpec:
    def test_bare_name(self) -> None:
        name, version = _split_npm_package_spec("lodash")
        assert name == "lodash"
        assert version == ""

    def test_name_at_version(self) -> None:
        name, version = _split_npm_package_spec("lodash@4.17.21")
        assert name == "lodash"
        assert version == "4.17.21"

    def test_scoped_package_no_version(self) -> None:
        name, version = _split_npm_package_spec("@scope/package")
        assert name == "@scope/package"
        assert version == ""

    def test_scoped_package_with_version(self) -> None:
        name, version = _split_npm_package_spec("@scope/package@1.0.0")
        assert name == "@scope/package"
        assert version == "1.0.0"

    def test_scoped_package_at_latest(self) -> None:
        name, version = _split_npm_package_spec("@modelcontextprotocol/server-filesystem@latest")
        assert name == "@modelcontextprotocol/server-filesystem"
        assert version == "latest"

    def test_empty_string_returns_empty(self) -> None:
        name, version = _split_npm_package_spec("")
        assert name == ""
        assert version == ""

    def test_at_sign_only(self) -> None:
        name, version = _split_npm_package_spec("@")
        # Edge case - scoped with nothing after
        assert isinstance(name, str)
        assert isinstance(version, str)


# ---------------------------------------------------------------------------
# Tests: Version specifier helpers
# ---------------------------------------------------------------------------


class TestIsNpmVersionBroad:
    def test_empty_string_is_broad(self) -> None:
        assert _is_npm_version_broad("") is True

    def test_wildcard_is_broad(self) -> None:
        assert _is_npm_version_broad("*") is True

    def test_latest_is_broad(self) -> None:
        assert _is_npm_version_broad("latest") is True

    def test_next_is_broad(self) -> None:
        assert _is_npm_version_broad("next") is True

    def test_beta_is_broad(self) -> None:
        assert _is_npm_version_broad("beta") is True

    def test_alpha_is_broad(self) -> None:
        assert _is_npm_version_broad("alpha") is True

    def test_gte_zero_is_broad(self) -> None:
        assert _is_npm_version_broad(">=0.0.0") is True
        assert _is_npm_version_broad(">=0") is True

    def test_exact_version_not_broad(self) -> None:
        assert _is_npm_version_broad("4.17.21") is False

    def test_caret_semver_not_broad(self) -> None:
        assert _is_npm_version_broad("^4.17.21") is False

    def test_tilde_semver_not_broad(self) -> None:
        assert _is_npm_version_broad("~4.17.0") is False

    def test_gte_specific_not_broad(self) -> None:
        assert _is_npm_version_broad(">=4.17.0") is False

    def test_range_not_broad(self) -> None:
        assert _is_npm_version_broad(">=4.17.0 <5.0.0") is False


class TestIsPipVersionBroad:
    def test_empty_string_is_broad(self) -> None:
        assert _is_pip_version_broad("") is True

    def test_gte_zero_is_broad(self) -> None:
        assert _is_pip_version_broad(">=0.0.0") is True
        assert _is_pip_version_broad(">=0") is True

    def test_gt_zero_is_broad(self) -> None:
        assert _is_pip_version_broad(">0.0.0") is True

    def test_pinned_not_broad(self) -> None:
        assert _is_pip_version_broad("==2.28.0") is False

    def test_range_not_broad(self) -> None:
        assert _is_pip_version_broad(">=2.28.0,<3.0") is False

    def test_gte_specific_not_broad(self) -> None:
        assert _is_pip_version_broad(">=2.28.0") is False


# ---------------------------------------------------------------------------
# Tests: _is_git_url() helper
# ---------------------------------------------------------------------------


class TestIsGitUrl:
    def test_git_plus_https(self) -> None:
        assert _is_git_url("git+https://github.com/user/repo.git") is True

    def test_git_protocol(self) -> None:
        assert _is_git_url("git://github.com/user/repo.git") is True

    def test_github_shorthand(self) -> None:
        assert _is_git_url("github:user/repo") is True

    def test_gitlab_shorthand(self) -> None:
        assert _is_git_url("gitlab:user/repo") is True

    def test_bitbucket_shorthand(self) -> None:
        assert _is_git_url("bitbucket:user/repo") is True

    def test_user_repo_hash_branch(self) -> None:
        assert _is_git_url("user/repo#main") is True

    def test_regular_version_not_git(self) -> None:
        assert _is_git_url("4.17.21") is False

    def test_semver_range_not_git(self) -> None:
        assert _is_git_url("^4.17.21") is False

    def test_latest_not_git(self) -> None:
        assert _is_git_url("latest") is False

    def test_empty_not_git(self) -> None:
        assert _is_git_url("") is False


# ---------------------------------------------------------------------------
# Tests: _is_local_path() helper
# ---------------------------------------------------------------------------


class TestIsLocalPath:
    def test_file_protocol(self) -> None:
        assert _is_local_path("file:../local") is True

    def test_relative_path(self) -> None:
        assert _is_local_path("./my-package") is True

    def test_parent_relative_path(self) -> None:
        assert _is_local_path("../sibling") is True

    def test_absolute_path(self) -> None:
        assert _is_local_path("/usr/local/my-package") is True

    def test_regular_version_not_local(self) -> None:
        assert _is_local_path("4.17.21") is False

    def test_semver_range_not_local(self) -> None:
        assert _is_local_path("^4.17.21") is False

    def test_npm_package_name_not_local(self) -> None:
        assert _is_local_path("lodash") is False

    def test_git_url_not_local(self) -> None:
        assert _is_local_path("git+https://github.com/user/repo.git") is False

    def test_empty_not_local(self) -> None:
        assert _is_local_path("") is False


# ---------------------------------------------------------------------------
# Tests: _deduplicate_findings()
# ---------------------------------------------------------------------------


class TestDeduplicateFindings:
    def _make_finding(
        self,
        check_id: str = "SC-001",
        evidence: str = "ev",
        line: int | None = None,
        path: Path | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            severity=Severity.MEDIUM,
            title=f"Title for {check_id}",
            description="desc",
            file_path=path,
            line_number=line,
            evidence=evidence,
        )

    def test_empty_list_returns_empty(self) -> None:
        assert _deduplicate_findings([]) == []

    def test_single_finding_returned(self) -> None:
        f = self._make_finding("SC-001")
        result = _deduplicate_findings([f])
        assert len(result) == 1

    def test_identical_findings_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("SC-001", evidence="same evidence", path=p)
        f2 = self._make_finding("SC-001", evidence="same evidence", path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_different_check_ids_not_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("SC-001", evidence="same", path=p)
        f2 = self._make_finding("SC-002", evidence="same", path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_evidence_not_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("SC-003", evidence="evidence A", path=p)
        f2 = self._make_finding("SC-003", evidence="evidence B", path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_line_numbers_not_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("SC-006", evidence="same", line=10, path=p)
        f2 = self._make_finding("SC-006", evidence="same", line=20, path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_preserves_first_occurrence(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("SC-001", evidence="same", path=p)
        f1.title = "First title"
        f2 = self._make_finding("SC-001", evidence="same", path=p)
        f2.title = "Second title"
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].title == "First title"

    def test_preserves_order(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("SC-001", evidence="first", path=p)
        f2 = self._make_finding("SC-002", evidence="second", path=p)
        f3 = self._make_finding("SC-003", evidence="third", path=p)
        result = _deduplicate_findings([f1, f2, f3])
        assert result[0].check_id == "SC-001"
        assert result[1].check_id == "SC-002"
        assert result[2].check_id == "SC-003"


# ---------------------------------------------------------------------------
# Tests: Finding structure and serialization
# ---------------------------------------------------------------------------


class TestFindingStructure:
    def test_all_findings_have_check_id(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest", "pkg": ""},
        )
        findings = check_file(p)
        for f in findings:
            assert f.check_id is not None and len(f.check_id) > 0

    def test_all_findings_have_severity(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        for f in findings:
            assert isinstance(f.severity, Severity)

    def test_all_findings_have_title(self, tmp_path: Path) -> None:
        p = _make_requirements_txt(
            tmp_path / "requirements.txt",
            ["requests"],
        )
        findings = check_file(p)
        for f in findings:
            assert f.title is not None and len(f.title) > 0

    def test_all_findings_have_description(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.description is not None and len(f.description) > 0

    def test_all_findings_have_file_path(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.file_path == p

    def test_all_findings_have_remediation(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        sc_findings = [f for f in findings if f.check_id.startswith("SC-")]
        for f in sc_findings:
            assert f.remediation is not None and len(f.remediation) > 0

    def test_findings_check_id_starts_with_sc(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest", "l0dash": "1.0.0"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.check_id.startswith("SC-"), (
                f"Expected SC- prefix but got: {f.check_id}"
            )

    def test_finding_to_dict_round_trip(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        for finding in findings:
            d = finding.to_dict()
            restored = Finding.from_dict(d)
            assert restored.check_id == finding.check_id
            assert restored.severity == finding.severity
            assert restored.title == finding.title
            assert restored.description == finding.description

    def test_finding_str_representation(self, tmp_path: Path) -> None:
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "latest"},
        )
        findings = check_file(p)
        for finding in findings:
            s = str(finding)
            assert finding.check_id in s
            assert finding.severity.value.upper() in s


# ---------------------------------------------------------------------------
# Tests: pyproject.toml analysis
# ---------------------------------------------------------------------------


class TestPyprojectTomlAnalysis:
    def test_pyproject_with_unversioned_deps(self, tmp_path: Path) -> None:
        content = (
            "[project]\n"
            'name = "my-project"\n'
            'version = "1.0.0"\n'
            "dependencies = [\n"
            '    \"requests\",\n'
            '    \"flask\",\n'
            "]\n"
        )
        p = _write(tmp_path / "pyproject.toml", content)
        findings = check_file(p)
        # Text-based analysis may not fully parse TOML but should not crash
        assert isinstance(findings, list)

    def test_pyproject_with_custom_index(self, tmp_path: Path) -> None:
        content = (
            "[tool.uv]\n"
            "index-url = \"https://my-private-pypi.example.com/simple\"\n"
        )
        p = _write(tmp_path / "pyproject.toml", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" in ids

    def test_pyproject_with_official_index_no_sc006(self, tmp_path: Path) -> None:
        content = (
            "[tool.uv]\n"
            "index-url = \"https://pypi.org/simple\"\n"
        )
        p = _write(tmp_path / "pyproject.toml", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" not in ids

    def test_pyproject_toml_file_returned_as_list(self, tmp_path: Path) -> None:
        content = "[project]\nname = \"test\"\n"
        p = _write(tmp_path / "pyproject.toml", content)
        result = check_file(p)
        assert isinstance(result, list)

    def test_pyproject_with_parsed_pep621_deps(self, tmp_path: Path) -> None:
        """Test that PEP 621 style dependencies are checked (requires Python 3.11+ tomllib)."""
        try:
            import tomllib  # noqa: F401
        except ImportError:
            pytest.skip("tomllib not available (Python < 3.11)")

        content = (
            "[project]\n"
            'name = \"my-project\"\n'
            'version = \"1.0.0\"\n'
            "dependencies = [\n"
            '    \"requests\",\n'  # unversioned
            '    \"flask==2.0.0\",\n'  # pinned - ok
            "]\n"
        )
        p = _write(tmp_path / "pyproject.toml", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        # requests is unversioned -> SC-002
        assert "SC-002" in ids


# ---------------------------------------------------------------------------
# Tests: Real-world MCP patterns
# ---------------------------------------------------------------------------


class TestRealWorldPatterns:
    def test_claude_desktop_config_with_unversioned_npx(self, tmp_path: Path) -> None:
        """Simulates a real Claude Desktop config with unversioned npx packages."""
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "<TOKEN>"}
                }
            }
        }
        p = _write_json(tmp_path / "claude_desktop_config.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        # Both npx invocations are unversioned
        sc011_findings = _findings_for("SC-011", findings)
        assert len(sc011_findings) >= 2

    def test_package_json_with_mixed_dep_issues(self, tmp_path: Path) -> None:
        """Package.json with a mix of issues: git URL, wildcard, local path."""
        p = _make_package_json(
            tmp_path / "package.json",
            dependencies={
                "lodash": "4.17.21",        # OK
                "express": "*",              # SC-003 (broad)
                "my-lib": "git+https://github.com/user/my-lib.git",  # SC-008
                "local-pkg": "file:../local",  # SC-009
            },
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-003" in ids  # express: *
        assert "SC-008" in ids  # my-lib: git+https
        assert "SC-009" in ids  # local-pkg: file:
        # lodash should not trigger issues
        lodash_findings = [f for f in findings if "lodash" in (f.evidence or "")]
        assert all(f.check_id not in ("SC-001", "SC-002", "SC-003") for f in lodash_findings)

    def test_requirements_txt_with_custom_index_and_unversioned(self, tmp_path: Path) -> None:
        """requirements.txt mixing custom index with unversioned packages."""
        content = (
            "--index-url https://my-private.example.com/simple\n"
            "my-private-pkg\n"      # unversioned
            "requests==2.28.0\n"   # OK
        )
        p = _write(tmp_path / "requirements.txt", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-006" in ids   # custom index
        assert "SC-002" in ids   # unversioned my-private-pkg

    def test_mcp_config_with_multiple_sc_issues(self, tmp_path: Path) -> None:
        """MCP config with npx latest, uvx unversioned, and git URL."""
        data = {
            "mcpServers": {
                "server1": {
                    "command": "npx",
                    "args": ["my-mcp-server@latest"],  # SC-011 (HIGH - latest tag)
                },
                "server2": {
                    "command": "uvx",
                    "args": ["mcp-server-fetch"],  # SC-012
                },
                "server3": {
                    "command": "npx",
                    "args": ["user/mcp-pkg#dev"],  # SC-008 (git URL)
                },
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-011" in ids  # server1 (latest tag)
        assert "SC-012" in ids  # server2 (unversioned uvx)
        assert "SC-008" in ids  # server3 (git URL)

    def test_npmrc_dependency_confusion_attack_setup(self, tmp_path: Path) -> None:
        """A .npmrc that configures scoped registry redirection - dependency confusion risk."""
        content = (
            "@myorg:registry=https://npm.pkg.github.com\n"
            "registry=https://registry.npmjs.org\n"
        )
        p = _write(tmp_path / ".npmrc", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        # Scoped private registry is flagged
        assert "SC-005" in ids

    def test_lockfile_with_all_integrity_hashes_no_sc007(self, tmp_path: Path) -> None:
        """A well-formed lockfile with all integrity hashes should not trigger SC-007."""
        lockdata = {
            "lockfileVersion": 2,
            "name": "my-project",
            "packages": {
                "": {"name": "my-project"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZkFekkObUFyGjFnoDCA==",
                },
                "node_modules/express": {
                    "version": "4.18.0",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
                    "integrity": "sha512-abc123def456==",
                },
            }
        }
        p = _write_json(tmp_path / "package-lock.json", lockdata)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "SC-007" not in ids

    def test_full_supply_chain_risk_project(self, tmp_path: Path) -> None:
        """A project with multiple supply chain risks across different manifest files."""
        # package.json with wildcard deps and no lockfile
        _make_package_json(
            tmp_path / "package.json",
            dependencies={"lodash": "*", "express": "latest"},
        )
        # requirements.txt with unversioned deps and custom index
        _write(
            tmp_path / "requirements.txt",
            "--index-url https://evil.example.com/simple\nrequests\nflask\n"
        )
        # MCP config with unversioned npx
        _write_json(tmp_path / "mcp.json", {
            "mcpServers": {
                "server": {
                    "command": "npx",
                    "args": ["my-mcp-server"],
                }
            }
        })

        all_findings: list[Finding] = []
        for fname in ["package.json", "requirements.txt", "mcp.json"]:
            all_findings.extend(check_file(tmp_path / fname))

        ids = _check_ids(all_findings)
        assert "SC-003" in ids   # wildcard/latest npm
        assert "SC-004" in ids   # missing lockfile
        assert "SC-006" in ids   # evil pip index
        assert "SC-002" in ids   # unversioned pip packages
        assert "SC-011" in ids   # unversioned npx
