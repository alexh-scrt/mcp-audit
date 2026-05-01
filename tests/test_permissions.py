"""Unit tests for the mcp_audit permissions checker.

Tests cover:
- World-writable files (PERM-001)
- Group-writable files (PERM-002)
- World-readable sensitive files (PERM-003)
- World-writable directories without sticky bit (PERM-004)
- Root-owned but user-writable files (PERM-005)
- Files with executable bits set (PERM-006)
- check_path() with files and directories
- check_paths() with multiple paths
- Nonexistent path handling
- Windows platform skips for chmod-dependent tests
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from mcp_audit.checks.permissions import (
    _is_sensitive_filename,
    _is_root_owned_but_user_writable,
    check_path,
    check_paths,
)
from mcp_audit.models import Finding, Severity


# ---------------------------------------------------------------------------
# Platform guard helpers
# ---------------------------------------------------------------------------

is_windows = sys.platform == "win32"
skip_on_windows = pytest.mark.skipif(
    is_windows, reason="chmod permission bits are not meaningful on Windows"
)
skip_if_root = pytest.mark.skipif(
    not is_windows and os.getuid() == 0,
    reason="Permission checks behave differently when running as root",
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _write(path: Path, content: str = "test") -> Path:
    """Write text to a file, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _check_ids(findings: list[Finding]) -> set[str]:
    """Extract all check IDs from a list of findings."""
    return {f.check_id for f in findings}


def _severities(findings: list[Finding]) -> set[Severity]:
    """Extract all unique severities from a list of findings."""
    return {f.severity for f in findings}


def _findings_for(check_id: str, findings: list[Finding]) -> list[Finding]:
    """Filter findings by check ID."""
    return [f for f in findings if f.check_id == check_id]


# ---------------------------------------------------------------------------
# Tests: check_path() with non-existent paths
# ---------------------------------------------------------------------------


class TestNonExistentPath:
    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = check_path(tmp_path / "does_not_exist.json")
        assert result == []

    def test_nonexistent_directory_returns_empty(self, tmp_path: Path) -> None:
        result = check_path(tmp_path / "no_such_dir")
        assert result == []


# ---------------------------------------------------------------------------
# Tests: PERM-001 - World-writable file
# ---------------------------------------------------------------------------


class TestWorldWritableFile:
    @skip_on_windows
    @skip_if_root
    def test_world_writable_file_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json", '{"mcpServers": {}}')
        os.chmod(p, 0o666)  # rw-rw-rw-
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-001" in ids

    @skip_on_windows
    @skip_if_root
    def test_world_writable_file_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        perm001 = _findings_for("PERM-001", findings)
        assert len(perm001) >= 1
        assert perm001[0].severity == Severity.CRITICAL

    @skip_on_windows
    @skip_if_root
    def test_world_writable_file_includes_path(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        perm001 = _findings_for("PERM-001", findings)
        assert perm001[0].file_path == p

    @skip_on_windows
    @skip_if_root
    def test_world_writable_file_has_evidence(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        perm001 = _findings_for("PERM-001", findings)
        assert perm001[0].evidence is not None
        assert "0o" in perm001[0].evidence or "mode" in perm001[0].evidence.lower()

    @skip_on_windows
    @skip_if_root
    def test_world_writable_file_has_remediation(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        perm001 = _findings_for("PERM-001", findings)
        assert perm001[0].remediation is not None
        assert len(perm001[0].remediation) > 0

    @skip_on_windows
    def test_non_world_writable_file_no_perm001(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o644)  # rw-r--r--
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-001" not in ids

    @skip_on_windows
    @skip_if_root
    def test_world_writable_with_exec_bits(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o777)  # rwxrwxrwx
        findings = check_path(p)
        ids = _check_ids(findings)
        # Should detect world-writable (PERM-001) at minimum
        assert "PERM-001" in ids


# ---------------------------------------------------------------------------
# Tests: PERM-002 - Group-writable file
# ---------------------------------------------------------------------------


class TestGroupWritableFile:
    @skip_on_windows
    @skip_if_root
    def test_group_writable_file_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o664)  # rw-rw-r--
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-002" in ids

    @skip_on_windows
    @skip_if_root
    def test_group_writable_file_is_high(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o664)
        findings = check_path(p)
        perm002 = _findings_for("PERM-002", findings)
        assert len(perm002) >= 1
        assert perm002[0].severity == Severity.HIGH

    @skip_on_windows
    @skip_if_root
    def test_group_writable_includes_file_path(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o664)
        findings = check_path(p)
        perm002 = _findings_for("PERM-002", findings)
        assert perm002[0].file_path == p

    @skip_on_windows
    def test_group_read_only_no_perm002(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o644)  # rw-r--r--
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-002" not in ids

    @skip_on_windows
    def test_owner_only_no_perm002(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o600)  # rw-------
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-002" not in ids


# ---------------------------------------------------------------------------
# Tests: PERM-003 - World-readable sensitive file
# ---------------------------------------------------------------------------


class TestWorldReadableSensitiveFile:
    @skip_on_windows
    @skip_if_root
    def test_sensitive_filename_world_readable_detected(self, tmp_path: Path) -> None:
        # Sensitive name: contains 'secret'
        p = _write(tmp_path / "mcp_secret.json", '{"token": "abc123"}')
        os.chmod(p, 0o644)  # world-readable
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" in ids

    @skip_on_windows
    @skip_if_root
    def test_token_filename_world_readable_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "api_token.json", '{"key": "secret"}')
        os.chmod(p, 0o644)
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" in ids

    @skip_on_windows
    @skip_if_root
    def test_credential_filename_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "credentials.json", '{"user": "admin"}')
        os.chmod(p, 0o644)
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" in ids

    @skip_on_windows
    @skip_if_root
    def test_key_filename_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "private_key.json", '{}')
        os.chmod(p, 0o644)
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" in ids

    @skip_on_windows
    @skip_if_root
    def test_env_filename_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / ".env", "API_KEY=12345")
        os.chmod(p, 0o644)
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" in ids

    @skip_on_windows
    @skip_if_root
    def test_sensitive_file_not_world_readable_no_perm003(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "secrets.json", '{"key": "val"}')
        os.chmod(p, 0o600)  # rw------- - not world-readable
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" not in ids

    @skip_on_windows
    @skip_if_root
    def test_non_sensitive_filename_no_perm003(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "mcp_config.json", '{}')
        os.chmod(p, 0o644)
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-003" not in ids

    @skip_on_windows
    @skip_if_root
    def test_perm003_severity_is_high(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "auth_config.json", '{}')
        os.chmod(p, 0o644)
        findings = check_path(p)
        perm003 = _findings_for("PERM-003", findings)
        assert len(perm003) >= 1
        assert perm003[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Tests: PERM-004 - World-writable directory without sticky bit
# ---------------------------------------------------------------------------


class TestWorldWritableDirectory:
    @skip_on_windows
    @skip_if_root
    def test_world_writable_dir_without_sticky_detected(self, tmp_path: Path) -> None:
        d = tmp_path / "config_dir"
        d.mkdir()
        os.chmod(d, 0o777)  # rwxrwxrwx - no sticky
        findings = check_path(d)
        ids = _check_ids(findings)
        assert "PERM-004" in ids

    @skip_on_windows
    @skip_if_root
    def test_perm004_is_critical(self, tmp_path: Path) -> None:
        d = tmp_path / "config_dir"
        d.mkdir()
        os.chmod(d, 0o777)
        findings = check_path(d)
        perm004 = _findings_for("PERM-004", findings)
        assert len(perm004) >= 1
        assert perm004[0].severity == Severity.CRITICAL

    @skip_on_windows
    @skip_if_root
    def test_world_writable_dir_with_sticky_bit_not_perm004(self, tmp_path: Path) -> None:
        d = tmp_path / "sticky_dir"
        d.mkdir()
        # Set world-writable WITH sticky bit (like /tmp)
        sticky_mode = 0o777 | stat.S_ISVTX
        os.chmod(d, sticky_mode)
        findings = check_path(d)
        ids = _check_ids(findings)
        # Should NOT be PERM-004 (sticky bit is set)
        assert "PERM-004" not in ids
        # But still flagged as world-writable (PERM-001)
        assert "PERM-001" in ids

    @skip_on_windows
    @skip_if_root
    def test_normal_dir_no_perm004(self, tmp_path: Path) -> None:
        d = tmp_path / "normal_dir"
        d.mkdir()
        os.chmod(d, 0o755)  # rwxr-xr-x
        findings = check_path(d)
        ids = _check_ids(findings)
        assert "PERM-004" not in ids

    @skip_on_windows
    @skip_if_root
    def test_perm004_includes_directory_path(self, tmp_path: Path) -> None:
        d = tmp_path / "config_dir"
        d.mkdir()
        os.chmod(d, 0o777)
        findings = check_path(d)
        perm004 = _findings_for("PERM-004", findings)
        assert perm004[0].file_path == d

    @skip_on_windows
    @skip_if_root
    def test_perm004_has_remediation(self, tmp_path: Path) -> None:
        d = tmp_path / "config_dir"
        d.mkdir()
        os.chmod(d, 0o777)
        findings = check_path(d)
        perm004 = _findings_for("PERM-004", findings)
        assert perm004[0].remediation is not None
        assert len(perm004[0].remediation) > 0


# ---------------------------------------------------------------------------
# Tests: PERM-002 for directories (group-writable)
# ---------------------------------------------------------------------------


class TestGroupWritableDirectory:
    @skip_on_windows
    @skip_if_root
    def test_group_writable_dir_detected(self, tmp_path: Path) -> None:
        d = tmp_path / "group_writable_dir"
        d.mkdir()
        os.chmod(d, 0o775)  # rwxrwxr-x
        findings = check_path(d)
        ids = _check_ids(findings)
        assert "PERM-002" in ids

    @skip_on_windows
    @skip_if_root
    def test_group_writable_dir_is_medium(self, tmp_path: Path) -> None:
        d = tmp_path / "group_writable_dir"
        d.mkdir()
        os.chmod(d, 0o775)
        findings = check_path(d)
        perm002 = _findings_for("PERM-002", findings)
        assert len(perm002) >= 1
        assert perm002[0].severity == Severity.MEDIUM

    @skip_on_windows
    def test_normal_dir_no_perm002(self, tmp_path: Path) -> None:
        d = tmp_path / "normal"
        d.mkdir()
        os.chmod(d, 0o755)  # rwxr-xr-x
        findings = check_path(d)
        ids = _check_ids(findings)
        assert "PERM-002" not in ids


# ---------------------------------------------------------------------------
# Tests: PERM-006 - Executable bits on config file
# ---------------------------------------------------------------------------


class TestExecutableBitsFile:
    @skip_on_windows
    @skip_if_root
    def test_executable_config_file_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        # 0o744 = rwxr--r-- (owner exec, no group/world write)
        os.chmod(p, 0o744)
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-006" in ids

    @skip_on_windows
    @skip_if_root
    def test_perm006_is_medium(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o744)
        findings = check_path(p)
        perm006 = _findings_for("PERM-006", findings)
        assert len(perm006) >= 1
        assert perm006[0].severity == Severity.MEDIUM

    @skip_on_windows
    def test_standard_config_no_perm006(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o644)  # rw-r--r--
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-006" not in ids

    @skip_on_windows
    def test_read_only_file_no_perm006(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o444)  # r--r--r--
        findings = check_path(p)
        ids = _check_ids(findings)
        assert "PERM-006" not in ids

    @skip_on_windows
    @skip_if_root
    def test_world_writable_exec_produces_perm001_not_just_perm006(self, tmp_path: Path) -> None:
        """World-writable is more severe; PERM-001 should also be present."""
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o777)  # rwxrwxrwx
        findings = check_path(p)
        ids = _check_ids(findings)
        # PERM-001 (world-writable) must be reported
        assert "PERM-001" in ids


# ---------------------------------------------------------------------------
# Tests: check_paths() - multiple paths
# ---------------------------------------------------------------------------


class TestCheckPaths:
    def test_empty_list_returns_empty(self) -> None:
        result = check_paths([])
        assert result == []

    def test_single_path_delegated(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        result_single = check_path(p)
        result_multi = check_paths([p])
        # Both should return the same findings
        assert {f.check_id for f in result_single} == {f.check_id for f in result_multi}

    @skip_on_windows
    @skip_if_root
    def test_multiple_paths_aggregated(self, tmp_path: Path) -> None:
        p1 = _write(tmp_path / "config1.json")
        p2 = _write(tmp_path / "config2.json")
        os.chmod(p1, 0o666)  # world-writable -> PERM-001
        os.chmod(p2, 0o664)  # group-writable -> PERM-002
        findings = check_paths([p1, p2])
        ids = _check_ids(findings)
        assert "PERM-001" in ids
        assert "PERM-002" in ids

    def test_nonexistent_paths_ignored(self, tmp_path: Path) -> None:
        paths = [
            tmp_path / "no1.json",
            tmp_path / "no2.json",
        ]
        result = check_paths(paths)
        assert result == []

    @skip_on_windows
    @skip_if_root
    def test_mixed_existing_nonexistent(self, tmp_path: Path) -> None:
        p_exists = _write(tmp_path / "real.json")
        os.chmod(p_exists, 0o666)
        p_missing = tmp_path / "missing.json"
        findings = check_paths([p_exists, p_missing])
        ids = _check_ids(findings)
        assert "PERM-001" in ids

    @skip_on_windows
    @skip_if_root
    def test_findings_include_correct_file_paths(self, tmp_path: Path) -> None:
        p1 = _write(tmp_path / "a.json")
        p2 = _write(tmp_path / "b.json")
        os.chmod(p1, 0o666)
        os.chmod(p2, 0o666)
        findings = check_paths([p1, p2])
        found_paths = {f.file_path for f in findings if f.file_path}
        assert p1 in found_paths
        assert p2 in found_paths


# ---------------------------------------------------------------------------
# Tests: _is_sensitive_filename() helper
# ---------------------------------------------------------------------------


class TestIsSensitiveFilename:
    def test_secret_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("my_secret_config.json")) is True

    def test_token_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("api_token.json")) is True

    def test_credential_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("credentials.yaml")) is True

    def test_password_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("password.txt")) is True

    def test_passwd_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("passwd")) is True

    def test_key_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("private_key.pem")) is True

    def test_auth_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("auth_config.json")) is True

    def test_private_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("private.json")) is True

    def test_cert_in_name(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("server_cert.pem")) is True

    def test_dotenv_filename(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path(".env")) is True

    def test_case_insensitive_match(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("SECRET_KEY.JSON")) is True
        assert _is_sensitive_filename(Path("TOKEN_CONFIG.JSON")) is True

    def test_unrelated_name_not_sensitive(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path("mcp_config.json")) is False
        assert _is_sensitive_filename(Path("settings.json")) is False
        assert _is_sensitive_filename(Path("package.json")) is False
        assert _is_sensitive_filename(Path("tsconfig.json")) is False

    def test_empty_stem_not_sensitive(self, tmp_path: Path) -> None:
        assert _is_sensitive_filename(Path(".json")) is False


# ---------------------------------------------------------------------------
# Tests: _is_root_owned_but_user_writable() helper
# ---------------------------------------------------------------------------


class TestIsRootOwnedButUserWritable:
    @skip_on_windows
    def test_non_root_owned_file_returns_false(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        st = p.stat()
        file_mode = stat.S_IMODE(st.st_mode)
        # Current user owns the file, not root
        if st.st_uid != 0:
            assert _is_root_owned_but_user_writable(st, file_mode) is False

    @skip_on_windows
    def test_returns_false_for_current_user_as_root(self, tmp_path: Path) -> None:
        """When running as root, should return False (not a privilege issue)."""
        if os.getuid() != 0:
            pytest.skip("This test only meaningful when running as root")
        p = _write(tmp_path / "config.json")
        st = p.stat()
        file_mode = stat.S_IMODE(st.st_mode)
        assert _is_root_owned_but_user_writable(st, file_mode) is False


# ---------------------------------------------------------------------------
# Tests: check_path() return types and structure
# ---------------------------------------------------------------------------


class TestCheckPathReturnTypes:
    def test_returns_list(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        result = check_path(p)
        assert isinstance(result, list)

    def test_returns_finding_instances(self, tmp_path: Path) -> None:
        if is_windows:
            pytest.skip("Cannot set restrictive permissions on Windows")
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        result = check_path(p)
        for item in result:
            assert isinstance(item, Finding)

    def test_each_finding_has_check_id(self, tmp_path: Path) -> None:
        if is_windows:
            pytest.skip("Cannot set permissions on Windows")
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        result = check_path(p)
        for finding in result:
            assert finding.check_id is not None
            assert len(finding.check_id) > 0

    def test_each_finding_has_severity(self, tmp_path: Path) -> None:
        if is_windows:
            pytest.skip("Cannot set permissions on Windows")
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        result = check_path(p)
        for finding in result:
            assert isinstance(finding.severity, Severity)

    def test_each_finding_has_title_and_description(self, tmp_path: Path) -> None:
        if is_windows:
            pytest.skip("Cannot set permissions on Windows")
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        result = check_path(p)
        for finding in result:
            assert finding.title is not None and len(finding.title) > 0
            assert finding.description is not None and len(finding.description) > 0

    def test_directory_returns_list(self, tmp_path: Path) -> None:
        result = check_path(tmp_path)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Tests: edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @skip_on_windows
    def test_read_only_file_no_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "readonly.json")
        os.chmod(p, 0o400)  # r--------
        findings = check_path(p)
        ids = _check_ids(findings)
        # A read-only, owner-only file should have no permission findings
        assert "PERM-001" not in ids
        assert "PERM-002" not in ids
        assert "PERM-004" not in ids

    @skip_on_windows
    def test_strict_config_file_no_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "claude_desktop_config.json")
        os.chmod(p, 0o600)  # rw------- (owner read-write only)
        findings = check_path(p)
        ids = _check_ids(findings)
        # 0o600 should be clean: no world or group write, not sensitive+world-read
        assert "PERM-001" not in ids
        assert "PERM-002" not in ids
        # PERM-003 requires world-readable
        assert "PERM-003" not in ids

    @skip_on_windows
    def test_644_config_no_critical_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "mcp_config.json")
        os.chmod(p, 0o644)  # rw-r--r-- (standard config permission)
        findings = check_path(p)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_empty_file_checked_normally(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.json"
        p.touch()  # empty file
        result = check_path(p)
        assert isinstance(result, list)

    @skip_on_windows
    @skip_if_root
    def test_multiple_issues_on_same_file(self, tmp_path: Path) -> None:
        """A file can have multiple permission issues simultaneously."""
        # World-writable + executable + sensitive name
        p = _write(tmp_path / "api_token.json")
        os.chmod(p, 0o777)  # rwxrwxrwx
        findings = check_path(p)
        ids = _check_ids(findings)
        # Should flag world-writable at minimum
        assert "PERM-001" in ids
        # Should have at least 2 distinct issues
        assert len(findings) >= 2

    @skip_on_windows
    @skip_if_root
    def test_world_writable_sensitive_file_both_detected(self, tmp_path: Path) -> None:
        """A world-writable sensitive file triggers both PERM-001 and PERM-003."""
        p = _write(tmp_path / "auth_token.json")
        os.chmod(p, 0o666)  # rw-rw-rw- (world-writable and world-readable)
        findings = check_path(p)
        ids = _check_ids(findings)
        # Both world-writable and world-readable sensitive should be flagged
        assert "PERM-001" in ids
        # PERM-003 requires world-readable (which 0o666 satisfies) and sensitive name
        assert "PERM-003" in ids

    def test_check_path_on_symlink_to_existing_file(self, tmp_path: Path) -> None:
        if is_windows:
            pytest.skip("Symlinks require elevated privileges on Windows")
        real = _write(tmp_path / "real.json")
        link = tmp_path / "link.json"
        link.symlink_to(real)
        # Should not raise
        result = check_path(link)
        assert isinstance(result, list)

    def test_check_path_on_symlink_to_nonexistent(self, tmp_path: Path) -> None:
        if is_windows:
            pytest.skip("Symlinks require elevated privileges on Windows")
        link = tmp_path / "broken_link.json"
        link.symlink_to(tmp_path / "nonexistent.json")
        # Broken symlink: stat() will fail, should return empty
        result = check_path(link)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Tests: findings serialization
# ---------------------------------------------------------------------------


class TestFindingsSerialization:
    @skip_on_windows
    @skip_if_root
    def test_finding_to_dict_round_trip(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        assert len(findings) > 0

        for finding in findings:
            d = finding.to_dict()
            restored = Finding.from_dict(d)
            assert restored.check_id == finding.check_id
            assert restored.severity == finding.severity
            assert restored.title == finding.title
            assert restored.description == finding.description

    @skip_on_windows
    @skip_if_root
    def test_finding_str_representation(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        for finding in findings:
            s = str(finding)
            assert finding.check_id in s
            assert finding.severity.value.upper() in s


# ---------------------------------------------------------------------------
# Tests: PERM check IDs are valid format
# ---------------------------------------------------------------------------


class TestCheckIdFormat:
    @skip_on_windows
    @skip_if_root
    def test_perm001_check_id_format(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.json")
        os.chmod(p, 0o666)
        findings = check_path(p)
        perm001 = _findings_for("PERM-001", findings)
        assert len(perm001) >= 1
        assert perm001[0].check_id == "PERM-001"

    @skip_on_windows
    @skip_if_root
    def test_all_perm_findings_have_perm_prefix(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "auth_config.json")
        os.chmod(p, 0o777)
        findings = check_path(p)
        for f in findings:
            assert f.check_id.startswith("PERM-"), (
                f"Expected PERM- prefix but got: {f.check_id}"
            )
