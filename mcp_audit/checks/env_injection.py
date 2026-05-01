"""Environment variable injection scanner for MCP configuration files.

This module scans MCP server configuration files for dangerous environment
variable overrides that could be exploited to hijack process execution,
load malicious libraries, or escalate privileges before the MCP sandbox
is initialized.

Inspired by injection vectors such as LD_PRELOAD library hijacking,
PATH prepending for command shadowing, PYTHONPATH/NODE_OPTIONS abuse,
and shell init file overrides.

Checks performed:
    ENV-001: PATH prepending or override with untrusted directory
    ENV-002: LD_PRELOAD or LD_LIBRARY_PATH injection
    ENV-003: PYTHONPATH or PYTHONSTARTUP injection
    ENV-004: NODE_OPTIONS or NODE_PATH injection
    ENV-005: DYLD_INSERT_LIBRARIES (macOS equivalent of LD_PRELOAD)
    ENV-006: BASH_ENV, ENV, or ZDOTDIR shell init file override
    ENV-007: Suspicious environment variable referencing temp or world-writable paths
    ENV-008: LD_AUDIT or LD_DEBUG injection (advanced linker hijack)
    ENV-009: RUBYOPT, RUBYLIB, PERL5OPT, or PERLLIB injection
    ENV-010: JAVA_TOOL_OPTIONS or _JAVA_OPTIONS injection
    ENV-011: Environment variable containing command substitution
    ENV-012: Multiple dangerous environment variables (amplified risk)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_audit.models import Finding, Severity

# ---------------------------------------------------------------------------
# Dangerous environment variable definitions
# ---------------------------------------------------------------------------

# Variables that can be used to override dynamic linker behavior (LD_PRELOAD etc.)
_LINKER_HIJACK_VARS: frozenset[str] = frozenset({
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_PROFILE",
    "LD_ORIGIN_PATH",
    "LD_DYNAMIC_WEAK",
    "LD_BIND_NOW",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FORCE_FLAT_NAMESPACE",
})

# Python interpreter abuse variables
_PYTHON_INJECTION_VARS: frozenset[str] = frozenset({
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONDEBUG",
    "PYTHONOPTIMIZE",
    "PYTHONWARNINGS",
    "PYTHONEXECUTABLE",
    "PYTHONUSERBASE",
})

# Node.js / npm abuse variables
_NODE_INJECTION_VARS: frozenset[str] = frozenset({
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_ENV",
    "NPM_CONFIG_PREFIX",
    "NPM_CONFIG_CACHE",
    "NODE_DEBUG",
    "NODE_EXTRA_CA_CERTS",
    "NODE_REPL_HISTORY",
    "NODE_NO_WARNINGS",
})

# Shell initialization file overrides
_SHELL_INIT_VARS: frozenset[str] = frozenset({
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "BASH_XTRACEFD",
    "PS4",                  # Can be abused to inject code via xtrace
    "PROMPT_COMMAND",       # Executed before every bash prompt
    "CDPATH",               # Directory search path hijacking
    "MANPATH",
    "INFOPATH",
})

# Ruby / Perl interpreter abuse variables
_RUBY_PERL_INJECTION_VARS: frozenset[str] = frozenset({
    "RUBYOPT",
    "RUBYLIB",
    "RUBY_GC_MALLOC_LIMIT",
    "PERL5OPT",
    "PERLLIB",
    "PERL5LIB",
    "PERL_UNICODE",
    "PERL_SIGNALS",
})

# JVM abuse variables
_JAVA_INJECTION_VARS: frozenset[str] = frozenset({
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "JAVA_OPTS",
    "CATALINA_OPTS",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
})

# Build all dangerous variable sets into a lookup map for quick severity resolution
_LINKER_VARS_SEVERITY = Severity.CRITICAL
_PYTHON_VARS_SEVERITY = Severity.HIGH
_NODE_VARS_SEVERITY = Severity.HIGH
_SHELL_INIT_VARS_SEVERITY = Severity.HIGH
_RUBY_PERL_VARS_SEVERITY = Severity.MEDIUM
_JAVA_VARS_SEVERITY = Severity.MEDIUM

# Combine all dangerous vars into a single mapping: var_name -> (check_id, severity, description)
_DANGEROUS_ENV_VARS: dict[str, tuple[str, Severity, str]] = {}

for _var in _LINKER_HIJACK_VARS:
    _DANGEROUS_ENV_VARS[_var] = (
        "ENV-002" if "LD_" in _var or "DYLD_" in _var else "ENV-005",
        _LINKER_VARS_SEVERITY,
        "dynamic linker hijacking variable",
    )

for _var in _PYTHON_INJECTION_VARS:
    _DANGEROUS_ENV_VARS[_var] = (
        "ENV-003",
        _PYTHON_VARS_SEVERITY,
        "Python interpreter injection variable",
    )

for _var in _NODE_INJECTION_VARS:
    _DANGEROUS_ENV_VARS[_var] = (
        "ENV-004",
        _NODE_VARS_SEVERITY,
        "Node.js runtime injection variable",
    )

for _var in _SHELL_INIT_VARS:
    _DANGEROUS_ENV_VARS[_var] = (
        "ENV-006",
        _SHELL_INIT_VARS_SEVERITY,
        "shell initialization override variable",
    )

for _var in _RUBY_PERL_INJECTION_VARS:
    _DANGEROUS_ENV_VARS[_var] = (
        "ENV-009",
        _RUBY_PERL_VARS_SEVERITY,
        "Ruby/Perl interpreter injection variable",
    )

for _var in _JAVA_INJECTION_VARS:
    _DANGEROUS_ENV_VARS[_var] = (
        "ENV-010",
        _JAVA_VARS_SEVERITY,
        "JVM options injection variable",
    )

# ---------------------------------------------------------------------------
# Regex patterns for PATH and value analysis
# ---------------------------------------------------------------------------

# Suspicious directories that should not appear at the start of PATH
_SUSPICIOUS_PATH_PREFIXES: list[re.Pattern[str]] = [
    re.compile(r"^[.]/?"),                        # Relative current-dir prefix
    re.compile(r"^\.\.?"),                        # Parent directory traversal
    re.compile(r"^/tmp"),                          # World-writable temp
    re.compile(r"^/var/tmp"),
    re.compile(r"^/dev/shm"),
    re.compile(r"^\$TMPDIR"),
    re.compile(r"^\$HOME/\.(local|config)/"),      # Hidden home dirs
    re.compile(r"^/private/tmp"),                  # macOS temp
    re.compile(r"^C:\\[Tt]emp"),                   # Windows temp (normalized)
    re.compile(r"^~"),                             # Unresolved home dir
]

# Command substitution patterns in env values
_CMD_SUBSTITUTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\([^)]+\)"),     # $(command)
    re.compile(r"`[^`]+`"),          # `command`
    re.compile(r"<\([^)]+\)"),       # <(process substitution)
]

# Temp / world-writable path patterns in env var values
_TEMP_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|[;:])(?:/tmp|/var/tmp|/dev/shm|/private/tmp)"),
    re.compile(r"\$TMPDIR"),
    re.compile(r"\$\{TMPDIR\}"),
    re.compile(r"C:\\[Tt]emp", re.IGNORECASE),
]

# High-threshold: number of dangerous env vars before triggering ENV-012
_DANGEROUS_COUNT_THRESHOLD = 3


def check_file(path: Path) -> list[Finding]:
    """Check a single configuration file for environment injection risks.

    Attempts to parse the file as JSON to locate 'env' blocks within MCP
    server definitions, then performs both structural and raw text analysis.

    Args:
        path: Path to the configuration file to analyze.

    Returns:
        A list of Finding instances for all environment injection issues
        detected. Returns an empty list if the file cannot be read.
    """
    if not path.exists() or not path.is_file():
        return []

    try:
        raw_content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []

    # Attempt JSON parsing for structural analysis
    parsed: Any = None
    if path.suffix.lower() in (".json", ".jsonc"):
        try:
            parsed = json.loads(raw_content)
        except json.JSONDecodeError:
            pass

    if parsed is not None and isinstance(parsed, dict):
        findings.extend(_check_json_env_blocks(parsed, path))

    # Always perform raw text analysis for non-JSON or supplemental detection
    findings.extend(_check_raw_text_env(raw_content, path))

    findings = _deduplicate_findings(findings)
    return findings


def check_files(paths: list[Path]) -> list[Finding]:
    """Run environment injection checks on multiple configuration files.

    Args:
        paths: A list of file paths to check.

    Returns:
        A combined list of all findings across all provided files.
    """
    findings: list[Finding] = []
    for path in paths:
        findings.extend(check_file(path))
    return findings


def check_env_dict(
    env: dict[str, Any],
    file_path: Path,
    context: str = "env",
) -> list[Finding]:
    """Check a dictionary of environment variable key-value pairs for injection risks.

    This is the core analysis function, callable directly for testing or for
    checking env dicts obtained from any source (not just JSON files).

    Args:
        env: A dictionary mapping environment variable names to their values.
        file_path: The file path to attribute findings to.
        context: A human-readable description of where this env dict came from
            (e.g., "mcpServers.my-server.env").

    Returns:
        A list of Finding instances for all injection risks detected.
    """
    findings: list[Finding] = []
    dangerous_found: list[tuple[str, str]] = []  # (var_name, check_id)

    for var_name, var_value in env.items():
        if not isinstance(var_name, str):
            continue

        var_value_str = str(var_value) if var_value is not None else ""
        var_upper = var_name.upper()

        # Check PATH separately (ENV-001)
        if var_upper == "PATH":
            findings.extend(_check_path_value(var_value_str, file_path, context))
            continue

        # Check against known dangerous variables
        if var_upper in _DANGEROUS_ENV_VARS:
            check_id, severity, var_description = _DANGEROUS_ENV_VARS[var_upper]
            dangerous_found.append((var_name, check_id))

            findings.append(_make_dangerous_var_finding(
                check_id=check_id,
                severity=severity,
                var_name=var_name,
                var_value=var_value_str,
                var_description=var_description,
                file_path=file_path,
                context=context,
            ))

        # Check value for command substitution regardless of variable name (ENV-011)
        cmd_sub_findings = _check_value_for_cmd_substitution(
            var_name, var_value_str, file_path, context
        )
        findings.extend(cmd_sub_findings)

        # Check for temp/world-writable paths in env var values (ENV-007)
        temp_path_findings = _check_value_for_temp_paths(
            var_name, var_value_str, file_path, context
        )
        findings.extend(temp_path_findings)

    # ENV-012: Multiple dangerous variables amplify overall risk
    if len(dangerous_found) >= _DANGEROUS_COUNT_THRESHOLD:
        var_names = [v for v, _ in dangerous_found]
        findings.append(
            Finding(
                check_id="ENV-012",
                severity=Severity.CRITICAL,
                title="Multiple dangerous environment variables configured",
                description=(
                    f"The environment block at '{context}' in '{file_path}' defines "
                    f"{len(dangerous_found)} dangerous environment variables: "
                    f"{', '.join(var_names)}. "
                    "Combining multiple injection vectors substantially increases "
                    "the attack surface and suggests a deliberate attempt to "
                    "compromise the process environment."
                ),
                file_path=file_path,
                evidence=f"Dangerous vars in {context}: {var_names}",
                remediation=(
                    "Remove all unnecessary environment variable overrides from MCP "
                    "server configurations. Each dangerous variable should be "
                    "individually justified and scoped to the minimum required value."
                ),
                extra={"dangerous_variables": var_names},
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_json_env_blocks(config: dict[str, Any], path: Path) -> list[Finding]:
    """Locate and analyse all 'env' blocks within a parsed JSON configuration.

    Handles both top-level env blocks and env blocks nested within
    mcpServers / servers / mcp_servers server definitions.

    Args:
        config: The parsed top-level configuration dictionary.
        path: The source file path.

    Returns:
        A list of findings from all env blocks found.
    """
    findings: list[Finding] = []

    # Check top-level 'env' key
    if isinstance(config.get("env"), dict):
        findings.extend(check_env_dict(config["env"], path, context="env"))

    # Check inside mcpServers / servers / mcp_servers blocks
    for block_key in ("mcpServers", "servers", "mcp_servers"):
        servers_block = config.get(block_key)
        if not isinstance(servers_block, dict):
            continue

        for server_name, server_def in servers_block.items():
            if not isinstance(server_def, dict):
                continue

            env_block = server_def.get("env")
            if isinstance(env_block, dict):
                context = f"{block_key}.{server_name}.env"
                findings.extend(check_env_dict(env_block, path, context=context))

            # Also check nested 'config.env' or 'options.env' patterns
            for sub_key in ("config", "options", "settings"):
                sub_block = server_def.get(sub_key)
                if isinstance(sub_block, dict):
                    sub_env = sub_block.get("env")
                    if isinstance(sub_env, dict):
                        context = f"{block_key}.{server_name}.{sub_key}.env"
                        findings.extend(check_env_dict(sub_env, path, context=context))

    # Recursively walk any other nested dicts looking for 'env' keys
    findings.extend(_walk_for_env_blocks(config, path, key_path=[], visited_paths=set()))

    return findings


def _walk_for_env_blocks(
    node: Any,
    path: Path,
    key_path: list[str],
    visited_paths: set[str],
) -> list[Finding]:
    """Recursively walk a JSON structure to find 'env' dict blocks.

    Skips the top-level and mcpServers blocks (already handled by
    ``_check_json_env_blocks``) to avoid duplicate reporting.

    Args:
        node: The current JSON node.
        path: The source file path.
        key_path: The list of parent keys leading to this node.
        visited_paths: Set of already-visited dotted key paths to avoid revisiting.

    Returns:
        A list of findings from any 'env' blocks found during the walk.
    """
    findings: list[Finding] = []

    # Skip top-level (handled separately) and already-visited paths
    if len(key_path) == 0:
        # At root level, skip top-level 'env' and server blocks
        skip_keys = {"env", "mcpServers", "servers", "mcp_servers"}
        if isinstance(node, dict):
            for key, value in node.items():
                if key in skip_keys:
                    continue
                findings.extend(
                    _walk_for_env_blocks(value, path, [key], visited_paths)
                )
        return findings

    dotted = ".".join(key_path)

    if dotted in visited_paths:
        return []
    visited_paths.add(dotted)

    if isinstance(node, dict):
        # Check if this dict has an 'env' key that is itself a dict
        env_val = node.get("env")
        if isinstance(env_val, dict) and dotted not in visited_paths:
            # Only report if depth > 1 to avoid re-processing top-level
            if len(key_path) > 1:
                context = dotted + ".env"
                findings.extend(check_env_dict(env_val, path, context=context))

        for key, value in node.items():
            if key == "env":
                continue  # Already handled above
            findings.extend(
                _walk_for_env_blocks(value, path, key_path + [key], visited_paths)
            )

    elif isinstance(node, list):
        for i, item in enumerate(node):
            findings.extend(
                _walk_for_env_blocks(item, path, key_path + [f"[{i}]"], visited_paths)
            )

    return findings


def _check_raw_text_env(content: str, path: Path) -> list[Finding]:
    """Perform raw text scanning for environment injection patterns.

    Looks for shell-export style lines (export VAR=value) and inline
    env assignments in command contexts, which may not be captured by
    structured JSON parsing.

    Args:
        content: The raw text content of the file.
        path: The source file path.

    Returns:
        A list of findings from raw text analysis.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    # Pattern for shell export statements
    export_pattern = re.compile(
        r"(?:^|\s)export\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)",
        re.IGNORECASE,
    )
    # Pattern for bare assignment lines (VAR=value) not in comments
    assignment_pattern = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)",
    )
    # Pattern for env -e or env VAR=val in command strings
    inline_env_pattern = re.compile(
        r'["\']?[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^\s"\',]+',
    )

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Check export statements
        m_export = export_pattern.search(line)
        if m_export:
            var_name = m_export.group(1).upper()
            var_value = m_export.group(2).strip().strip('"\'')

            if var_name == "PATH":
                for finding in _check_path_value(var_value, path, context="shell export"):
                    finding.line_number = line_num
                    finding.evidence = stripped[:200]
                    findings.append(finding)

            elif var_name in _DANGEROUS_ENV_VARS:
                check_id, severity, var_description = _DANGEROUS_ENV_VARS[var_name]
                findings.append(
                    Finding(
                        check_id=check_id,
                        severity=severity,
                        title=f"Dangerous environment variable export: {var_name}",
                        description=(
                            f"Line {line_num} of '{path}' exports the {var_description} "
                            f"'{var_name}'. This may be processed by a shell or script "
                            "runner and could compromise the MCP process environment "
                            "before sandbox initialization."
                        ),
                        file_path=path,
                        line_number=line_num,
                        evidence=stripped[:200],
                        remediation=(
                            f"Remove the export of '{var_name}' from this file. "
                            "Sensitive environment overrides should never appear in "
                            "MCP configuration files."
                        ),
                    )
                )

            # Check for command substitution in the value
            for pattern in _CMD_SUBSTITUTION_PATTERNS:
                cm = pattern.search(var_value)
                if cm:
                    findings.append(
                        Finding(
                            check_id="ENV-011",
                            severity=Severity.CRITICAL,
                            title=f"Command substitution in exported variable {var_name}",
                            description=(
                                f"Line {line_num} of '{path}' exports '{var_name}' with a "
                                f"command substitution pattern ('{cm.group()}'). "
                                "This allows arbitrary command execution at shell expansion "
                                "time, potentially before any sandbox controls are active."
                            ),
                            file_path=path,
                            line_number=line_num,
                            evidence=stripped[:200],
                            remediation=(
                                f"Replace the command substitution in '{var_name}' with "
                                "a static literal value."
                            ),
                        )
                    )
                    break

    return findings


def _check_path_value(
    path_value: str,
    file_path: Path,
    context: str,
) -> list[Finding]:
    """Analyse a PATH environment variable value for suspicious directory prepending.

    The most dangerous form of PATH injection is prepending a world-writable
    or attacker-controlled directory before standard system directories,
    allowing shadowing of system commands (e.g., a malicious 'node' binary).

    Args:
        path_value: The value of the PATH variable.
        file_path: The source file path.
        context: Human-readable location context string.

    Returns:
        A list of findings if PATH manipulation is detected.
    """
    findings: list[Finding] = []

    if not path_value:
        return findings

    # Split PATH by ':' (Unix) or ';' (Windows)
    separator = ";" if ";" in path_value and ":" not in path_value else ":"
    path_entries = [p.strip() for p in path_value.split(separator) if p.strip()]

    if not path_entries:
        return findings

    # Check the first entry (prepend position is most dangerous)
    first_entry = path_entries[0]
    is_suspicious_prefix = any(
        pattern.search(first_entry) for pattern in _SUSPICIOUS_PATH_PREFIXES
    )

    if is_suspicious_prefix:
        findings.append(
            Finding(
                check_id="ENV-001",
                severity=Severity.CRITICAL,
                title="Suspicious directory prepended to PATH",
                description=(
                    f"The PATH variable in '{context}' of '{file_path}' has a "
                    f"suspicious directory ('{first_entry}') prepended to the front. "
                    "Prepending untrusted, world-writable, or relative directories to "
                    "PATH allows command shadowing: a malicious binary named 'node', "
                    "'python', or 'sh' in that directory will be executed instead of "
                    "the legitimate system binary."
                ),
                file_path=file_path,
                evidence=f"PATH in {context} starts with: {first_entry!r}",
                remediation=(
                    "Ensure PATH values in MCP configs only reference absolute, "
                    "trusted system directories. Never prepend relative paths, "
                    "temp directories, or hidden home directories."
                ),
            )
        )

    # Also check all entries for temp/world-writable dirs
    for entry in path_entries:
        for pattern in _TEMP_PATH_PATTERNS:
            if pattern.search(entry):
                # Avoid duplicate if already flagged above
                if entry == first_entry and is_suspicious_prefix:
                    break
                findings.append(
                    Finding(
                        check_id="ENV-007",
                        severity=Severity.HIGH,
                        title="World-writable directory in PATH",
                        description=(
                            f"The PATH variable in '{context}' of '{file_path}' contains "
                            f"a world-writable or temp directory entry ('{entry}'). "
                            "Placing temp directories in PATH allows any user on the "
                            "system to shadow legitimate commands with malicious binaries."
                        ),
                        file_path=file_path,
                        evidence=f"PATH entry: {entry!r}",
                        remediation=(
                            f"Remove '{entry}' from the PATH configuration. "
                            "PATH should only contain trusted, non-world-writable "
                            "system directories."
                        ),
                    )
                )
                break

    # Check for command substitution within PATH value
    for pattern in _CMD_SUBSTITUTION_PATTERNS:
        m = pattern.search(path_value)
        if m:
            findings.append(
                Finding(
                    check_id="ENV-011",
                    severity=Severity.CRITICAL,
                    title="Command substitution in PATH value",
                    description=(
                        f"The PATH variable in '{context}' of '{file_path}' contains a "
                        f"command substitution pattern ('{m.group()}'). This allows "
                        "arbitrary commands to be executed at shell expansion time, "
                        "which may occur before the MCP sandbox is initialized."
                    ),
                    file_path=file_path,
                    evidence=f"PATH = {path_value[:200]!r}",
                    remediation=(
                        "Replace command substitution in PATH with static literal "
                        "directory paths."
                    ),
                )
            )
            break

    return findings


def _make_dangerous_var_finding(
    check_id: str,
    severity: Severity,
    var_name: str,
    var_value: str,
    var_description: str,
    file_path: Path,
    context: str,
) -> Finding:
    """Create a Finding for a known-dangerous environment variable.

    Args:
        check_id: The check identifier to use.
        severity: The severity level for this finding.
        var_name: The environment variable name.
        var_value: The value of the environment variable.
        var_description: A human-readable description of why this var is dangerous.
        file_path: The file path to attribute the finding to.
        context: Human-readable location context string.

    Returns:
        A Finding instance describing the dangerous variable.
    """
    # Truncate long values in evidence
    display_value = var_value[:120] + "..." if len(var_value) > 120 else var_value

    return Finding(
        check_id=check_id,
        severity=severity,
        title=f"Dangerous environment variable: {var_name}",
        description=(
            f"The environment block at '{context}' in '{file_path}' sets '{var_name}', "
            f"a {var_description}. Setting this variable can allow an attacker to "
            f"hijack the MCP server process before sandbox initialization completes, "
            f"enabling library injection, code execution, or privilege escalation."
        ),
        file_path=file_path,
        evidence=f"{context}.{var_name} = {display_value!r}",
        remediation=(
            f"Remove '{var_name}' from the MCP server environment configuration. "
            "If this variable is required for legitimate functionality, document the "
            "justification and ensure the value is strictly controlled and cannot "
            "be influenced by untrusted input."
        ),
        extra={"variable": var_name, "value_preview": display_value},
    )


def _check_value_for_cmd_substitution(
    var_name: str,
    var_value: str,
    file_path: Path,
    context: str,
) -> list[Finding]:
    """Check an environment variable value for command substitution patterns.

    Args:
        var_name: The name of the environment variable.
        var_value: The value string to check.
        file_path: The source file path.
        context: Human-readable location context string.

    Returns:
        A list of findings if command substitution patterns are found.
    """
    findings: list[Finding] = []
    for pattern in _CMD_SUBSTITUTION_PATTERNS:
        m = pattern.search(var_value)
        if m:
            findings.append(
                Finding(
                    check_id="ENV-011",
                    severity=Severity.CRITICAL,
                    title=f"Command substitution in environment variable {var_name}",
                    description=(
                        f"The environment variable '{var_name}' in '{context}' of "
                        f"'{file_path}' contains a command substitution pattern "
                        f"('{m.group()}'). If this configuration is processed by a "
                        "shell or script interpreter, arbitrary commands will be "
                        "executed, potentially before the MCP sandbox is active."
                    ),
                    file_path=file_path,
                    evidence=f"{context}.{var_name} = {var_value[:200]!r}",
                    remediation=(
                        f"Replace the command substitution in '{var_name}' with a "
                        "static literal value. Never use shell expansion in MCP "
                        "environment configurations."
                    ),
                )
            )
            break  # One finding per variable
    return findings


def _check_value_for_temp_paths(
    var_name: str,
    var_value: str,
    file_path: Path,
    context: str,
) -> list[Finding]:
    """Check an environment variable value for temp or world-writable path references.

    Args:
        var_name: The name of the environment variable.
        var_value: The value string to check.
        file_path: The source file path.
        context: Human-readable location context string.

    Returns:
        A list of findings if temp path patterns are found in non-PATH variables.
    """
    findings: list[Finding] = []
    # Skip PATH (handled separately) and skip vars already flagged as dangerous
    if var_name.upper() in ("PATH",) or var_name.upper() in _DANGEROUS_ENV_VARS:
        return findings

    for pattern in _TEMP_PATH_PATTERNS:
        m = pattern.search(var_value)
        if m:
            findings.append(
                Finding(
                    check_id="ENV-007",
                    severity=Severity.MEDIUM,
                    title=f"Temp/world-writable path in environment variable {var_name}",
                    description=(
                        f"The environment variable '{var_name}' in '{context}' of "
                        f"'{file_path}' references a temp or world-writable path "
                        f"('{m.group()}'). If this path is used during MCP server "
                        "initialization, an attacker who can write to that directory "
                        "may be able to influence process behavior."
                    ),
                    file_path=file_path,
                    evidence=f"{context}.{var_name} = {var_value[:200]!r}",
                    remediation=(
                        f"Replace the temp path in '{var_name}' with a stable, "
                        "non-world-writable directory. Ensure the target directory "
                        "has appropriate ownership and permissions."
                    ),
                )
            )
            break  # One finding per variable
    return findings


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on check_id, file path, and evidence.

    Args:
        findings: The list of findings to deduplicate.

    Returns:
        A deduplicated list preserving the first occurrence of each unique finding.
    """
    seen: set[tuple[str, str | None, int | None, str | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (
            finding.check_id,
            str(finding.file_path) if finding.file_path else None,
            finding.line_number,
            finding.evidence[:100] if finding.evidence else None,
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
