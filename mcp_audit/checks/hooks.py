"""Hook injection detector for MCP configuration files.

This module scans MCP server configuration files for suspicious pre-sandbox
lifecycle hooks, pre-initialization execution patterns, and shell-exec
constructs that could be exploited for remote code execution or privilege
escalation.

Inspired by the Gemini CLI RCE vulnerability class where malicious content
in the working directory could be executed before the sandbox is initialized.

Checks performed:
    HOOK-001: Suspicious preExec / pre-init command hook in config
    HOOK-002: Shell execution pattern in lifecycle hook value
    HOOK-003: Dangerous onInit / postInit hook referencing external scripts
    HOOK-004: Startup script references with absolute or relative path traversal
    HOOK-005: Environment setup scripts with potential injection vectors
    HOOK-006: Config contains eval, exec, or dynamic code execution patterns
    HOOK-007: Pre-sandbox hook referencing network resources (curl, wget, etc.)
    HOOK-008: Command substitution patterns in hook values
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_audit.models import Finding, Severity

# ---------------------------------------------------------------------------
# Regex patterns for hook detection
# ---------------------------------------------------------------------------

# Keys in JSON/config structures that suggest lifecycle hooks or pre-init execution
_HOOK_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"pre[_\-]?exec", re.IGNORECASE),
    re.compile(r"pre[_\-]?init", re.IGNORECASE),
    re.compile(r"pre[_\-]?start", re.IGNORECASE),
    re.compile(r"pre[_\-]?run", re.IGNORECASE),
    re.compile(r"pre[_\-]?sandbox", re.IGNORECASE),
    re.compile(r"on[_\-]?init", re.IGNORECASE),
    re.compile(r"on[_\-]?start", re.IGNORECASE),
    re.compile(r"on[_\-]?load", re.IGNORECASE),
    re.compile(r"post[_\-]?init", re.IGNORECASE),
    re.compile(r"startup[_\-]?script", re.IGNORECASE),
    re.compile(r"init[_\-]?script", re.IGNORECASE),
    re.compile(r"bootstrap", re.IGNORECASE),
    re.compile(r"prologue", re.IGNORECASE),
    re.compile(r"lifecycle", re.IGNORECASE),
    re.compile(r"hooks?", re.IGNORECASE),
    re.compile(r"setup[_\-]?cmd", re.IGNORECASE),
    re.compile(r"setup[_\-]?command", re.IGNORECASE),
    re.compile(r"before[_\-]?start", re.IGNORECASE),
]

# Dangerous shell patterns that indicate shell execution within hook values
_SHELL_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsh\s+-c\b"),
    re.compile(r"\bbash\s+-c\b"),
    re.compile(r"\bzsh\s+-c\b"),
    re.compile(r"\bpowersh(ell)?\b", re.IGNORECASE),
    re.compile(r"\bcmd\.exe\b", re.IGNORECASE),
    re.compile(r"\beval\s*[\'\"(]"),
    re.compile(r"\bexec\s*[\'\"(]"),
    re.compile(r"\bsystem\s*\("),
    re.compile(r"\bspawn\s*\("),
    re.compile(r"\bpopen\s*\("),
    re.compile(r"\bsubprocess\.\w+"),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bchild_process\.exec"),
    re.compile(r"\brequire\s*\(\s*['"]child_process['"]"),
]

# Command substitution patterns (shell injection vectors)
_CMD_SUBSTITUTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\([^)]+\)"),          # $(command)
    re.compile(r"`[^`]+`"),              # `command`
    re.compile(r"\$\{[^}]+\}"),         # ${variable} - can be exploited
    re.compile(r"<\([^)]+\)"),           # <(process substitution)
]

# Network fetch patterns that indicate remote code execution risk
_NETWORK_FETCH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bcurl\b"),
    re.compile(r"\bwget\b"),
    re.compile(r"\bfetch\b"),
    re.compile(r"\bhttp[s]?://"),
    re.compile(r"\bftp://"),
    re.compile(r"\baxios\.get"),
    re.compile(r"\bnode-fetch"),
    re.compile(r"\bpython\s+-c.*urllib"),
    re.compile(r"\bpython\s+-c.*requests"),
    re.compile(r"\bnpm.*install.*--no-save"),
    re.compile(r"\bpip\s+install"),
]

# Path traversal / dangerous absolute paths in hook values
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./"),                           # relative traversal
    re.compile(r"\.\.\\\\?"),                       # Windows traversal
    re.compile(r"/tmp/"),                           # temp directory scripts
    re.compile(r"/var/tmp/"),
    re.compile(r"C:\\\\?[Tt]emp\\"),              # Windows temp
    re.compile(r"\$TMPDIR"),
    re.compile(r"\$HOME/\.config"),
    re.compile(r"\$XDG_CONFIG_HOME"),
]

# Dynamic code execution patterns
_DYNAMIC_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\beval\b"),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bFunction\s*\("),
    re.compile(r"__import__\s*\("),
    re.compile(r"importlib\.import_module"),
    re.compile(r"\bcompile\s*\("),
    re.compile(r"\bexecfile\s*\("),
    re.compile(r"\brunpy"),
    re.compile(r"\bnode\s+-e\b"),
    re.compile(r"\bpython\s+-c\b"),
    re.compile(r"\bruby\s+-e\b"),
    re.compile(r"\bperl\s+-e\b"),
]

# Suspicious MCP server 'command' patterns (the main server command field)
_SUSPICIOUS_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsh\b"),
    re.compile(r"\bbash\b"),
    re.compile(r"\bzsh\b"),
    re.compile(r"\bcmd\.exe\b", re.IGNORECASE),
    re.compile(r"\bpowersh", re.IGNORECASE),
]


def check_file(path: Path) -> list[Finding]:
    """Check a single configuration file for suspicious hook patterns.

    Attempts to parse the file as JSON and then performs structural analysis
    on the parsed content. Also performs raw text-based pattern matching
    regardless of whether JSON parsing succeeds.

    Args:
        path: Path to the configuration file to analyze.

    Returns:
        A list of Finding instances for all hook-related issues detected.
        Returns an empty list if the file does not exist or cannot be read.
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
        findings.extend(_check_json_structure(parsed, path))
        findings.extend(_check_mcp_servers_block(parsed, path))

    # Always do raw text analysis
    findings.extend(_check_raw_text(raw_content, path))

    # Deduplicate by (check_id, evidence) pairs
    findings = _deduplicate_findings(findings)

    return findings


def check_files(paths: list[Path]) -> list[Finding]:
    """Run hook checks on multiple configuration files.

    Args:
        paths: A list of file paths to check.

    Returns:
        A combined list of all findings across all provided files.
    """
    findings: list[Finding] = []
    for path in paths:
        findings.extend(check_file(path))
    return findings


def _check_json_structure(config: dict[str, Any], path: Path) -> list[Finding]:
    """Recursively scan a parsed JSON structure for hook key patterns.

    Args:
        config: The parsed JSON configuration dictionary.
        path: The source file path (for reporting).

    Returns:
        A list of findings from structural analysis.
    """
    findings: list[Finding] = []
    _walk_json(config, path, findings, key_path=[])
    return findings


def _walk_json(
    node: Any,
    path: Path,
    findings: list[Finding],
    key_path: list[str],
) -> None:
    """Recursively walk a JSON node and check keys and values for hook patterns.

    Args:
        node: The current JSON node (dict, list, or scalar).
        path: The source file path.
        findings: The list to append findings to.
        key_path: The list of parent keys forming the path to this node.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            current_path = key_path + [key]

            # Check if this key matches a suspicious hook key pattern
            if _matches_hook_key(key):
                findings.extend(
                    _analyze_hook_value(key, value, current_path, path)
                )

            # Continue walking
            _walk_json(value, path, findings, current_path)

    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_json(item, path, findings, key_path + [f"[{i}]"])


def _check_mcp_servers_block(config: dict[str, Any], path: Path) -> list[Finding]:
    """Check the 'mcpServers' block specifically for MCP config files.

    MCP configuration files typically have a top-level 'mcpServers' key
    mapping server names to server definitions. This function checks each
    server definition for suspicious command and args patterns.

    Args:
        config: The parsed top-level configuration dictionary.
        path: The source file path.

    Returns:
        A list of findings from MCP server block analysis.
    """
    findings: list[Finding] = []

    # Support both 'mcpServers' (Claude Desktop) and 'servers' (generic)
    for block_key in ("mcpServers", "servers", "mcp_servers"):
        servers_block = config.get(block_key)
        if not isinstance(servers_block, dict):
            continue

        for server_name, server_def in servers_block.items():
            if not isinstance(server_def, dict):
                continue

            findings.extend(
                _check_server_definition(server_name, server_def, path, block_key)
            )

    return findings


def _check_server_definition(
    server_name: str,
    server_def: dict[str, Any],
    path: Path,
    block_key: str,
) -> list[Finding]:
    """Analyze a single MCP server definition for security issues.

    Args:
        server_name: The name/key of the server in the config.
        server_def: The server definition dictionary.
        path: The source file path.
        block_key: The parent key (e.g., 'mcpServers').

    Returns:
        A list of findings from server definition analysis.
    """
    findings: list[Finding] = []
    command = server_def.get("command", "")
    args = server_def.get("args", [])

    if not isinstance(command, str):
        command = str(command)
    if not isinstance(args, list):
        args = []

    # Check if the command itself is a shell (highly suspicious)
    for pattern in _SUSPICIOUS_COMMAND_PATTERNS:
        if pattern.search(command):
            full_cmd = command + " " + " ".join(str(a) for a in args)
            findings.append(
                Finding(
                    check_id="HOOK-001",
                    severity=Severity.CRITICAL,
                    title=f"MCP server '{server_name}' uses shell as command",
                    description=(
                        f"The MCP server '{server_name}' in '{path}' is configured to "
                        f"run a shell ('{command}') directly as its command. This allows "
                        "arbitrary shell code execution and bypasses sandboxing, creating "
                        "a pre-initialization injection vector."
                    ),
                    file_path=path,
                    evidence=f"{block_key}.{server_name}.command = {full_cmd!r}",
                    remediation=(
                        "Replace shell commands with direct executable invocations. "
                        "Avoid 'sh -c', 'bash -c', or similar shell wrappers in MCP server "
                        "command definitions."
                    ),
                )
            )
            break

    # Check args for shell injection patterns
    all_args_str = " ".join(str(a) for a in args)
    if args:
        for pattern in _SHELL_EXEC_PATTERNS:
            m = pattern.search(all_args_str)
            if m:
                findings.append(
                    Finding(
                        check_id="HOOK-002",
                        severity=Severity.HIGH,
                        title=f"Shell execution pattern in MCP server '{server_name}' args",
                        description=(
                            f"The args for MCP server '{server_name}' in '{path}' contain "
                            f"a shell execution pattern ('{m.group()}')."
                            " This may allow command injection when the server is started."
                        ),
                        file_path=path,
                        evidence=f"{block_key}.{server_name}.args = {args!r}",
                        remediation=(
                            "Avoid shell execution patterns in MCP server args. "
                            "Use explicit argument lists without shell evaluation."
                        ),
                    )
                )
                break

        # Check for command substitution in args
        for pattern in _CMD_SUBSTITUTION_PATTERNS:
            m = pattern.search(all_args_str)
            if m:
                findings.append(
                    Finding(
                        check_id="HOOK-008",
                        severity=Severity.HIGH,
                        title=f"Command substitution in MCP server '{server_name}' args",
                        description=(
                            f"The args for MCP server '{server_name}' in '{path}' contain "
                            f"a command substitution pattern ('{m.group()}'). "
                            "Command substitution allows arbitrary code execution at "
                            "shell expansion time, before the server sandbox is active."
                        ),
                        file_path=path,
                        evidence=f"{block_key}.{server_name}.args contains: {m.group()!r}",
                        remediation=(
                            "Remove command substitution patterns from server args. "
                            "Use literal values only."
                        ),
                    )
                )
                break

        # Check for network fetch in args (RCE via remote script)
        for pattern in _NETWORK_FETCH_PATTERNS:
            m = pattern.search(all_args_str)
            if m:
                findings.append(
                    Finding(
                        check_id="HOOK-007",
                        severity=Severity.CRITICAL,
                        title=f"Network fetch in MCP server '{server_name}' args",
                        description=(
                            f"The args for MCP server '{server_name}' in '{path}' reference "
                            f"a network resource or fetch command ('{m.group()}'). "
                            "Fetching and executing remote content during server initialization "
                            "is a critical supply-chain and RCE risk."
                        ),
                        file_path=path,
                        evidence=f"{block_key}.{server_name}.args contains: {m.group()!r}",
                        remediation=(
                            "Never fetch or execute remote scripts during MCP server startup. "
                            "Use pre-downloaded, integrity-verified local scripts."
                        ),
                    )
                )
                break

    return findings


def _analyze_hook_value(
    key: str,
    value: Any,
    key_path: list[str],
    file_path: Path,
) -> list[Finding]:
    """Analyze the value of a detected hook key for dangerous patterns.

    Args:
        key: The configuration key that matched a hook pattern.
        value: The associated value (may be a string, list, dict, etc.).
        key_path: The full key path from the root of the config.
        file_path: The source file path.

    Returns:
        A list of findings from analyzing the hook value.
    """
    findings: list[Finding] = []
    path_str = ".".join(key_path)

    # Normalize the value to a string for pattern matching
    if isinstance(value, str):
        value_str = value
    elif isinstance(value, (list, dict)):
        value_str = json.dumps(value)
    elif value is None:
        return []
    else:
        value_str = str(value)

    if not value_str.strip():
        return []

    # Check for shell execution in hook value
    for pattern in _SHELL_EXEC_PATTERNS:
        m = pattern.search(value_str)
        if m:
            findings.append(
                Finding(
                    check_id="HOOK-002",
                    severity=Severity.HIGH,
                    title=f"Shell execution pattern in hook '{key}'",
                    description=(
                        f"The lifecycle hook '{path_str}' in '{file_path}' contains a "
                        f"shell execution pattern ('{m.group()}'). This hook may execute "
                        "arbitrary shell commands before the MCP sandbox is initialized."
                    ),
                    file_path=file_path,
                    evidence=f"{path_str} = {value_str[:200]!r}",
                    remediation=(
                        f"Review and sanitize the hook at '{path_str}'. "
                        "Avoid shell execution patterns in lifecycle hooks."
                    ),
                )
            )
            break

    # Check for network fetch in hook value
    for pattern in _NETWORK_FETCH_PATTERNS:
        m = pattern.search(value_str)
        if m:
            findings.append(
                Finding(
                    check_id="HOOK-007",
                    severity=Severity.CRITICAL,
                    title=f"Network resource reference in hook '{key}'",
                    description=(
                        f"The lifecycle hook '{path_str}' in '{file_path}' references a "
                        f"network resource or fetch command ('{m.group()}'). "
                        "Pre-sandbox hooks that fetch remote content enable remote code "
                        "execution before any security controls are active."
                    ),
                    file_path=file_path,
                    evidence=f"{path_str} = {value_str[:200]!r}",
                    remediation=(
                        "Remove network fetch operations from lifecycle hooks. "
                        "All scripts must be local and integrity-verified."
                    ),
                )
            )
            break

    # Check for path traversal in hook value
    for pattern in _PATH_TRAVERSAL_PATTERNS:
        m = pattern.search(value_str)
        if m:
            findings.append(
                Finding(
                    check_id="HOOK-004",
                    severity=Severity.MEDIUM,
                    title=f"Suspicious path in hook '{key}'",
                    description=(
                        f"The lifecycle hook '{path_str}' in '{file_path}' references a "
                        f"suspicious path pattern ('{m.group()}'). Path traversal or "
                        "references to temp directories in hooks may indicate an attempt "
                        "to execute untrusted scripts."
                    ),
                    file_path=file_path,
                    evidence=f"{path_str} = {value_str[:200]!r}",
                    remediation=(
                        "Ensure hook scripts use absolute, well-known paths and do not "
                        "traverse directory boundaries or reference temp directories."
                    ),
                )
            )
            break

    # Check for dynamic code execution
    for pattern in _DYNAMIC_EXEC_PATTERNS:
        m = pattern.search(value_str)
        if m:
            findings.append(
                Finding(
                    check_id="HOOK-006",
                    severity=Severity.HIGH,
                    title=f"Dynamic code execution in hook '{key}'",
                    description=(
                        f"The lifecycle hook '{path_str}' in '{file_path}' contains a "
                        f"dynamic code execution pattern ('{m.group()}'). Dynamic execution "
                        "(eval, exec, new Function, etc.) can be used to run arbitrary "
                        "code injected through configuration."
                    ),
                    file_path=file_path,
                    evidence=f"{path_str} = {value_str[:200]!r}",
                    remediation=(
                        "Avoid eval, exec, new Function, or similar dynamic execution "
                        "constructs in lifecycle hooks."
                    ),
                )
            )
            break

    # Check for command substitution
    for pattern in _CMD_SUBSTITUTION_PATTERNS:
        m = pattern.search(value_str)
        if m:
            findings.append(
                Finding(
                    check_id="HOOK-008",
                    severity=Severity.HIGH,
                    title=f"Command substitution in hook '{key}'",
                    description=(
                        f"The lifecycle hook '{path_str}' in '{file_path}' contains a "
                        f"command substitution pattern ('{m.group()}'). Command substitution "
                        "allows arbitrary code to be executed at shell expansion time, "
                        "before sandboxing takes effect."
                    ),
                    file_path=file_path,
                    evidence=f"{path_str} = {value_str[:200]!r}",
                    remediation=(
                        "Remove command substitution syntax ($(...), `...`) from hook values."
                    ),
                )
            )
            break

    # If the hook value is non-empty and none of the above matched,
    # still flag the presence of a hook key as informational
    if not findings:
        findings.append(
            Finding(
                check_id="HOOK-003",
                severity=Severity.LOW,
                title=f"Lifecycle hook detected: '{key}'",
                description=(
                    f"A lifecycle hook key '{path_str}' was found in '{file_path}'. "
                    "While no immediately dangerous patterns were detected, lifecycle "
                    "hooks execute at server startup and should be reviewed to ensure "
                    "they do not introduce pre-sandbox injection risks."
                ),
                file_path=file_path,
                evidence=f"{path_str} = {value_str[:200]!r}",
                remediation=(
                    f"Review the hook at '{path_str}' to confirm it is trusted, "
                    "minimal, and cannot be influenced by untrusted input."
                ),
            )
        )

    return findings


def _check_raw_text(content: str, path: Path) -> list[Finding]:
    """Perform raw text-based pattern matching for hook injection risks.

    This analysis is format-agnostic and works on any text file, supplementing
    the structural JSON analysis.

    Args:
        content: The raw text content of the file.
        path: The source file path.

    Returns:
        A list of findings from raw text analysis.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        # Check for command substitution in any line
        for pattern in _CMD_SUBSTITUTION_PATTERNS:
            m = pattern.search(line)
            if m:
                findings.append(
                    Finding(
                        check_id="HOOK-008",
                        severity=Severity.HIGH,
                        title="Command substitution pattern detected",
                        description=(
                            f"Line {line_num} of '{path}' contains a command substitution "
                            f"pattern ('{m.group()}'). If this is processed by a shell or "
                            "script runner, it may execute arbitrary commands before the "
                            "MCP sandbox is active."
                        ),
                        file_path=path,
                        line_number=line_num,
                        evidence=line.strip()[:200],
                        remediation=(
                            "Remove command substitution patterns from configuration files. "
                            "Use static literal values only."
                        ),
                    )
                )
                break

        # Check for network fetch patterns in suspicious contexts
        _check_line_for_network_fetch(line, line_num, path, findings)

    return findings


def _check_line_for_network_fetch(
    line: str,
    line_num: int,
    path: Path,
    findings: list[Finding],
) -> None:
    """Check a single line for network fetch patterns in command contexts.

    Only flags network fetch patterns when they appear adjacent to execution
    keywords to reduce false positives.

    Args:
        line: The line content to check.
        line_num: The 1-based line number.
        path: The source file path.
        findings: The list to append findings to.
    """
    # Only flag curl/wget if they appear in what looks like a command value
    exec_context = re.search(
        r'["\']?(?:command|cmd|exec|run|script|hook)["\']?\s*[:=]',
        line,
        re.IGNORECASE,
    )
    if not exec_context:
        return

    for pattern in _NETWORK_FETCH_PATTERNS:
        m = pattern.search(line)
        if m:
            findings.append(
                Finding(
                    check_id="HOOK-007",
                    severity=Severity.CRITICAL,
                    title="Network fetch in command/hook context",
                    description=(
                        f"Line {line_num} of '{path}' contains a network fetch operation "
                        f"('{m.group()}') within a command or hook context. "
                        "Fetching remote content during server initialization is a "
                        "critical remote code execution risk."
                    ),
                    file_path=path,
                    line_number=line_num,
                    evidence=line.strip()[:200],
                    remediation=(
                        "Remove network fetch operations from command and hook definitions. "
                        "Never execute remotely fetched scripts during MCP initialization."
                    ),
                )
            )
            break


def _matches_hook_key(key: str) -> bool:
    """Check if a configuration key matches any known hook key pattern.

    Args:
        key: The configuration key string to check.

    Returns:
        True if the key matches any hook key pattern.
    """
    return any(pattern.search(key) for pattern in _HOOK_KEY_PATTERNS)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on check_id, file, line, and evidence.

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
