"""Permission checker for MCP configuration files and directories.

This module inspects file and directory permission bits to detect overly
permissive or dangerous configurations. It checks for world-writable files,
group-writable files, and files owned by unexpected users that could allow
unauthorized modification of MCP server configurations.

Checks performed:
    PERM-001: World-writable file or directory
    PERM-002: Group-writable config file
    PERM-003: World-readable file containing sensitive keys/secrets
    PERM-004: Sticky bit missing on world-writable directory
    PERM-005: Config file owned by root but writable by current user
    PERM-006: Permissions too permissive (more than 0o644 for files)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Sequence

from mcp_audit.models import Finding, Severity

# Bitmasks for permission checks
_WORLD_WRITE = stat.S_IWOTH  # 0o002
_WORLD_READ = stat.S_IROTH   # 0o004
_GROUP_WRITE = stat.S_IWGRP  # 0o020
_STICKY = stat.S_ISVTX       # 0o1000
_EXEC_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH  # 0o111

# Maximum acceptable permission mode for regular config files
_MAX_FILE_MODE = 0o644
# Maximum acceptable permission mode for directories
_MAX_DIR_MODE = 0o755

# Patterns that suggest a file may contain sensitive data
_SENSITIVE_FILENAME_PATTERNS = (
    "secret",
    "token",
    "credential",
    "password",
    "passwd",
    "key",
    "auth",
    "private",
    "cert",
    ".env",
)


def check_path(path: Path) -> list[Finding]:
    """Run all permission checks on a given file or directory path.

    This is the primary entry point for the permissions checker. It dispatches
    to individual check functions and aggregates their results.

    Args:
        path: The file system path to check. Can be a file or directory.

    Returns:
        A list of Finding instances for all permission issues detected.
        Returns an empty list if no issues are found or if the path does
        not exist.
    """
    if not path.exists():
        return []

    findings: list[Finding] = []

    try:
        st = path.stat()
    except OSError:
        return []

    mode = st.st_mode

    if path.is_dir():
        findings.extend(_check_directory_permissions(path, mode, st))
    else:
        findings.extend(_check_file_permissions(path, mode, st))

    return findings


def check_paths(paths: Sequence[Path]) -> list[Finding]:
    """Run permission checks on multiple paths.

    Args:
        paths: A sequence of file system paths to check.

    Returns:
        A combined list of all findings across all provided paths.
    """
    findings: list[Finding] = []
    for path in paths:
        findings.extend(check_path(path))
    return findings


def _check_file_permissions(path: Path, mode: int, st: os.stat_result) -> list[Finding]:
    """Run all file-specific permission checks.

    Args:
        path: The file path being checked.
        mode: The raw stat mode bits for the file.
        st: The full os.stat_result for the file.

    Returns:
        A list of findings for file permission issues.
    """
    findings: list[Finding] = []
    file_mode = stat.S_IMODE(mode)

    # PERM-001: World-writable file
    if file_mode & _WORLD_WRITE:
        findings.append(
            Finding(
                check_id="PERM-001",
                severity=Severity.CRITICAL,
                title="World-writable config file detected",
                description=(
                    f"The file '{path}' is world-writable (mode {oct(file_mode)}). "
                    "Any user on the system can modify this MCP configuration file, "
                    "which could allow injection of malicious server definitions, "
                    "environment variables, or pre-init hooks."
                ),
                file_path=path,
                evidence=f"File mode: {oct(file_mode)}",
                remediation=(
                    f"Remove world-write permission: chmod o-w '{path}'. "
                    f"Recommended mode for config files is 0o644 or stricter."
                ),
            )
        )

    # PERM-002: Group-writable config file
    if file_mode & _GROUP_WRITE:
        findings.append(
            Finding(
                check_id="PERM-002",
                severity=Severity.HIGH,
                title="Group-writable config file detected",
                description=(
                    f"The file '{path}' is group-writable (mode {oct(file_mode)}). "
                    "Any member of the file's group can modify this MCP configuration, "
                    "potentially injecting malicious content."
                ),
                file_path=path,
                evidence=f"File mode: {oct(file_mode)}",
                remediation=(
                    f"Remove group-write permission: chmod g-w '{path}'. "
                    "Recommended mode for config files is 0o644 or stricter."
                ),
            )
        )

    # PERM-003: World-readable sensitive file
    if (file_mode & _WORLD_READ) and _is_sensitive_filename(path):
        findings.append(
            Finding(
                check_id="PERM-003",
                severity=Severity.HIGH,
                title="World-readable sensitive config file",
                description=(
                    f"The file '{path}' appears to contain sensitive data (based on "
                    f"filename) and is world-readable (mode {oct(file_mode)}). "
                    "Secrets, tokens, or credentials in this file are accessible "
                    "to all users on the system."
                ),
                file_path=path,
                evidence=f"File mode: {oct(file_mode)}, filename suggests sensitive content",
                remediation=(
                    f"Restrict read access: chmod o-r '{path}'. "
                    "Sensitive config files should be readable only by the owning user (0o600)."
                ),
            )
        )

    # PERM-005: Config file owned by root but writable by current user
    if _is_root_owned_but_user_writable(st, file_mode):
        findings.append(
            Finding(
                check_id="PERM-005",
                severity=Severity.HIGH,
                title="Root-owned config file writable by current user",
                description=(
                    f"The file '{path}' is owned by root (uid=0) but is writable by "
                    f"the current user (mode {oct(file_mode)}). This configuration "
                    "asymmetry may indicate a privilege escalation risk or misconfiguration "
                    "where a privileged process reads a user-modifiable file."
                ),
                file_path=path,
                evidence=f"Owner UID: {st.st_uid}, File mode: {oct(file_mode)}",
                remediation=(
                    "Ensure root-owned config files are not writable by unprivileged users. "
                    f"Run: chmod go-w '{path}'"
                ),
                extra={"owner_uid": st.st_uid, "current_uid": os.getuid()},
            )
        )

    # PERM-006: Overly permissive file (more than 0o644)
    if file_mode > _MAX_FILE_MODE and not (file_mode & _WORLD_WRITE) and not (file_mode & _GROUP_WRITE):
        # Only flag this if we haven't already caught more specific issues above
        # and the excess permissions are execution bits
        if file_mode & _EXEC_BITS:
            findings.append(
                Finding(
                    check_id="PERM-006",
                    severity=Severity.MEDIUM,
                    title="Config file has executable permission bits set",
                    description=(
                        f"The file '{path}' has executable bits set (mode {oct(file_mode)}). "
                        "Configuration files should not be executable. An executable config "
                        "file could be mistakenly invoked as a script or exploit a vulnerability "
                        "in a tool that respects the executable bit."
                    ),
                    file_path=path,
                    evidence=f"File mode: {oct(file_mode)}",
                    remediation=(
                        f"Remove executable bits: chmod a-x '{path}'. "
                        "Config files should typically have mode 0o644."
                    ),
                )
            )

    return findings


def _check_directory_permissions(path: Path, mode: int, st: os.stat_result) -> list[Finding]:
    """Run all directory-specific permission checks.

    Args:
        path: The directory path being checked.
        mode: The raw stat mode bits for the directory.
        st: The full os.stat_result for the directory.

    Returns:
        A list of findings for directory permission issues.
    """
    findings: list[Finding] = []
    dir_mode = stat.S_IMODE(mode)

    # PERM-001: World-writable directory
    if dir_mode & _WORLD_WRITE:
        # PERM-004: World-writable without sticky bit is especially dangerous
        if not (dir_mode & _STICKY):
            findings.append(
                Finding(
                    check_id="PERM-004",
                    severity=Severity.CRITICAL,
                    title="World-writable directory without sticky bit",
                    description=(
                        f"The directory '{path}' is world-writable and lacks the sticky bit "
                        f"(mode {oct(dir_mode)}). Without the sticky bit, any user can delete "
                        "or replace files owned by other users in this directory, allowing "
                        "replacement of MCP config files with malicious versions."
                    ),
                    file_path=path,
                    evidence=f"Directory mode: {oct(dir_mode)}",
                    remediation=(
                        f"Add sticky bit or remove world-write: chmod o-w '{path}' "
                        f"OR chmod +t '{path}'. "
                        "MCP config directories should not be world-writable."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="PERM-001",
                    severity=Severity.HIGH,
                    title="World-writable config directory (sticky bit set)",
                    description=(
                        f"The directory '{path}' is world-writable (mode {oct(dir_mode)}). "
                        "Although the sticky bit is set (preventing file deletion by non-owners), "
                        "any user can still create new files in this directory, potentially "
                        "introducing malicious config files."
                    ),
                    file_path=path,
                    evidence=f"Directory mode: {oct(dir_mode)}",
                    remediation=(
                        f"Remove world-write permission: chmod o-w '{path}'. "
                        "MCP config directories should have mode 0o755 or stricter."
                    ),
                )
            )

    # PERM-002: Group-writable directory
    elif dir_mode & _GROUP_WRITE:
        findings.append(
            Finding(
                check_id="PERM-002",
                severity=Severity.MEDIUM,
                title="Group-writable config directory",
                description=(
                    f"The directory '{path}' is group-writable (mode {oct(dir_mode)}). "
                    "Members of the directory's group can create, modify, or delete files "
                    "within this MCP configuration directory."
                ),
                file_path=path,
                evidence=f"Directory mode: {oct(dir_mode)}",
                remediation=(
                    f"Remove group-write permission: chmod g-w '{path}'. "
                    "Config directories should have mode 0o755 or stricter."
                ),
            )
        )

    return findings


def _is_sensitive_filename(path: Path) -> bool:
    """Check if the filename suggests the file contains sensitive data.

    Args:
        path: The file path to check.

    Returns:
        True if the filename contains any sensitive keyword patterns.
    """
    name_lower = path.name.lower()
    return any(pattern in name_lower for pattern in _SENSITIVE_FILENAME_PATTERNS)


def _is_root_owned_but_user_writable(st: os.stat_result, file_mode: int) -> bool:
    """Check if a file is owned by root but writable by the current user.

    Args:
        st: The os.stat_result for the file.
        file_mode: The permission bits (from stat.S_IMODE).

    Returns:
        True if the file is root-owned but writable by the current (non-root) user.
    """
    try:
        current_uid = os.getuid()
    except AttributeError:
        # Windows does not have getuid
        return False

    # Only relevant when the current user is not root
    if current_uid == 0:
        return False

    # File must be owned by root
    if st.st_uid != 0:
        return False

    # Check if world-writable (any user can write) or group-writable and user is in the group
    if file_mode & _WORLD_WRITE:
        return True

    if file_mode & _GROUP_WRITE:
        try:
            import grp
            current_groups = os.getgroups()
            file_gid = st.st_gid
            if file_gid in current_groups:
                return True
        except (ImportError, OSError):
            pass

    return False
