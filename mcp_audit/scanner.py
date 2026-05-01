"""Core scanner orchestration for mcp_audit.

This module provides the main scanning engine that walks MCP configuration
files and startup directories, dispatches findings to all registered checker
modules, and aggregates the results into a unified AuditReport.

The scanner is designed to be:
- Format-aware: detects and prioritises known MCP config file formats
- Extensible: checkers are dispatched via a simple list of callables
- Non-destructive: all filesystem access is read-only
- Error-resilient: individual file scan failures do not abort the entire run
- CI-friendly: exit codes are derived from finding severities

Typical usage::

    from pathlib import Path
    from mcp_audit.scanner import scan

    report = scan(Path("/home/user/.config/claude"))
    print(report)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable

from mcp_audit.checks import env_injection, hooks, permissions, supply_chain
from mcp_audit.models import AuditReport, Finding

# ---------------------------------------------------------------------------
# Known MCP / AI agent configuration file names and directories
# ---------------------------------------------------------------------------

#: File names that are recognised as MCP server configuration files.
#: These receive the full suite of checks (permissions, hooks, env, supply chain).
MCP_CONFIG_FILENAMES: frozenset[str] = frozenset({
    # Claude Desktop (Anthropic)
    "claude_desktop_config.json",
    # Cursor IDE
    "cursor_mcp.json",
    ".cursor/mcp.json",
    "mcp.json",
    # Windsurf / Codeium
    "windsurf_mcp.json",
    # Generic MCP config names
    "mcp_config.json",
    "mcp-config.json",
    ".mcp.json",
    "mcp-servers.json",
    # VS Code / Copilot workspace configs that may embed MCP
    ".vscode/settings.json",
    "settings.json",
})

#: Directories commonly used to store MCP / AI agent configurations.
#: The scanner will search these locations relative to the scan target.
WELL_KNOWN_CONFIG_DIRS: tuple[str, ...] = (
    # Claude Desktop
    ".config/claude",
    "Library/Application Support/Claude",           # macOS
    "AppData/Roaming/Claude",                        # Windows
    # Cursor
    ".cursor",
    # Windsurf
    ".windsurf",
    # Generic MCP
    ".mcp",
    ".config/mcp",
)

#: Supply-chain manifest file names that are scanned when encountered.
SUPPLY_CHAIN_FILENAMES: frozenset[str] = frozenset({
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    ".npmrc",
    "pip.conf",
    "pip.ini",
    "setup.cfg",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
})

#: Maximum directory recursion depth during scanning.
_MAX_DEPTH: int = 8

#: Maximum file size (bytes) to read for content-based checks.
#: Files larger than this are skipped for content analysis but still
#: receive permission checks.
_MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MiB

#: Directories that should never be recursed into.
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    ".npm",
    ".yarn",
    "dist",
    "build",
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
})


# ---------------------------------------------------------------------------
# Checker type alias
# ---------------------------------------------------------------------------

#: A checker callable: takes a Path, returns a list of Finding instances.
CheckerFunc = Callable[[Path], list[Finding]]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(
    target: Path,
    *,
    recursive: bool = True,
    max_depth: int = _MAX_DEPTH,
    include_supply_chain: bool = True,
    include_permissions: bool = True,
    include_hooks: bool = True,
    include_env_injection: bool = True,
    follow_symlinks: bool = False,
) -> AuditReport:
    """Run a full security audit on an MCP configuration target.

    The target may be:
    - A single file: the file is checked directly with all applicable checkers.
    - A directory: the directory is walked recursively (up to ``max_depth``)
      and all discovered config and manifest files are checked.

    Args:
        target: The file or directory path to audit.
        recursive: If True and target is a directory, walk subdirectories
            recursively up to ``max_depth`` levels deep. Defaults to True.
        max_depth: Maximum recursion depth when walking directories.
            Defaults to 8.
        include_supply_chain: If False, skip supply chain checks entirely.
            Defaults to True.
        include_permissions: If False, skip permission checks entirely.
            Defaults to True.
        include_hooks: If False, skip hook injection checks entirely.
            Defaults to True.
        include_env_injection: If False, skip environment variable injection
            checks entirely. Defaults to True.
        follow_symlinks: If True, follow symbolic links during directory
            traversal. Defaults to False (safer).

    Returns:
        An AuditReport aggregating all findings, scanned file paths, and
        any non-fatal errors encountered during the scan.
    """
    target = target.resolve()
    report = AuditReport(scan_target=target)

    try:
        if target.is_file():
            _scan_single_file(
                path=target,
                report=report,
                include_supply_chain=include_supply_chain,
                include_permissions=include_permissions,
                include_hooks=include_hooks,
                include_env_injection=include_env_injection,
            )
        elif target.is_dir():
            _scan_directory(
                directory=target,
                report=report,
                recursive=recursive,
                max_depth=max_depth,
                include_supply_chain=include_supply_chain,
                include_permissions=include_permissions,
                include_hooks=include_hooks,
                include_env_injection=include_env_injection,
                follow_symlinks=follow_symlinks,
                current_depth=0,
                visited_inodes=set(),
            )
        else:
            report.add_error(
                f"Target '{target}' does not exist or is not a file/directory."
            )
    except PermissionError as exc:
        report.add_error(f"Permission denied accessing target '{target}': {exc}")
    except OSError as exc:
        report.add_error(f"OS error while scanning '{target}': {exc}")
    finally:
        report.mark_finished()

    return report


def scan_file(
    path: Path,
    *,
    include_supply_chain: bool = True,
    include_permissions: bool = True,
    include_hooks: bool = True,
    include_env_injection: bool = True,
) -> AuditReport:
    """Convenience wrapper to scan a single file and return an AuditReport.

    Args:
        path: The file path to audit.
        include_supply_chain: Include supply chain checks.
        include_permissions: Include permission checks.
        include_hooks: Include hook injection checks.
        include_env_injection: Include environment injection checks.

    Returns:
        An AuditReport for the single file.
    """
    return scan(
        path,
        recursive=False,
        include_supply_chain=include_supply_chain,
        include_permissions=include_permissions,
        include_hooks=include_hooks,
        include_env_injection=include_env_injection,
    )


def discover_mcp_configs(base: Path) -> list[Path]:
    """Discover MCP configuration files starting from a base directory.

    Checks both the base directory itself and known well-known sub-paths
    (e.g., ``~/.config/claude``, ``~/.cursor``) relative to the base.

    Args:
        base: The base directory to search. Typically the user home directory
            or the project root.

    Returns:
        A sorted list of unique, existing MCP configuration file paths.
        Returns an empty list if the base does not exist or is not a directory.
    """
    if not base.exists() or not base.is_dir():
        return []

    found: set[Path] = set()

    # Check well-known config dirs relative to the base
    for rel_dir in WELL_KNOWN_CONFIG_DIRS:
        config_dir = base / rel_dir
        if config_dir.exists() and config_dir.is_dir():
            for fname in MCP_CONFIG_FILENAMES:
                candidate = config_dir / Path(fname).name
                if candidate.exists() and candidate.is_file():
                    found.add(candidate.resolve())

    # Also walk the base directory shallowly for direct config file hits
    try:
        for child in base.iterdir():
            if child.is_file() and child.name.lower() in {
                n.lower() for n in MCP_CONFIG_FILENAMES
            }:
                found.add(child.resolve())
    except PermissionError:
        pass

    return sorted(found)


# ---------------------------------------------------------------------------
# Internal scanning helpers
# ---------------------------------------------------------------------------


def _scan_single_file(
    path: Path,
    report: AuditReport,
    *,
    include_supply_chain: bool,
    include_permissions: bool,
    include_hooks: bool,
    include_env_injection: bool,
) -> None:
    """Scan a single file with all applicable checkers and add results to report.

    Determines which checkers to apply based on the file name and extension,
    then dispatches to each checker and records the findings and the file
    as scanned.

    Args:
        path: The file path to scan.
        report: The AuditReport to add findings and metadata to.
        include_supply_chain: Whether to run supply chain checks.
        include_permissions: Whether to run permission checks.
        include_hooks: Whether to run hook injection checks.
        include_env_injection: Whether to run environment injection checks.
    """
    if not path.exists() or not path.is_file():
        return

    report.scanned_files.append(path)

    file_name_lower = path.name.lower()
    is_mcp_config = _is_mcp_config_file(path)
    is_supply_chain_manifest = file_name_lower in {
        n.lower() for n in SUPPLY_CHAIN_FILENAMES
    }

    # ----------------------------------------------------------------
    # Permission checks (apply to all files)
    # ----------------------------------------------------------------
    if include_permissions:
        _run_checker(
            checker=permissions.check_path,
            path=path,
            report=report,
            checker_name="permissions",
        )

    # ----------------------------------------------------------------
    # Content-based checks: skip oversized files
    # ----------------------------------------------------------------
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        report.add_error(f"Cannot stat file '{path}': {exc}")
        return

    if file_size > _MAX_FILE_SIZE:
        report.add_error(
            f"Skipping content checks for '{path}': file too large "
            f"({file_size:,} bytes > {_MAX_FILE_SIZE:,} bytes limit)."
        )
        return

    # ----------------------------------------------------------------
    # Hook injection checks (MCP config files and JSON files)
    # ----------------------------------------------------------------
    if include_hooks and (is_mcp_config or path.suffix.lower() in (".json", ".jsonc")):
        _run_checker(
            checker=hooks.check_file,
            path=path,
            report=report,
            checker_name="hooks",
        )

    # ----------------------------------------------------------------
    # Environment variable injection checks (MCP config files)
    # ----------------------------------------------------------------
    if include_env_injection and (
        is_mcp_config or path.suffix.lower() in (".json", ".jsonc", ".env")
    ):
        _run_checker(
            checker=env_injection.check_file,
            path=path,
            report=report,
            checker_name="env_injection",
        )

    # ----------------------------------------------------------------
    # Supply chain checks (manifest and config files)
    # ----------------------------------------------------------------
    if include_supply_chain and (is_supply_chain_manifest or is_mcp_config):
        _run_checker(
            checker=supply_chain.check_file,
            path=path,
            report=report,
            checker_name="supply_chain",
        )


def _scan_directory(
    directory: Path,
    report: AuditReport,
    *,
    recursive: bool,
    max_depth: int,
    include_supply_chain: bool,
    include_permissions: bool,
    include_hooks: bool,
    include_env_injection: bool,
    follow_symlinks: bool,
    current_depth: int,
    visited_inodes: set[int],
) -> None:
    """Recursively scan a directory for MCP configuration and manifest files.

    Applies permission checks to the directory itself, then iterates its
    children. Subdirectories are recursed into if ``recursive`` is True and
    the depth limit has not been reached. Known skip directories (e.g.,
    ``node_modules``, ``.git``) are never entered.

    Args:
        directory: The directory to scan.
        report: The AuditReport to add findings and metadata to.
        recursive: Whether to recurse into subdirectories.
        max_depth: Maximum recursion depth.
        include_supply_chain: Whether to run supply chain checks.
        include_permissions: Whether to run permission checks.
        include_hooks: Whether to run hook injection checks.
        include_env_injection: Whether to run environment injection checks.
        follow_symlinks: Whether to follow symbolic links.
        current_depth: The current recursion depth (0 = root).
        visited_inodes: Set of already-visited directory inodes (cycle detection).
    """
    if current_depth > max_depth:
        return

    # Cycle detection via inode tracking
    try:
        dir_stat = directory.stat()
        inode = dir_stat.st_ino
        if inode in visited_inodes:
            return
        visited_inodes.add(inode)
    except OSError as exc:
        report.add_error(f"Cannot stat directory '{directory}': {exc}")
        return

    # Permission check on the directory itself
    if include_permissions:
        _run_checker(
            checker=permissions.check_path,
            path=directory,
            report=report,
            checker_name="permissions",
        )

    # Iterate children
    try:
        children = sorted(directory.iterdir())
    except PermissionError as exc:
        report.add_error(f"Permission denied reading directory '{directory}': {exc}")
        return
    except OSError as exc:
        report.add_error(f"Cannot list directory '{directory}': {exc}")
        return

    for child in children:
        try:
            # Handle symlinks
            if child.is_symlink():
                if not follow_symlinks:
                    continue
                # Resolve the symlink target
                try:
                    resolved = child.resolve()
                except OSError:
                    continue
                child = resolved

            if child.is_file():
                if _should_scan_file(child):
                    _scan_single_file(
                        path=child,
                        report=report,
                        include_supply_chain=include_supply_chain,
                        include_permissions=include_permissions,
                        include_hooks=include_hooks,
                        include_env_injection=include_env_injection,
                    )

            elif child.is_dir():
                if recursive and not _should_skip_directory(child):
                    _scan_directory(
                        directory=child,
                        report=report,
                        recursive=recursive,
                        max_depth=max_depth,
                        include_supply_chain=include_supply_chain,
                        include_permissions=include_permissions,
                        include_hooks=include_hooks,
                        include_env_injection=include_env_injection,
                        follow_symlinks=follow_symlinks,
                        current_depth=current_depth + 1,
                        visited_inodes=visited_inodes,
                    )

        except PermissionError as exc:
            report.add_error(f"Permission denied accessing '{child}': {exc}")
        except OSError as exc:
            report.add_error(f"OS error accessing '{child}': {exc}")


def _run_checker(
    checker: CheckerFunc,
    path: Path,
    report: AuditReport,
    checker_name: str,
) -> None:
    """Invoke a single checker function and add its results to the report.

    Catches all exceptions from the checker to ensure a single checker
    failure does not abort the entire scan. Errors are recorded in the
    report's error list.

    Args:
        checker: The checker callable to invoke. Must accept a Path and
            return a list of Finding instances.
        path: The file or directory path to pass to the checker.
        report: The AuditReport to add findings and errors to.
        checker_name: A human-readable name for the checker, used in
            error messages.
    """
    try:
        findings = checker(path)
        if findings:
            report.add_findings(findings)
    except PermissionError as exc:
        report.add_error(
            f"[{checker_name}] Permission denied running check on '{path}': {exc}"
        )
    except OSError as exc:
        report.add_error(
            f"[{checker_name}] OS error running check on '{path}': {exc}"
        )
    except Exception as exc:  # noqa: BLE001 - we intentionally swallow all checker errors
        report.add_error(
            f"[{checker_name}] Unexpected error checking '{path}': "
            f"{type(exc).__name__}: {exc}"
        )


# ---------------------------------------------------------------------------
# File classification helpers
# ---------------------------------------------------------------------------


def _is_mcp_config_file(path: Path) -> bool:
    """Determine if a file path looks like an MCP server configuration file.

    A file is considered an MCP config if:
    - Its name matches a known MCP config filename, OR
    - Its name matches a known MCP config filename case-insensitively, OR
    - It is a ``.json`` file in a well-known MCP config directory.

    Args:
        path: The file path to classify.

    Returns:
        True if the file should be treated as an MCP configuration file.
    """
    name_lower = path.name.lower()

    # Direct match against known MCP config filenames
    known_names_lower = {n.lower().split("/")[-1] for n in MCP_CONFIG_FILENAMES}
    if name_lower in known_names_lower:
        return True

    # JSON files in well-known MCP config directories
    if path.suffix.lower() == ".json":
        for part in path.parts:
            if part.lower() in {
                "claude",
                "cursor",
                ".cursor",
                "windsurf",
                ".windsurf",
                ".mcp",
                "mcp",
            }:
                return True

    # Files with 'mcp' in the name
    if "mcp" in name_lower and path.suffix.lower() in (".json", ".jsonc", ".yaml", ".yml"):
        return True

    return False


def _should_scan_file(path: Path) -> bool:
    """Return True if the given file should be scanned.

    A file should be scanned if:
    - It is an MCP configuration file, OR
    - It is a known supply chain manifest file.

    Hidden files (dot-files) are included if they match known patterns.
    Binary files (based on extension) are excluded.

    Args:
        path: The file path to evaluate.

    Returns:
        True if the file is a candidate for scanning.
    """
    name_lower = path.name.lower()

    # Always scan known supply chain manifests
    if name_lower in {n.lower() for n in SUPPLY_CHAIN_FILENAMES}:
        return True

    # Always scan MCP config files
    if _is_mcp_config_file(path):
        return True

    # Skip clearly binary or irrelevant extensions
    _SKIP_EXTENSIONS = frozenset({
        ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe",
        ".bin", ".o", ".a", ".lib",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".mp3", ".mp4", ".mov", ".avi",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
        ".whl", ".egg",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".db", ".sqlite", ".sqlite3",
        ".lock",  # Binary lockfiles (bun.lockb etc.) - text lock files are already whitelisted
    })
    if path.suffix.lower() in _SKIP_EXTENSIONS:
        # Exception: .lock text files by name are already in SUPPLY_CHAIN_FILENAMES
        return False

    # Scan JSON / YAML / TOML / env files generically
    if path.suffix.lower() in (".json", ".jsonc", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg"):
        return True

    return False


def _should_skip_directory(path: Path) -> bool:
    """Return True if the given directory should be skipped during traversal.

    Directories in the ``_SKIP_DIRS`` set are never recursed into to avoid
    scanning large, irrelevant directory trees (e.g., node_modules) or
    version control internals.

    Args:
        path: The directory path to evaluate.

    Returns:
        True if the directory should be skipped.
    """
    return path.name.lower() in {d.lower() for d in _SKIP_DIRS}


# ---------------------------------------------------------------------------
# Utility: exit code helper for CLI integration
# ---------------------------------------------------------------------------


def exit_code_for_report(report: AuditReport) -> int:
    """Compute the appropriate process exit code for an AuditReport.

    This function maps finding severities to exit codes suitable for use
    in CI/CD pipelines:

    - ``0``: No findings.
    - ``1``: Only LOW or INFO findings.
    - ``2``: At least one MEDIUM finding, no HIGH or CRITICAL.
    - ``3``: At least one HIGH finding, no CRITICAL.
    - ``4``: At least one CRITICAL finding.
    - ``5``: The scan encountered errors (regardless of findings).

    Args:
        report: The completed AuditReport to evaluate.

    Returns:
        An integer exit code. Higher values indicate more severe issues.
    """
    if report.errors and report.finding_count == 0:
        return 5

    if report.critical_count > 0:
        return 4
    if report.high_count > 0:
        return 3
    if report.medium_count > 0:
        return 2
    if report.low_count > 0 or report.info_count > 0:
        return 1
    return 0
