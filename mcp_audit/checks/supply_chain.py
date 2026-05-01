"""Supply chain risk checker for MCP configuration files.

This module scans MCP server configuration files for supply chain attack
vectors including unversioned package references, missing integrity hashes,
references to non-standard or private registries, and other indicators
that the software supply chain for MCP server tooling may be compromised
or vulnerable.

Inspired by real-world supply chain attacks such as dependency confusion,
typosquatting, and malicious package injection in npm and pip ecosystems.

Checks performed:
    SC-001: Unversioned npm package dependency (no version specifier)
    SC-002: Unversioned pip/Python package dependency
    SC-003: Overly broad version range (e.g., '*', 'latest', '>= 0')
    SC-004: Missing lockfile (package-lock.json, yarn.lock, poetry.lock, etc.)
    SC-005: Reference to non-standard or unknown npm registry
    SC-006: Reference to non-standard or unknown pip index
    SC-007: Missing integrity hash (npm 'integrity' field absent)
    SC-008: Package referenced from a git URL or branch (not a stable release)
    SC-009: Package referenced from a local path (file: protocol)
    SC-010: Suspicious package name matching typosquatting patterns
    SC-011: MCP server using 'npx' with unversioned or latest package
    SC-012: MCP server using 'uvx'/'pipx' with unversioned package
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_audit.models import Finding, Severity

# ---------------------------------------------------------------------------
# Known trusted registries
# ---------------------------------------------------------------------------

_TRUSTED_NPM_REGISTRIES: frozenset[str] = frozenset({
    "https://registry.npmjs.org",
    "https://registry.npmjs.org/",
    "http://registry.npmjs.org",
    "http://registry.npmjs.org/",
})

_TRUSTED_PIP_INDEXES: frozenset[str] = frozenset({
    "https://pypi.org/simple",
    "https://pypi.org/simple/",
    "https://pypi.python.org/simple",
    "https://pypi.python.org/simple/",
    "https://files.pythonhosted.org",
})

# ---------------------------------------------------------------------------
# Version specifier patterns
# ---------------------------------------------------------------------------

# npm version patterns that are too broad or unversioned
_NPM_UNVERSIONED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\*$"),                          # wildcard
    re.compile(r"^latest$", re.IGNORECASE),        # 'latest' tag
    re.compile(r"^next$", re.IGNORECASE),          # 'next' tag
    re.compile(r"^beta$", re.IGNORECASE),          # 'beta' tag
    re.compile(r"^alpha$", re.IGNORECASE),         # 'alpha' tag
    re.compile(r"^x$", re.IGNORECASE),             # bare 'x'
    re.compile(r"^>=\s*0\.?0?\.?0?\s*$"),         # >= 0.0.0
    re.compile(r"^>\s*0\.?0?\.?0?\s*$"),          # > 0.0.0
    re.compile(r"^>=\s*0\s*$"),                    # >= 0
    re.compile(r"^\.x\.x$"),                       # .x.x shorthand
]

# pip version specifiers that are too broad
_PIP_UNVERSIONED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^$"),                             # no version
    re.compile(r"^>=\s*0\.?0?\.?0?\s*$"),         # >= 0.0.0
    re.compile(r"^>\s*0\.?0?\.?0?\s*$"),          # > 0.0.0
    re.compile(r"^>=\s*0\s*$"),                    # >= 0
    re.compile(r"^!=.*$"),                          # only exclusion, no upper bound
]

# Git URL patterns for npm/pip dependencies
_GIT_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^git\+https?://"),
    re.compile(r"^git://"),
    re.compile(r"^github:"),
    re.compile(r"^gitlab:"),
    re.compile(r"^bitbucket:"),
    re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.+)?$"),  # user/repo#branch
    re.compile(r"https?://github\.com/.+\.git"),
    re.compile(r"https?://gitlab\.com/.+\.git"),
]

# Local path (file:) patterns
_LOCAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^file:"),
    re.compile(r"^\./"),
    re.compile(r"^\.\./"),
    re.compile(r"^/(?!dev/null)"),  # absolute path (not /dev/null)
    re.compile(r"^[A-Za-z]:\\\\"),  # Windows absolute path
]

# Registry URL patterns for detecting non-standard registries
_REGISTRY_URL_PATTERN = re.compile(
    r'(?:registry|index[_-]?url|extra[_-]?index[_-]?url)\s*[=:]\s*["\']?(https?://[^\s"\']+)',
    re.IGNORECASE,
)

# npm registry patterns in .npmrc or package.json
_NPM_REGISTRY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'"registry"\s*:\s*"(https?://[^"]+)"'),
    re.compile(r'^registry\s*=\s*(https?://\S+)', re.MULTILINE),
    re.compile(r'^(?:@[^:]+:)?registry\s*=\s*(https?://\S+)', re.MULTILINE),
]

# pip index patterns in pip.conf, setup.cfg, or pyproject.toml
_PIP_INDEX_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'index[_-]url\s*=\s*(https?://\S+)', re.IGNORECASE),
    re.compile(r'extra[_-]index[_-]url\s*=\s*(https?://\S+)', re.IGNORECASE),
    re.compile(r'find[_-]links\s*=\s*(https?://\S+)', re.IGNORECASE),
]

# Typosquatting patterns: common legitimate packages with minor variations
_COMMON_LEGITIMATE_PACKAGES: list[tuple[str, re.Pattern[str]]] = [
    ("lodash", re.compile(r"^l[o0]d[a@]sh$", re.IGNORECASE)),
    ("express", re.compile(r"^[e3]xpr[e3]ss$", re.IGNORECASE)),
    ("react", re.compile(r"^r[e3][a@]ct$", re.IGNORECASE)),
    ("numpy", re.compile(r"^num[p|]y$", re.IGNORECASE)),
    ("requests", re.compile(r"^r[e3]qu[e3]sts?$", re.IGNORECASE)),
    ("django", re.compile(r"^d[j|]ango$", re.IGNORECASE)),
    ("flask", re.compile(r"^fl[a@]sk$", re.IGNORECASE)),
    ("boto3", re.compile(r"^b[o0]t[o0]3?$", re.IGNORECASE)),
    ("urllib3", re.compile(r"^url[l|]ib3?$", re.IGNORECASE)),
    ("setuptools", re.compile(r"^set[u|]pt[o0]{2}ls?$", re.IGNORECASE)),
    ("pip", re.compile(r"^p[i|][p|]$", re.IGNORECASE)),
    ("axios", re.compile(r"^[a@]xi[o0]s$", re.IGNORECASE)),
    ("webpack", re.compile(r"^w[e3]bp[a@]ck$", re.IGNORECASE)),
    ("typescript", re.compile(r"^typ[e3]scr[i|]pt$", re.IGNORECASE)),
    ("eslint", re.compile(r"^[e3]sl[i|]nt$", re.IGNORECASE)),
]

# Well-known MCP tooling packages that should be versioned
_KNOWN_MCP_PACKAGES: frozenset[str] = frozenset({
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-sequential-thinking",
    "mcp",
    "mcp-server",
    "fastmcp",
})

# Lockfile names indicating dependency locking is in place
_LOCKFILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",  # pinned requirements
    "uv.lock",
    "pdm.lock",
    "conda-lock.yml",
    "frozen-requirements.txt",
})


def check_file(path: Path) -> list[Finding]:
    """Check a single file for supply chain security risks.

    Supports JSON config files (MCP configs, package.json), text-based
    requirement files (requirements.txt), and raw configuration files
    (.npmrc, pip.conf). Dispatches to format-specific sub-checkers.

    Args:
        path: Path to the file to analyze.

    Returns:
        A list of Finding instances for all supply chain risks detected.
        Returns an empty list if the file does not exist or cannot be read.
    """
    if not path.exists() or not path.is_file():
        return []

    try:
        raw_content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    name = path.name.lower()

    # Dispatch based on file type
    if name == "package.json":
        findings.extend(_check_package_json(raw_content, path))
    elif name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        findings.extend(_check_lockfile(raw_content, path))
    elif name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
        findings.extend(_check_requirements_txt(raw_content, path))
    elif name in (".npmrc",):
        findings.extend(_check_npmrc(raw_content, path))
    elif name in ("pip.conf", "pip.ini", "setup.cfg"):
        findings.extend(_check_pip_config(raw_content, path))
    elif path.suffix.lower() in (".json", ".jsonc"):
        # Treat as potential MCP config
        findings.extend(_check_mcp_config_json(raw_content, path))
    elif name in ("pyproject.toml",):
        findings.extend(_check_pyproject_toml(raw_content, path))

    # Check for missing lockfile if this is a package.json
    if name == "package.json":
        findings.extend(_check_missing_lockfile(path))

    findings = _deduplicate_findings(findings)
    return findings


def check_files(paths: list[Path]) -> list[Finding]:
    """Run supply chain checks on multiple files.

    Args:
        paths: A list of file paths to check.

    Returns:
        A combined list of all findings across all provided files.
    """
    findings: list[Finding] = []
    for path in paths:
        findings.extend(check_file(path))
    return findings


def check_directory(directory: Path) -> list[Finding]:
    """Check a directory for supply chain risks in its manifest files.

    Scans the top level of the directory for known manifest files
    (package.json, requirements.txt, pyproject.toml, etc.) and checks
    each for supply chain risks.

    Args:
        directory: The directory path to scan.

    Returns:
        A list of findings from all manifest files found in the directory.
    """
    if not directory.exists() or not directory.is_dir():
        return []

    findings: list[Finding] = []
    manifest_names = {
        "package.json",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "pyproject.toml",
        ".npmrc",
        "pip.conf",
        "pip.ini",
        "setup.cfg",
    }

    for child in directory.iterdir():
        if child.is_file() and child.name.lower() in manifest_names:
            findings.extend(check_file(child))

    # Check for missing lockfile at directory level
    findings.extend(_check_missing_lockfile(directory))

    return _deduplicate_findings(findings)


# ---------------------------------------------------------------------------
# Format-specific checkers
# ---------------------------------------------------------------------------


def _check_package_json(content: str, path: Path) -> list[Finding]:
    """Check a package.json file for supply chain risks.

    Args:
        content: The raw text content of the package.json file.
        path: The path to the package.json file.

    Returns:
        A list of findings from package.json analysis.
    """
    findings: list[Finding] = []

    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return findings

    if not isinstance(pkg, dict):
        return findings

    # Check dependencies and devDependencies
    for dep_key in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        deps = pkg.get(dep_key)
        if not isinstance(deps, dict):
            continue

        for pkg_name, version_spec in deps.items():
            if not isinstance(version_spec, str):
                continue

            findings.extend(_check_npm_package_version(
                pkg_name, version_spec, path, dep_key
            ))

    # Check if registry is configured non-standardly
    publish_config = pkg.get("publishConfig", {})
    if isinstance(publish_config, dict):
        registry = publish_config.get("registry", "")
        if registry and registry not in _TRUSTED_NPM_REGISTRIES:
            findings.append(
                Finding(
                    check_id="SC-005",
                    severity=Severity.HIGH,
                    title="Non-standard npm registry in publishConfig",
                    description=(
                        f"The file '{path}' specifies a non-standard npm registry "
                        f"('{registry}') in publishConfig. Packages published to or "
                        "fetched from untrusted registries may contain malicious code."
                    ),
                    file_path=path,
                    evidence=f"publishConfig.registry = {registry!r}",
                    remediation=(
                        "Use only the official npm registry (https://registry.npmjs.org) "
                        "unless a private registry is explicitly required and audited."
                    ),
                )
            )

    return findings


def _check_lockfile(content: str, path: Path) -> list[Finding]:
    """Check a lockfile for missing integrity hashes.

    Args:
        content: The raw text content of the lockfile.
        path: The path to the lockfile.

    Returns:
        A list of findings from lockfile analysis.
    """
    findings: list[Finding] = []

    if path.name.lower() != "package-lock.json":
        return findings

    try:
        lockdata = json.loads(content)
    except json.JSONDecodeError:
        return findings

    if not isinstance(lockdata, dict):
        return findings

    # Check packages section (npm lockfile v2/v3)
    packages = lockdata.get("packages", {})
    if isinstance(packages, dict):
        missing_integrity: list[str] = []
        for pkg_path, pkg_data in packages.items():
            if not isinstance(pkg_data, dict):
                continue
            # Skip the root package entry (empty string key)
            if pkg_path == "":
                continue
            # Skip local/bundled packages
            if pkg_data.get("link") or pkg_data.get("bundled"):
                continue
            if not pkg_data.get("integrity"):
                pkg_name = pkg_path.lstrip("node_modules/")
                missing_integrity.append(pkg_name)

        if missing_integrity:
            # Report first few missing, summarize the rest
            sample = missing_integrity[:5]
            total = len(missing_integrity)
            sample_str = ", ".join(sample)
            if total > 5:
                sample_str += f" (and {total - 5} more)"

            findings.append(
                Finding(
                    check_id="SC-007",
                    severity=Severity.HIGH,
                    title="Packages missing integrity hashes in lockfile",
                    description=(
                        f"The lockfile '{path}' has {total} package entries missing "
                        "'integrity' (SRI hash) fields. Without integrity hashes, "
                        "package downloads cannot be verified and may be tampered with "
                        "by a registry mirror or man-in-the-middle attack."
                    ),
                    file_path=path,
                    evidence=f"Packages missing integrity: {sample_str}",
                    remediation=(
                        "Regenerate the lockfile using 'npm install' or 'npm ci' to "
                        "ensure all packages have integrity hashes. Use 'npm audit' to "
                        "verify package integrity."
                    ),
                    extra={"missing_count": total, "sample": sample},
                )
            )

    return findings


def _check_requirements_txt(content: str, path: Path) -> list[Finding]:
    """Check a requirements.txt file for supply chain risks.

    Args:
        content: The raw text content of the requirements.txt file.
        path: The path to the requirements file.

    Returns:
        A list of findings from requirements.txt analysis.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue

        # Skip option lines (-r, -c, -f, etc.)
        if stripped.startswith("-"):
            # But check for custom index URLs
            for pattern in _PIP_INDEX_PATTERNS:
                m = pattern.search(stripped)
                if m:
                    index_url = m.group(1).rstrip("/")
                    normalized = index_url.rstrip("/")
                    is_trusted = any(
                        normalized.startswith(t.rstrip("/"))
                        for t in _TRUSTED_PIP_INDEXES
                    )
                    if not is_trusted:
                        findings.append(
                            Finding(
                                check_id="SC-006",
                                severity=Severity.HIGH,
                                title="Non-standard pip index URL",
                                description=(
                                    f"Line {line_num} of '{path}' specifies a non-standard "
                                    f"pip index URL ('{index_url}'). Packages fetched from "
                                    "untrusted indexes may be malicious or tampered with."
                                ),
                                file_path=path,
                                line_number=line_num,
                                evidence=stripped[:200],
                                remediation=(
                                    "Use only PyPI (https://pypi.org/simple) or an audited "
                                    "private index. If a private index is required, ensure "
                                    "it mirrors PyPI packages with integrity verification."
                                ),
                            )
                        )
                continue

        # Parse package name and version specifier
        # Handle: package==1.0, package>=1.0, package, package[extra]>=1.0
        # Also handle VCS URLs: git+https://...
        pkg_name, version_spec = _parse_pip_requirement(stripped)
        if not pkg_name:
            continue

        findings.extend(_check_pip_package_version(
            pkg_name, version_spec, path, line_num, stripped
        ))

    return findings


def _check_npmrc(content: str, path: Path) -> list[Finding]:
    """Check an .npmrc file for non-standard registry configurations.

    Args:
        content: The raw text content of the .npmrc file.
        path: The path to the .npmrc file.

    Returns:
        A list of findings from .npmrc analysis.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("#"):
            continue

        for pattern in _NPM_REGISTRY_PATTERNS:
            m = pattern.search(line)
            if m:
                registry_url = m.group(1).rstrip("/")
                normalized = registry_url.rstrip("/")
                is_trusted = normalized in {
                    url.rstrip("/") for url in _TRUSTED_NPM_REGISTRIES
                }
                if not is_trusted:
                    findings.append(
                        Finding(
                            check_id="SC-005",
                            severity=Severity.HIGH,
                            title="Non-standard npm registry in .npmrc",
                            description=(
                                f"Line {line_num} of '{path}' configures a non-standard "
                                f"npm registry ('{registry_url}'). Packages installed from "
                                "untrusted registries may be malicious. This is a common "
                                "vector for dependency confusion attacks."
                            ),
                            file_path=path,
                            line_number=line_num,
                            evidence=stripped[:200],
                            remediation=(
                                "Use only the official npm registry unless a private "
                                "registry is explicitly required. Verify private registries "
                                "use proper scoping (e.g., @myorg:registry=...) to prevent "
                                "dependency confusion attacks."
                            ),
                        )
                    )
                break

    return findings


def _check_pip_config(content: str, path: Path) -> list[Finding]:
    """Check a pip configuration file for non-standard index configurations.

    Args:
        content: The raw text content of the pip config file.
        path: The path to the config file.

    Returns:
        A list of findings from pip config analysis.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        for pattern in _PIP_INDEX_PATTERNS:
            m = pattern.search(line)
            if m:
                index_url = m.group(1).rstrip("/")
                normalized = index_url.rstrip("/")
                is_trusted = any(
                    normalized.startswith(t.rstrip("/"))
                    for t in _TRUSTED_PIP_INDEXES
                )
                if not is_trusted:
                    findings.append(
                        Finding(
                            check_id="SC-006",
                            severity=Severity.HIGH,
                            title="Non-standard pip index URL in pip config",
                            description=(
                                f"Line {line_num} of '{path}' configures a non-standard "
                                f"pip index URL ('{index_url}'). Fetching packages from "
                                "untrusted indexes is a supply chain attack vector "
                                "(dependency confusion, typosquatting)."
                            ),
                            file_path=path,
                            line_number=line_num,
                            evidence=stripped[:200],
                            remediation=(
                                "Use only PyPI (https://pypi.org/simple) or a verified "
                                "private index. Ensure private indexes do not expose "
                                "internal packages to public registries."
                            ),
                        )
                    )
                break

    return findings


def _check_pyproject_toml(content: str, path: Path) -> list[Finding]:
    """Check a pyproject.toml file for supply chain risks.

    Performs text-based analysis since we cannot import a TOML parser
    from stdlib in Python < 3.11. Uses regex patterns to find dependency
    declarations and index configurations.

    Args:
        content: The raw text content of the pyproject.toml file.
        path: The path to the pyproject.toml file.

    Returns:
        A list of findings from pyproject.toml analysis.
    """
    findings: list[Finding] = []

    # Try stdlib tomllib (Python 3.11+)
    parsed: dict[str, Any] | None = None
    try:
        import tomllib
        parsed = tomllib.loads(content)
    except (ImportError, Exception):
        parsed = None

    if parsed is not None:
        findings.extend(_check_pyproject_toml_parsed(parsed, path))
    else:
        # Fallback: text-based analysis
        findings.extend(_check_pyproject_toml_text(content, path))

    return findings


def _check_pyproject_toml_parsed(parsed: dict[str, Any], path: Path) -> list[Finding]:
    """Check a parsed pyproject.toml dict for supply chain risks.

    Args:
        parsed: The parsed TOML data as a dictionary.
        path: The path to the pyproject.toml file.

    Returns:
        A list of findings.
    """
    findings: list[Finding] = []

    # PEP 621 dependencies
    project = parsed.get("project", {})
    if isinstance(project, dict):
        deps = project.get("dependencies", [])
        if isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str):
                    pkg_name, version_spec = _parse_pip_requirement(dep)
                    if pkg_name:
                        findings.extend(_check_pip_package_version(
                            pkg_name, version_spec, path, None, dep
                        ))

        # optional-dependencies
        opt_deps = project.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for _group, group_deps in opt_deps.items():
                if isinstance(group_deps, list):
                    for dep in group_deps:
                        if isinstance(dep, str):
                            pkg_name, version_spec = _parse_pip_requirement(dep)
                            if pkg_name:
                                findings.extend(_check_pip_package_version(
                                    pkg_name, version_spec, path, None, dep
                                ))

    # Check tool.poetry.dependencies
    tool = parsed.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            for dep_key in ("dependencies", "dev-dependencies",
                            "group"):
                if dep_key == "group":
                    groups = poetry.get("group", {})
                    if isinstance(groups, dict):
                        for _gname, gdata in groups.items():
                            if isinstance(gdata, dict):
                                gdeps = gdata.get("dependencies", {})
                                if isinstance(gdeps, dict):
                                    for pkg_name, ver in gdeps.items():
                                        ver_str = ver if isinstance(ver, str) else ""
                                        findings.extend(_check_pip_package_version(
                                            pkg_name, ver_str, path, None, f"{pkg_name} = {ver_str!r}"
                                        ))
                else:
                    deps = poetry.get(dep_key, {})
                    if isinstance(deps, dict):
                        for pkg_name, ver in deps.items():
                            if pkg_name.lower() == "python":
                                continue
                            ver_str = ver if isinstance(ver, str) else (
                                ver.get("version", "") if isinstance(ver, dict) else ""
                            )
                            findings.extend(_check_pip_package_version(
                                pkg_name, ver_str, path, None, f"{pkg_name} = {ver_str!r}"
                            ))

        # Check tool.uv or tool.pip sources
        for tool_key in ("uv", "pip"):
            tool_section = tool.get(tool_key, {})
            if isinstance(tool_section, dict):
                sources = tool_section.get("index-url") or tool_section.get("extra-index-url")
                if sources:
                    source_list = [sources] if isinstance(sources, str) else sources
                    for source in source_list:
                        if isinstance(source, str):
                            normalized = source.rstrip("/")
                            is_trusted = any(
                                normalized.startswith(t.rstrip("/"))
                                for t in _TRUSTED_PIP_INDEXES
                            )
                            if not is_trusted:
                                findings.append(
                                    Finding(
                                        check_id="SC-006",
                                        severity=Severity.HIGH,
                                        title="Non-standard pip index in pyproject.toml",
                                        description=(
                                            f"The file '{path}' configures a non-standard "
                                            f"pip index URL ('{source}'). This is a potential "
                                            "supply chain attack vector."
                                        ),
                                        file_path=path,
                                        evidence=f"index-url = {source!r}",
                                        remediation=(
                                            "Use only trusted package indexes. Audit any "
                                            "private index configurations carefully."
                                        ),
                                    )
                                )

    return findings


def _check_pyproject_toml_text(content: str, path: Path) -> list[Finding]:
    """Perform text-based supply chain checks on pyproject.toml content.

    Args:
        content: The raw text content.
        path: The file path.

    Returns:
        A list of findings from text-based analysis.
    """
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Check for non-standard index URLs
        for pattern in _PIP_INDEX_PATTERNS:
            m = pattern.search(line)
            if m:
                index_url = m.group(1).rstrip("/")
                normalized = index_url.rstrip("/")
                is_trusted = any(
                    normalized.startswith(t.rstrip("/"))
                    for t in _TRUSTED_PIP_INDEXES
                )
                if not is_trusted:
                    findings.append(
                        Finding(
                            check_id="SC-006",
                            severity=Severity.HIGH,
                            title="Non-standard pip index URL in pyproject.toml",
                            description=(
                                f"Line {line_num} of '{path}' configures a non-standard "
                                f"pip index URL ('{index_url}')."
                            ),
                            file_path=path,
                            line_number=line_num,
                            evidence=stripped[:200],
                            remediation=(
                                "Use only trusted package indexes in pyproject.toml."
                            ),
                        )
                    )
                break

    return findings


def _check_mcp_config_json(content: str, path: Path) -> list[Finding]:
    """Check an MCP configuration JSON file for supply chain risks.

    Focuses on the mcpServers block where packages are referenced via
    npx, uvx, or pipx commands.

    Args:
        content: The raw text content of the JSON file.
        path: The path to the JSON file.

    Returns:
        A list of findings from MCP config analysis.
    """
    findings: list[Finding] = []

    try:
        config = json.loads(content)
    except json.JSONDecodeError:
        return findings

    if not isinstance(config, dict):
        return findings

    for block_key in ("mcpServers", "servers", "mcp_servers"):
        servers_block = config.get(block_key)
        if not isinstance(servers_block, dict):
            continue

        for server_name, server_def in servers_block.items():
            if not isinstance(server_def, dict):
                continue

            command = server_def.get("command", "")
            args = server_def.get("args", [])
            if not isinstance(command, str):
                command = ""
            if not isinstance(args, list):
                args = []

            args_str_list = [str(a) for a in args]

            # SC-011: npx with unversioned package
            if command.lower() in ("npx", "npx.cmd"):
                findings.extend(_check_npx_args(
                    server_name, args_str_list, path, block_key
                ))

            # SC-012: uvx / pipx with unversioned package
            elif command.lower() in ("uvx", "pipx", "pipx.exe"):
                findings.extend(_check_uvx_pipx_args(
                    server_name, command, args_str_list, path, block_key
                ))

            # Check if command itself is an npx-style invocation embedded in a shell
            full_cmd = " ".join([command] + args_str_list)
            if re.search(r"\bnpx\b", full_cmd) and command not in ("npx", "npx.cmd"):
                findings.extend(_check_npx_args(
                    server_name,
                    # Try to extract args after npx
                    args_str_list,
                    path,
                    block_key,
                ))

    return findings


# ---------------------------------------------------------------------------
# npx / uvx / pipx specific checks
# ---------------------------------------------------------------------------


def _check_npx_args(
    server_name: str,
    args: list[str],
    path: Path,
    block_key: str,
) -> list[Finding]:
    """Check npx invocation arguments for unversioned package references.

    Args:
        server_name: The MCP server name.
        args: The argument list passed to npx.
        path: The source file path.
        block_key: The parent key in the config (e.g., 'mcpServers').

    Returns:
        A list of findings for npx supply chain risks.
    """
    findings: list[Finding] = []
    if not args:
        return findings

    # Filter out npx flags (-y, --yes, --no, -p, etc.)
    pkg_args = [a for a in args if not a.startswith("-")]
    if not pkg_args:
        return findings

    # The first non-flag arg is typically the package name (possibly with @version)
    pkg_spec = pkg_args[0]

    # Check for '@latest' or no version
    pkg_name, version = _split_npm_package_spec(pkg_spec)
    if not pkg_name:
        return findings

    is_unversioned = not version or _is_npm_version_broad(version)
    is_latest = version and version.lower() in ("latest", "next", "beta", "alpha")

    if is_unversioned or is_latest:
        severity = Severity.HIGH if is_latest else Severity.MEDIUM
        findings.append(
            Finding(
                check_id="SC-011",
                severity=severity,
                title=f"MCP server '{server_name}' uses npx with unversioned package",
                description=(
                    f"The MCP server '{server_name}' in '{path}' is configured to run "
                    f"via 'npx {pkg_spec}' without a pinned version specifier. "
                    "Unversioned npx invocations always pull the latest version of the "
                    "package from the registry at runtime, making the server vulnerable "
                    "to supply chain attacks if the package is compromised or hijacked."
                ),
                file_path=path,
                evidence=f"{block_key}.{server_name}: npx {' '.join(args)}",
                remediation=(
                    f"Pin the package version in the npx invocation: "
                    f"change '{pkg_spec}' to '{pkg_name}@<exact_version>'. "
                    "Use a lockfile and verify package integrity with 'npm audit'."
                ),
                extra={"package": pkg_name, "version_spec": version or "(none)"},
            )
        )

    # Check if this is a git URL reference
    if version and _is_git_url(version):
        findings.append(
            Finding(
                check_id="SC-008",
                severity=Severity.HIGH,
                title=f"MCP server '{server_name}' uses git URL package reference",
                description=(
                    f"The MCP server '{server_name}' in '{path}' references package "
                    f"'{pkg_name}' via a git URL ('{version}'). Git URL references "
                    "may point to mutable branches or commits and cannot be reliably "
                    "integrity-verified, creating a supply chain risk."
                ),
                file_path=path,
                evidence=f"{block_key}.{server_name}: npx {pkg_spec}",
                remediation=(
                    "Use a published, versioned package release from the npm registry "
                    "instead of git URL references. If a git reference is required, "
                    "pin to a specific commit hash (not a branch name)."
                ),
            )
        )

    return findings


def _check_uvx_pipx_args(
    server_name: str,
    command: str,
    args: list[str],
    path: Path,
    block_key: str,
) -> list[Finding]:
    """Check uvx/pipx invocation arguments for unversioned package references.

    Args:
        server_name: The MCP server name.
        command: The command (uvx or pipx).
        args: The argument list.
        path: The source file path.
        block_key: The parent key in the config.

    Returns:
        A list of findings for uvx/pipx supply chain risks.
    """
    findings: list[Finding] = []
    if not args:
        return findings

    # Filter out flags
    pkg_args = [a for a in args if not a.startswith("-")]
    if not pkg_args:
        return findings

    pkg_spec = pkg_args[0]
    pkg_name, version = _parse_pip_requirement(pkg_spec)
    if not pkg_name:
        return findings

    is_unversioned = not version or _is_pip_version_broad(version)

    if is_unversioned:
        findings.append(
            Finding(
                check_id="SC-012",
                severity=Severity.MEDIUM,
                title=f"MCP server '{server_name}' uses {command} with unversioned package",
                description=(
                    f"The MCP server '{server_name}' in '{path}' is configured to run "
                    f"via '{command} {pkg_spec}' without a pinned version. "
                    "Unversioned {command} invocations install the latest available "
                    "version at runtime, making the server vulnerable to supply chain "
                    "attacks if the package is compromised or a malicious version is "
                    "published."
                ),
                file_path=path,
                evidence=f"{block_key}.{server_name}: {command} {' '.join(args)}",
                remediation=(
                    f"Pin the package version: change '{pkg_spec}' to "
                    f"'{pkg_name}==<exact_version>'. "
                    "Use 'pip-audit' or 'safety' to verify package integrity."
                ),
                extra={"package": pkg_name, "version_spec": version or "(none)"},
            )
        )

    # Check for git URL references in pip-style specs
    if _is_git_url(pkg_spec):
        findings.append(
            Finding(
                check_id="SC-008",
                severity=Severity.HIGH,
                title=f"MCP server '{server_name}' uses git URL package reference",
                description=(
                    f"The MCP server '{server_name}' in '{path}' installs a package "
                    f"via a git URL ('{pkg_spec}'). Git URL references may point to "
                    "mutable branches and bypass integrity verification."
                ),
                file_path=path,
                evidence=f"{block_key}.{server_name}: {command} {pkg_spec}",
                remediation=(
                    "Use a published PyPI package with a pinned version instead of "
                    "git URL references. If a git reference is required, pin to a "
                    "specific commit hash."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Package version checkers
# ---------------------------------------------------------------------------


def _check_npm_package_version(
    pkg_name: str,
    version_spec: str,
    path: Path,
    dep_section: str,
) -> list[Finding]:
    """Check an npm package dependency for supply chain risks.

    Args:
        pkg_name: The npm package name.
        version_spec: The version specifier string.
        path: The source file path.
        dep_section: The section name (e.g., 'dependencies').

    Returns:
        A list of findings for this package dependency.
    """
    findings: list[Finding] = []

    # SC-003: Overly broad version range
    if _is_npm_version_broad(version_spec):
        findings.append(
            Finding(
                check_id="SC-003",
                severity=Severity.MEDIUM,
                title=f"Overly broad npm version range: {pkg_name}",
                description=(
                    f"The npm package '{pkg_name}' in '{dep_section}' of '{path}' "
                    f"uses an overly broad version specifier ('{version_spec}'). "
                    "Broad version ranges allow automatic upgrades to potentially "
                    "malicious versions published after the config was written."
                ),
                file_path=path,
                evidence=f"{dep_section}.{pkg_name} = {version_spec!r}",
                remediation=(
                    f"Pin '{pkg_name}' to an exact version (e.g., '1.2.3') or a "
                    "tight range ('^1.2.3'). Use 'npm audit' and review updates manually."
                ),
                extra={"package": pkg_name, "version_spec": version_spec},
            )
        )

    # SC-001: Completely unversioned (empty string is already caught by broad check)
    elif not version_spec:
        findings.append(
            Finding(
                check_id="SC-001",
                severity=Severity.HIGH,
                title=f"Unversioned npm package dependency: {pkg_name}",
                description=(
                    f"The npm package '{pkg_name}' in '{dep_section}' of '{path}' "
                    "has no version specifier. Without version pinning, npm may "
                    "install any available version, including malicious releases."
                ),
                file_path=path,
                evidence=f"{dep_section}.{pkg_name} = (no version)",
                remediation=(
                    f"Add an explicit version for '{pkg_name}' in package.json."
                ),
            )
        )

    # SC-008: Git URL reference
    if _is_git_url(version_spec):
        findings.append(
            Finding(
                check_id="SC-008",
                severity=Severity.HIGH,
                title=f"npm package '{pkg_name}' referenced via git URL",
                description=(
                    f"The npm package '{pkg_name}' in '{dep_section}' of '{path}' "
                    f"is referenced via a git URL ('{version_spec}'). Git references "
                    "are mutable and cannot be verified with integrity hashes."
                ),
                file_path=path,
                evidence=f"{dep_section}.{pkg_name} = {version_spec!r}",
                remediation=(
                    f"Use a published npm version for '{pkg_name}' instead of a git URL. "
                    "If a git reference is required, pin to a specific immutable commit hash."
                ),
            )
        )

    # SC-009: Local path reference
    if _is_local_path(version_spec):
        findings.append(
            Finding(
                check_id="SC-009",
                severity=Severity.MEDIUM,
                title=f"npm package '{pkg_name}' referenced via local path",
                description=(
                    f"The npm package '{pkg_name}' in '{dep_section}' of '{path}' "
                    f"is referenced via a local path ('{version_spec}'). Local path "
                    "references bypass registry integrity checks and may reference "
                    "untrusted or mutable code."
                ),
                file_path=path,
                evidence=f"{dep_section}.{pkg_name} = {version_spec!r}",
                remediation=(
                    f"Publish '{pkg_name}' to a registry and reference it by version, "
                    "or ensure the local path points to audited, version-controlled code."
                ),
            )
        )

    # SC-010: Typosquatting check
    typo_finding = _check_typosquatting(pkg_name, path, f"{dep_section}.{pkg_name}")
    if typo_finding:
        findings.append(typo_finding)

    return findings


def _check_pip_package_version(
    pkg_name: str,
    version_spec: str,
    path: Path,
    line_num: int | None,
    raw_line: str,
) -> list[Finding]:
    """Check a pip package dependency for supply chain risks.

    Args:
        pkg_name: The pip package name.
        version_spec: The version specifier string (may be empty).
        path: The source file path.
        line_num: The line number (for requirements.txt), or None.
        raw_line: The raw line text for evidence.

    Returns:
        A list of findings for this pip package dependency.
    """
    findings: list[Finding] = []

    # SC-008: Git URL reference (full spec is a git URL)
    if _is_git_url(pkg_name) or _is_git_url(version_spec):
        findings.append(
            Finding(
                check_id="SC-008",
                severity=Severity.HIGH,
                title=f"pip package '{pkg_name}' referenced via git URL",
                description=(
                    f"The pip package '{pkg_name}' in '{path}' is referenced via a "
                    f"git URL. Git references are mutable and bypass PyPI integrity "
                    "verification."
                ),
                file_path=path,
                line_number=line_num,
                evidence=raw_line[:200],
                remediation=(
                    f"Use a published PyPI version for '{pkg_name}' instead of a git URL."
                ),
            )
        )
        return findings  # No further checks on git URLs

    # SC-009: Local path reference
    if _is_local_path(pkg_name) or _is_local_path(version_spec):
        findings.append(
            Finding(
                check_id="SC-009",
                severity=Severity.MEDIUM,
                title=f"pip package '{pkg_name}' referenced via local path",
                description=(
                    f"The pip package '{pkg_name}' in '{path}' is referenced via a "
                    "local path. Local path references bypass PyPI integrity checks."
                ),
                file_path=path,
                line_number=line_num,
                evidence=raw_line[:200],
                remediation=(
                    f"Publish '{pkg_name}' to PyPI and reference it by pinned version."
                ),
            )
        )
        return findings

    # SC-002: Unversioned pip package
    if not version_spec:
        findings.append(
            Finding(
                check_id="SC-002",
                severity=Severity.MEDIUM,
                title=f"Unversioned pip package dependency: {pkg_name}",
                description=(
                    f"The pip package '{pkg_name}' in '{path}' has no version specifier. "
                    "Without version pinning, pip may install any available version, "
                    "including newly published malicious releases."
                ),
                file_path=path,
                line_number=line_num,
                evidence=raw_line[:200],
                remediation=(
                    f"Pin '{pkg_name}' to an exact version (e.g., '{pkg_name}==1.2.3'). "
                    "Use 'pip-compile' or 'uv lock' to generate a pinned lockfile."
                ),
                extra={"package": pkg_name},
            )
        )

    # SC-003: Overly broad version range
    elif _is_pip_version_broad(version_spec):
        findings.append(
            Finding(
                check_id="SC-003",
                severity=Severity.LOW,
                title=f"Overly broad pip version range: {pkg_name}",
                description=(
                    f"The pip package '{pkg_name}' in '{path}' uses an overly broad "
                    f"version specifier ('{version_spec}'). This allows automatic "
                    "upgrades to potentially malicious future versions."
                ),
                file_path=path,
                line_number=line_num,
                evidence=raw_line[:200],
                remediation=(
                    f"Tighten the version constraint for '{pkg_name}' "
                    f"(e.g., '{pkg_name}>={version_spec.lstrip('>=')} ,<X.0'). "
                    "Consider using 'pip-audit' to check for vulnerabilities."
                ),
                extra={"package": pkg_name, "version_spec": version_spec},
            )
        )

    # SC-010: Typosquatting check
    typo_finding = _check_typosquatting(pkg_name, path, raw_line)
    if typo_finding:
        findings.append(typo_finding)

    return findings


def _check_missing_lockfile(path: Path) -> list[Finding]:
    """Check if a project directory is missing a dependency lockfile.

    If ``path`` is a file (e.g., package.json), checks the parent directory.
    If ``path`` is a directory, checks it directly.

    Args:
        path: A file or directory path to check.

    Returns:
        A list with a single SC-004 finding if no lockfile is found,
        or an empty list if a lockfile exists.
    """
    directory = path.parent if path.is_file() else path

    for lockfile_name in _LOCKFILE_NAMES:
        if (directory / lockfile_name).exists():
            return []

    # No lockfile found
    # Only warn if there's a package.json or requirements.txt present
    has_manifest = any([
        (directory / "package.json").exists(),
        (directory / "requirements.txt").exists(),
        (directory / "pyproject.toml").exists(),
        (directory / "Pipfile").exists(),
    ])

    if not has_manifest:
        return []

    return [
        Finding(
            check_id="SC-004",
            severity=Severity.MEDIUM,
            title="Missing dependency lockfile",
            description=(
                f"The directory '{directory}' contains a package manifest but no "
                "lockfile was found. Without a lockfile "
                "(package-lock.json, yarn.lock, poetry.lock, etc.), dependency "
                "resolution is non-deterministic and vulnerable to dependency "
                "confusion and version drift attacks."
            ),
            file_path=directory,
            evidence=f"No lockfile found in {directory}",
            remediation=(
                "Generate a lockfile to pin all transitive dependencies: "
                "'npm install' (creates package-lock.json), "
                "'yarn install' (creates yarn.lock), "
                "'poetry lock' (creates poetry.lock), or "
                "'uv lock' (creates uv.lock)."
            ),
        )
    ]


def _check_typosquatting(
    pkg_name: str,
    path: Path,
    context: str,
) -> Finding | None:
    """Check if a package name looks like a typosquatted version of a known package.

    Args:
        pkg_name: The package name to check.
        path: The source file path.
        context: Human-readable context string for the finding evidence.

    Returns:
        A Finding if the package name looks like a typosquatting attempt,
        or None if no match is found.
    """
    # Normalize: lowercase, remove scope for scoped npm packages
    normalized = pkg_name.lower()
    if normalized.startswith("@"):
        # Scoped packages like @scope/name are generally not typosquatted
        return None

    for legitimate_name, pattern in _COMMON_LEGITIMATE_PACKAGES:
        if normalized == legitimate_name:
            # Exact match - not a typosquat
            continue
        if pattern.search(normalized):
            return Finding(
                check_id="SC-010",
                severity=Severity.HIGH,
                title=f"Possible typosquatted package: '{pkg_name}'",
                description=(
                    f"The package '{pkg_name}' in '{path}' closely resembles the "
                    f"well-known package '{legitimate_name}'. This may be a "
                    "typosquatting attempt where a malicious package with a similar "
                    "name is installed instead of the intended legitimate package."
                ),
                file_path=path,
                evidence=f"Package '{pkg_name}' resembles '{legitimate_name}': {context}",
                remediation=(
                    f"Verify that '{pkg_name}' is the intended package. "
                    f"If you meant '{legitimate_name}', correct the package name. "
                    "Always verify package names against the official registry before "
                    "adding new dependencies."
                ),
                extra={
                    "suspected_typosquat": pkg_name,
                    "legitimate_package": legitimate_name,
                },
            )

    return None


# ---------------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------------


def _parse_pip_requirement(spec: str) -> tuple[str, str]:
    """Parse a pip requirement specifier into (package_name, version_spec).

    Handles formats like:
    - ``package``
    - ``package==1.0``
    - ``package>=1.0,<2.0``
    - ``package[extra]>=1.0``
    - ``git+https://...``
    - ``./local/path``

    Args:
        spec: The raw requirement specifier string.

    Returns:
        A tuple of (package_name, version_spec). If no version is specified,
        version_spec will be an empty string. If the spec cannot be parsed,
        returns ('', '').
    """
    spec = spec.strip()
    if not spec:
        return "", ""

    # Handle VCS URLs (git+https://...)
    if any(spec.startswith(prefix) for prefix in ("git+", "git://", "svn+", "hg+", "bzr+")):
        # Extract egg name if present
        egg_match = re.search(r"#egg=([A-Za-z0-9_.-]+)", spec)
        if egg_match:
            return egg_match.group(1), spec
        return spec, spec

    # Handle local paths
    if spec.startswith(("./", "../", "/")) or re.match(r"[A-Za-z]:\\\\", spec):
        return spec, spec
    if spec.startswith("file:"):
        return spec, spec

    # Standard requirement: name[extras]version_specs; options
    # Strip trailing options (e.g., ; python_version >= '3.6')
    spec_no_options = spec.split(";")[0].strip()

    # Match package name (including optional extras)
    name_match = re.match(
        r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(\[[^\]]*\])?",
        spec_no_options,
    )
    if not name_match:
        return "", ""

    pkg_name = name_match.group(1)
    rest = spec_no_options[name_match.end():].strip()

    return pkg_name, rest


def _split_npm_package_spec(spec: str) -> tuple[str, str]:
    """Split an npm package spec into (name, version).

    Handles:
    - ``package`` -> (``package``, ``""``)
    - ``package@1.0.0`` -> (``package``, ``"1.0.0"``)
    - ``@scope/package@1.0.0`` -> (``@scope/package``, ``"1.0.0"``)
    - ``@scope/package`` -> (``@scope/package``, ``""``)

    Args:
        spec: The npm package specifier.

    Returns:
        A tuple of (package_name, version_spec).
    """
    spec = spec.strip()
    if not spec:
        return "", ""

    # Scoped packages: @scope/name[@version]
    if spec.startswith("@"):
        # Find the @ that separates version from scoped package name
        second_at = spec.find("@", 1)
        if second_at == -1:
            return spec, ""
        return spec[:second_at], spec[second_at + 1:]

    # Non-scoped: name[@version]
    at_idx = spec.find("@")
    if at_idx == -1:
        return spec, ""
    return spec[:at_idx], spec[at_idx + 1:]


def _is_npm_version_broad(version_spec: str) -> bool:
    """Return True if the given npm version specifier is too broad.

    Args:
        version_spec: The npm version specifier string.

    Returns:
        True if the version spec is considered overly permissive.
    """
    if not version_spec:
        return True
    return any(pattern.match(version_spec.strip()) for pattern in _NPM_UNVERSIONED_PATTERNS)


def _is_pip_version_broad(version_spec: str) -> bool:
    """Return True if the given pip version specifier is too broad.

    Args:
        version_spec: The pip version specifier string.

    Returns:
        True if the version spec is considered overly permissive.
    """
    if not version_spec:
        return True
    return any(pattern.match(version_spec.strip()) for pattern in _PIP_UNVERSIONED_PATTERNS)


def _is_git_url(spec: str) -> bool:
    """Return True if the given spec string is a git URL or VCS reference.

    Args:
        spec: The package version or reference string.

    Returns:
        True if the spec is a git URL or VCS reference.
    """
    return any(pattern.match(spec) for pattern in _GIT_URL_PATTERNS)


def _is_local_path(spec: str) -> bool:
    """Return True if the given spec string is a local filesystem path.

    Args:
        spec: The package version or reference string.

    Returns:
        True if the spec is a local path reference.
    """
    return any(pattern.match(spec) for pattern in _LOCAL_PATH_PATTERNS)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on check_id, file path, line, and evidence.

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
