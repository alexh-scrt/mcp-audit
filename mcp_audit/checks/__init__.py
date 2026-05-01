"""Security checker modules for mcp_audit.

This sub-package contains individual checker modules, each responsible for
detecting a specific class of security vulnerability in MCP server
configurations:

- ``permissions``: Checks file and directory permission bits for world-writable
  or overly permissive configurations.
- ``hooks``: Detects suspicious pre-sandbox lifecycle hooks and pre-init
  execution patterns in config files.
- ``env_injection``: Scans for dangerous environment variable overrides such
  as PATH manipulation and LD_PRELOAD injections.
- ``supply_chain``: Flags supply chain risks including unversioned package
  references, missing lockfiles, and unknown registries.

All checkers follow the same interface: they accept a file path and optional
parsed content, and return a list of ``Finding`` instances.

Example usage::

    from mcp_audit.checks import permissions, hooks, env_injection, supply_chain
    from pathlib import Path

    findings = permissions.check_path(Path("/etc/mcp/config.json"))
"""

__all__ = [
    "permissions",
    "hooks",
    "env_injection",
    "supply_chain",
]
