"""mcp_audit: A CLI security tool for scanning MCP server configurations.

This package provides tools to detect pre-initialization injection risks,
permission vulnerabilities, environment variable injection, and supply chain
attack vectors in Model Context Protocol (MCP) server configurations.

Typical usage example::

    from mcp_audit import __version__
    from mcp_audit.models import AuditReport, Finding, Severity
"""

from mcp_audit.models import AuditReport, Finding, Severity

__version__ = "0.1.0"
__author__ = "mcp-audit contributors"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "AuditReport",
    "Finding",
    "Severity",
]
