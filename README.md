# mcp-audit

> Security scanning for MCP server configurations — catch injection risks before they catch you.

`mcp-audit` is a CLI tool that scans [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server configuration files and startup directories for pre-initialization injection vulnerabilities. Inspired by the Gemini CLI RCE vulnerability class, it detects dangerous permission settings, hook injections, environment variable overrides, and supply chain risks in AI agent tooling setups. Results render as colored terminal output or exportable JSON reports for seamless CI/CD integration.

---

## Quick Start

```bash
# Install from PyPI
pip install mcp-audit

# Scan your Claude Desktop config directory
mcp-audit scan ~/.config/claude

# Scan a specific config file
mcp-audit scan claude_desktop_config.json

# Output machine-readable JSON (great for CI)
mcp-audit scan ~/.config/claude --json
```

That's it. A developer should be able to assess their MCP setup security in under 60 seconds.

---

## What It Does

`mcp-audit` walks your MCP config files and startup directories, dispatches them through a set of focused security checkers, and produces a prioritized report of findings — each tagged with a severity level (`critical`, `high`, `medium`, `low`, `info`) and a check ID for easy triage.

---

## Features

- **Permission auditing** — Detects world-writable, group-writable, and root-owned-but-user-editable MCP config files and startup directories (`PERM-001` through `PERM-006`)
- **Hook injection detection** — Identifies suspicious pre-sandbox lifecycle hooks (`preExec`, `onInit`, `postInit`), shell-exec patterns, network fetches, and command substitution in JSON/YAML MCP configs (`HOOK-001` through `HOOK-008`)
- **Environment variable injection scanning** — Flags dangerous overrides including `LD_PRELOAD`, `PATH` prepending, `PYTHONPATH`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, and shell init file hijacks (`ENV-001` through `ENV-012`)
- **Supply chain risk flagging** — Warns on unversioned npm/pip dependencies, missing lockfiles, non-standard registries, typosquatted package names, and `npx`/`uvx` references without pinned versions (`SC-001` through `SC-012`)
- **CI-friendly JSON output** — `--json` flag emits machine-readable reports with severity levels for pipeline integration; exit codes reflect finding severity for automated gating

---

## Usage Examples

### Scan a config directory (terminal output)

```bash
mcp-audit scan ~/.config/claude
```

```
╭─────────────────────────────────────────────────────────╮
│              mcp-audit  •  v0.1.0                       │
╰─────────────────────────────────────────────────────────╯

 Scanned: /home/user/.config/claude  •  3 files  •  7 findings

┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Check    ┃ Message                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ ENV-002  │ LD_PRELOAD set in server env block        │
│ HIGH     │ HOOK-001 │ preExec hook detected in server config    │
│ HIGH     │ SC-011   │ npx with unversioned package: some-tool   │
│ MEDIUM   │ PERM-001 │ World-writable config file detected       │
│ MEDIUM   │ ENV-001  │ PATH prepended with untrusted directory   │
│ LOW      │ SC-004   │ Missing package-lock.json                 │
│ INFO     │ HOOK-003 │ onInit lifecycle hook present             │
└──────────┴──────────┴───────────────────────────────────────────┘

 1 critical  •  2 high  •  2 medium  •  1 low  •  1 info
```

### Output JSON for CI pipelines

```bash
mcp-audit scan ~/.config/claude --json
```

```json
{
  "scanned_at": "2024-01-15T10:30:00Z",
  "target": "/home/user/.config/claude",
  "summary": {
    "total": 7,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 1,
    "info": 1
  },
  "findings": [
    {
      "check_id": "ENV-002",
      "severity": "critical",
      "message": "LD_PRELOAD set in server env block",
      "file": "claude_desktop_config.json",
      "detail": "LD_PRELOAD=/tmp/malicious.so can hijack all shared library loading"
    }
  ]
}
```

### Save JSON report to a file

```bash
mcp-audit scan . --json --output report.json
```

### Fail CI on critical or high findings

```bash
mcp-audit scan . --fail-on high
echo "Exit code: $?"  # Non-zero if any high/critical findings exist
```

### Disable specific checker categories

```bash
# Skip supply chain checks
mcp-audit scan ~/.config/claude --no-supply-chain

# Only run permission and env checks
mcp-audit scan ~/.config/claude --no-hooks --no-supply-chain
```

### Filter by minimum severity

```bash
mcp-audit scan ~/.config/claude --min-severity high
```

### List all available checks

```bash
mcp-audit checks
```

---

## Project Structure

```
mcp_audit/
├── pyproject.toml          # Project metadata, dependencies, CLI entry point
├── README.md               # This file
├── mcp_audit/
│   ├── __init__.py         # Package init, version, top-level API
│   ├── cli.py              # Click-based CLI entry point
│   ├── scanner.py          # Core scanner: walks configs, dispatches checkers
│   ├── models.py           # Finding, Severity, AuditReport dataclasses
│   ├── reporter.py         # Rich terminal tables + JSON serialization
│   └── checks/
│       ├── __init__.py
│       ├── permissions.py  # File/directory permission bit checks
│       ├── hooks.py        # Pre-sandbox hook injection detection
│       ├── env_injection.py# Environment variable injection scanning
│       └── supply_chain.py # Supply chain risk detection
└── tests/
    ├── __init__.py
    ├── test_permissions.py
    ├── test_hooks.py
    ├── test_env_injection.py
    ├── test_supply_chain.py
    ├── test_scanner.py
    ├── test_reporter.py
    └── test_cli.py
```

---

## Configuration

`mcp-audit` requires no configuration file — it works out of the box. All behavior is controlled via CLI flags.

| Flag | Description | Default |
|---|---|---|
| `--json` | Emit machine-readable JSON to stdout | off |
| `--output FILE` | Write JSON report to a file (requires `--json`) | stdout |
| `--fail-on LEVEL` | Exit non-zero if findings at this severity or above exist | `critical` |
| `--min-severity LEVEL` | Only report findings at this severity or above | `info` |
| `--no-permissions` | Disable permission checks | enabled |
| `--no-hooks` | Disable hook injection checks | enabled |
| `--no-env` | Disable environment variable injection checks | enabled |
| `--no-supply-chain` | Disable supply chain checks | enabled |
| `--compact` | Compact single-line output per finding | off |
| `--verbose` | Show full finding details and remediation hints | off |
| `--quiet` | Suppress all output except errors | off |

### CI/CD Integration Example

```yaml
# .github/workflows/security.yml
- name: Audit MCP configs
  run: |
    pip install mcp-audit
    mcp-audit scan . --json --output mcp-report.json --fail-on high

- name: Upload audit report
  uses: actions/upload-artifact@v3
  with:
    name: mcp-audit-report
    path: mcp-report.json
```

---

## Severity Levels

| Level | Meaning |
|---|---|
| `critical` | Immediate exploitation risk (e.g., active `LD_PRELOAD` override) |
| `high` | Strong indicator of malicious or dangerous configuration |
| `medium` | Potentially exploitable misconfiguration worth investigating |
| `low` | Best-practice violation that increases attack surface |
| `info` | Informational finding, no immediate risk |

---

## Requirements

- Python 3.11+
- [`click`](https://click.palletsprojects.com/) >= 8.1
- [`rich`](https://rich.readthedocs.io/) >= 13.0

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
