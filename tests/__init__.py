"""Test package for mcp_audit.

This package contains unit tests for all mcp_audit checker modules,
the scanner orchestration layer, the reporter, and the CLI entry point.

Test modules:
    test_permissions: Permission checker tests using crafted permission bits.
    test_hooks: Hook injection detector tests with benign and malicious configs.
    test_env_injection: Environment variable injection detection tests.
    test_supply_chain: Supply chain risk detection tests with mock manifests.
    test_scanner: Scanner orchestration and file discovery tests.
    test_reporter: Terminal and JSON reporter rendering tests.
    test_cli: CLI entry point integration tests.
"""
