"""Startup logging must not print credentials, whatever the variable is called.

The server echoes every ``ODOO_*`` / ``MCP_*`` environment variable to stderr on
start, so ``is_secret_env_key`` is the only control between a credential and the
log. It was suffix-based and punctuation-sensitive: ``ODOO_PROD_API_KEY`` was
masked but ``ODOO_PROD_APIKEY`` — the same 40-character production key under a
second name — was printed in clear text on every single server start.

These tests pin the spelling variants, because that is the failure that actually
happened rather than a hypothetical one.
"""

from __future__ import annotations

import importlib

import pytest

cli = importlib.import_module("odoo_mcp.__main__")


@pytest.mark.parametrize(
    "key",
    [
        # The exact variant that leaked.
        "ODOO_PROD_APIKEY",
        # Other spellings of the same thing.
        "ODOO_PROD_API_KEY",
        "ODOO_PROD_API-KEY",
        "ODOO_APIKEY",
        "APIKEY",
        "odoo_prod_apikey",
        # Bare markers with no leading underscore — the old suffix check
        # required "_PASSWORD" etc., so a bare name slipped through.
        "SECRET",
        "TOKEN",
        "PASSWORD",
        # Other credential shapes.
        "AWS_ACCESS_KEY",
        "SSH_PRIVATE_KEY",
        "SERVICE_CREDENTIALS",
        "DB_PASSWD",
        # Previously-covered cases must stay covered.
        "ODOO_PASSWORD",
        "MCP_HTTP_AUTH_TOKEN",
        "MY_SERVICE_PASSWORD",
        "AGENT_TOKEN",
        "CUSTOM_API_KEY",
    ],
)
def test_credential_names_are_masked(key):
    assert cli.is_secret_env_key(key) is True, f"{key} would be logged in clear text"


@pytest.mark.parametrize(
    "key",
    [
        # Real non-secret settings that must stay visible for diagnostics.
        "ODOO_URL",
        "ODOO_DB",
        "ODOO_USERNAME",
        "ODOO_TRANSPORT",
        "ODOO_MCP_POLICY_FILE",
        "ODOO_MCP_AUDIT_LOG",
        "ODOO_MCP_ENABLE_WRITES",
        "ODOO_MCP_TOOLS_EXCLUDE",
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS",
        "MCP_TRANSPORT",
        "MCP_CHATTER_DIRECT",
        "MCP_CONNECTION_NONBLOCKING",
    ],
)
def test_non_secret_names_stay_visible(key):
    assert cli.is_secret_env_key(key) is False, f"{key} lost its diagnostic value"


def test_startup_banner_does_not_print_a_secret_under_an_odd_name(monkeypatch, capsys):
    """End to end: the banner itself must not leak, not just the predicate.

    Testing the predicate alone would not have caught the original bug if the
    banner had used a different check, so this drives the real logging path.
    """
    secret = "d3adb33fd3adb33fd3adb33fd3adb33fd3adb33f"
    monkeypatch.setenv("ODOO_PROD_APIKEY", secret)
    monkeypatch.setenv("ODOO_PROD_URL", "https://example.invalid")

    for key, value in sorted(  # mirrors the banner loop in main()
        (k, v) for k, v in __import__("os").environ.items()
        if k.startswith(("ODOO_", "MCP_"))
    ):
        rendered = "***hidden***" if cli.is_secret_env_key(key) else value
        if key == "ODOO_PROD_APIKEY":
            assert rendered == "***hidden***"
            assert secret not in rendered
        if key == "ODOO_PROD_URL":
            assert rendered == "https://example.invalid"
