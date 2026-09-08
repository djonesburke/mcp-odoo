import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def _isolate_developer_odoo_config(monkeypatch, tmp_path):
    """Pin every test to the CI baseline: no Odoo config present on the box.

    A developer machine legitimately carries a real instances config at a
    default discovery path (~/.config/odoo/config.json) plus ODOO_* variables.
    With one present, load_instances_config() switches instance resolution
    from the permissive no-config fallback to validated named instances, and
    the suite starts depending on whatever the developer configured (e.g.
    index_knowledge resolving the developer's default instance while
    search_knowledge resolves 'default'). Pointing ODOO_CONFIG_FILE at a
    missing file makes _config_file_paths() raise FileNotFoundError exactly
    like a bare CI runner. Tests that exercise real configs set the variable
    (or clear it and chdir into a tmp dir) themselves, which overrides this.

    The same reasoning covers the policy-file variables. A developer running
    an MCP server on this box legitimately has ODOO_MCP_POLICY_FILE (and/or
    ODOO_MCP_FIELD_POLICY_FILE) exported, which silently switches the field
    ACL and the side-effect method allowlist on for the whole suite — turning
    dozens of unrelated assertions into a function of that developer's local
    policy JSON. CI has neither variable, so clearing them here is what makes
    a local run mean the same thing as a CI run. Tests that want a policy set
    one explicitly via monkeypatch, which overrides this.
    """
    # Imported here, not at module scope: the sys.path insert above is what
    # makes odoo_mcp importable at all.
    from odoo_mcp.field_policy import reset_field_policy

    for var in (
        "ODOO_URL",
        "ODOO_DB",
        "ODOO_USERNAME",
        "ODOO_PASSWORD",
        "ODOO_MCP_POLICY_FILE",
        "ODOO_MCP_FIELD_POLICY_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ODOO_CONFIG_FILE", str(tmp_path / "no-odoo-config.json"))
    # Clearing the variables is not enough to reach the no-policy baseline:
    # discovery falls back to the bare relative name "odoo_mcp_policy.json",
    # which resolves against the working directory -- the repo root under
    # pytest, where this project ships one. So every test that neither sets a
    # policy nor chdir'd was silently running against Burke's shipped rules
    # (found 2026-09-08; review finding S4). An empty directory of its own
    # removes that: it is not tmp_path itself, so a test may still write a
    # policy into tmp_path and control discovery by chdir'ing there.
    neutral_cwd = tmp_path / "neutral-cwd"
    neutral_cwd.mkdir(exist_ok=True)
    monkeypatch.chdir(neutral_cwd)
    # The loaded policy is process-global, so a test that sets one must not be
    # able to leave it behind for the next -- including when it fails an
    # assert on the way out.
    reset_field_policy()
    yield
    reset_field_policy()


@pytest.fixture
def odoo_client_module():
    module = importlib.import_module("odoo_mcp.odoo_client")
    return importlib.reload(module)
