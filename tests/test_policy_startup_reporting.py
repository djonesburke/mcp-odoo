"""Startup reporting for the two policy files.

Both policy paths resolve through a chain that can end in "nothing
configured", and the two ends fail in opposite directions. An absent
side-effect policy allows no methods, which is safe. An absent *field* policy
applies no masking at all, and the resolution used to reach that state without
a word: an unset variable with no ./odoo_mcp_policy.json in the working
directory produced no signal anywhere, so a redeploy that moved the file lost
field masking silently. These tests pin the startup lines that say so.
"""

import json

import pytest

from odoo_mcp.field_policy import FieldPolicyError, reset_field_policy
from odoo_mcp.server_core import report_policy_resolution


@pytest.fixture(autouse=True)
def _isolated_policy_env(monkeypatch, tmp_path):
    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE", raising=False)
    monkeypatch.delenv("ODOO_MCP_POLICY_FILE", raising=False)
    monkeypatch.delenv("ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", raising=False)
    monkeypatch.chdir(tmp_path)
    reset_field_policy()
    yield
    reset_field_policy()


def test_no_policy_configured_warns_that_masking_is_off():
    lines, fatal = report_policy_resolution()
    assert fatal is None
    blob = "\n".join(lines)
    assert "WARNING" in blob
    assert "NO field masking is active" in blob
    assert "none configured" in blob


def test_policy_with_no_rules_warns(tmp_path):
    policy = tmp_path / "odoo_mcp_policy.json"
    policy.write_text(json.dumps({"allowed_side_effect_methods": []}))
    lines, fatal = report_policy_resolution()
    assert fatal is None
    blob = "\n".join(lines)
    assert "defines no rules" in blob
    assert "NO field masking is active" in blob


def test_unreadable_policy_reports_and_stays_fatal(monkeypatch, tmp_path):
    """A configured path that does not exist must not degrade quietly."""
    missing = tmp_path / "nowhere" / "odoo_mcp_policy.json"
    monkeypatch.setenv("ODOO_MCP_POLICY_FILE", str(missing))
    lines, fatal = report_policy_resolution()
    assert isinstance(fatal, FieldPolicyError)
    blob = "\n".join(lines)
    assert "FIELD ACL ERROR" in blob
    assert "refusing to start" in blob


def test_active_policy_names_the_file_and_instances(tmp_path):
    policy = tmp_path / "odoo_mcp_policy.json"
    policy.write_text(
        json.dumps(
            {
                "allowed_side_effect_methods": ["sale.order.action_confirm"],
                "field_acl": {"default": {"res.partner": {"deny": ["credit_limit"]}}},
            }
        )
    )
    lines, fatal = report_policy_resolution()
    assert fatal is None
    blob = "\n".join(lines)
    assert "field ACL: odoo_mcp_policy.json" in blob
    assert "instances with rules: default" in blob
    assert "WARNING" not in blob
    # Flat list: say that it reaches every instance.
    assert "applies to every instance" in blob


def test_per_instance_policy_reports_the_resolution(tmp_path):
    """An operator must be able to read back which list applied where."""
    policy = tmp_path / "odoo_mcp_policy.json"
    policy.write_text(
        json.dumps(
            {
                "allowed_side_effect_methods": {
                    "default": [],
                    "staging": ["stock.picking.action_assign"],
                },
                "field_acl": {"default": {"res.partner": {"deny": ["credit_limit"]}}},
            }
        )
    )
    lines, fatal = report_policy_resolution()
    assert fatal is None
    blob = "\n".join(lines)
    assert "per-instance" in blob
    assert "default=0" in blob
    assert "staging=1" in blob
    assert "allows nothing" in blob


def test_broken_side_effect_policy_is_reported(tmp_path):
    policy = tmp_path / "odoo_mcp_policy.json"
    policy.write_text(json.dumps({"allowed_side_effect_methods": {"staging": "oops"}}))
    lines, fatal = report_policy_resolution()
    assert fatal is None
    blob = "\n".join(lines)
    assert "side-effect policy ERROR" in blob
    assert "no methods allowed" in blob
