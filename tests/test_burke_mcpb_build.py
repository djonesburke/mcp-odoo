"""The team bundle builder must refuse to ship a misleading artifact.

The read-only ``.mcpb`` (docs/BURKE-DEPLOY.md section 12) is installed by people
who will never open a config file, so every safety property it claims has to be
true of the artifact itself -- there is no operator downstream to notice
otherwise. Each guard below corresponds to a way the bundle could look correct
and not be:

* an unsuffixed version is indistinguishable from vanilla upstream (section 1);
* a label that disagrees with the database is how a "staging" config reaches
  production (section 10);
* a policy file with no ``field_acl`` masks nothing while the bundle's own
  description promises masking;
* a write-enabling env var, or an exclude list missing ``execute_method``
  (section 4), turns the read-only bundle into something else entirely.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_burke_mcpb.py"


def _load():
    """Import the builder by path; scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location("build_burke_mcpb", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _load()

PROD = ("prod", "https://example.com", "maindb.example.com")
STAGING = ("staging", "https://staging.example.com", "staging.example.com")


def _render(**overrides):
    kwargs = {
        "version": "1.3.0+burke.8",
        "wheel": "odoo_mcp-1.3.0+burke.8-py3-none-any.whl",
        "url": PROD[1],
        "db": PROD[2],
        "label": "prod",
        "describe": "burke-1.3.0.6-3-gdeadbee",
    }
    kwargs.update(overrides)
    return json.loads(builder.render_manifest(**kwargs))


# --- version identity ------------------------------------------------------


def test_burke_version_accepted():
    builder.check_version("1.3.0+burke.8")


@pytest.mark.parametrize("version", ["1.3.0", "1.4.0", "0.13.0"])
def test_unsuffixed_version_refused(version):
    """A bundle that cannot name itself is worse than no bundle."""
    with pytest.raises(SystemExit, match="burke"):
        builder.check_version(version)


# --- instance labelling ----------------------------------------------------


def test_matching_labels_accepted():
    builder.check_instance(*PROD)
    builder.check_instance(*STAGING)


def test_prod_label_with_staging_target_refused():
    with pytest.raises(SystemExit, match="mislabel"):
        builder.check_instance("prod", STAGING[1], STAGING[2])


def test_staging_label_with_prod_target_refused():
    """The dangerous direction: a 'staging' bundle that reaches production."""
    with pytest.raises(SystemExit, match="reaches"):
        builder.check_instance("staging", PROD[1], PROD[2])


def test_staging_detected_in_db_alone():
    """Half a giveaway is enough; the url need not mention staging."""
    builder.check_instance("staging", "https://example.com", "staging.example.com")
    with pytest.raises(SystemExit, match="mislabel"):
        builder.check_instance("prod", "https://example.com", "staging.example.com")


# --- policy ----------------------------------------------------------------


def test_shipped_policy_has_field_acl():
    """The real policy file is the one that gets vendored."""
    builder.check_policy()


@pytest.mark.parametrize("policy", [{}, {"field_acl": {}}, {"allowed": []}])
def test_policy_without_field_acl_refused(policy, tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(builder, "POLICY", path)
    with pytest.raises(SystemExit, match="field_acl"):
        builder.check_policy()


def test_missing_policy_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "POLICY", tmp_path / "absent.json")
    with pytest.raises(SystemExit, match="missing"):
        builder.check_policy()


# --- rendered manifest -----------------------------------------------------


def test_rendered_manifest_is_read_only():
    env = _render()["server"]["mcp_config"]["env"]
    assert "ODOO_MCP_ENABLE_WRITES" not in env
    assert "ODOO_MCP_ELICIT_WRITES" not in env
    assert "MCP_CHATTER_DIRECT" not in env


def test_rendered_manifest_excludes_the_write_surface():
    env = _render()["server"]["mcp_config"]["env"]
    excluded = set(env["ODOO_MCP_TOOLS_EXCLUDE"].split(","))
    assert excluded == {
        "execute_method",
        "execute_approved_write",
        "chatter_post",
        "preview_write",
        "validate_write",
    }


def test_rendered_manifest_uses_the_vendored_policy():
    """An absolute path could be switched by a branch change; ${__dirname} cannot."""
    env = _render()["server"]["mcp_config"]["env"]
    assert env["ODOO_MCP_POLICY_FILE"] == "${__dirname}/odoo_mcp_policy.json"


def test_rendered_manifest_vendors_the_wheel():
    cfg = _render()["server"]["mcp_config"]
    assert cfg["command"] == "uvx"
    assert cfg["args"][0] == "--from"
    assert cfg["args"][1].startswith("${__dirname}/wheels/")
    assert cfg["args"][1].endswith(".whl")
    # Not a PyPI pin: that would resolve to vanilla upstream.
    assert not any(a.startswith("odoo-mcp==") for a in cfg["args"])


def test_rendered_manifest_prompts_only_for_identity():
    """Nobody installing this should have to type a database name."""
    cfg = _render()
    assert set(cfg["user_config"]) == {"odoo_username", "odoo_api_key"}
    assert cfg["user_config"]["odoo_api_key"]["sensitive"] is True
    env = cfg["server"]["mcp_config"]["env"]
    assert env["ODOO_DB"] == PROD[2]
    assert "${user_config" not in env["ODOO_URL"]


def test_rendered_manifest_declares_no_python_runtime():
    """Declaring a python runtime makes the host demand a system interpreter.

    This bundle launches through ``uvx``, and uv provisions its own Python, so
    a machine with no system Python runs it fine. Declaring
    ``runtimes: {python: ">=3.10"}`` -- inherited from the upstream template,
    which has the same bug for the same reason -- made Claude Desktop show
    "Python >=3.10" unmet with "this extension may not work correctly", which
    stops a non-technical installer cold over a requirement that is not real.

    The genuine prerequisite is uv, and the manifest format has no field for
    it, so it stays in the description and the deploy doc.
    """
    compat = _render().get("compatibility", {})
    assert "python" not in compat.get("runtimes", {}), (
        "uvx supplies its own Python; declaring one demands a system interpreter"
    )


def test_rendered_manifest_carries_provenance():
    cfg = _render(describe="burke-1.3.0.6-3-gdeadbee-UNCOMMITTED")
    assert "1.3.0+burke.8" in cfg["version"]
    assert "UNCOMMITTED" in cfg["long_description"]


def test_unreplaced_placeholder_refused(monkeypatch, tmp_path):
    template = tmp_path / "manifest.template.json"
    template.write_text('{"version": "__VERSION__", "x": "__SURPRISE__"}', "utf-8")
    monkeypatch.setattr(builder, "TEMPLATE", template)
    with pytest.raises(SystemExit, match="__SURPRISE__"):
        _render()


def test_template_names_no_odoo_instance():
    """This repository is public, so the template carries no instance identity.

    The rule is about what reaches an instance: hostnames and database names.
    A login-hint email at Burke's own public domain is not that, and dropping it
    would make the prompt worse for the people this bundle is for. What must
    stay out is anything that could be pasted into a config and connect.

    Asserted as a shape, deliberately: an allowlist of forbidden literals would
    have to spell Burke's real hostname and database out in a public test file,
    which is the leak this test exists to prevent. So the invariant is that the
    connection fields are still placeholders and the env block contains no
    absolute URL or dotted host at all -- stronger than any blocklist, and it
    names nothing.
    """
    env = json.loads(builder.TEMPLATE.read_text(encoding="utf-8"))
    env = env["server"]["mcp_config"]["env"]
    assert env["ODOO_URL"] == "__ODOO_URL__"
    assert env["ODOO_DB"] == "__ODOO_DB__"

    for key, value in env.items():
        assert "://" not in value, f"{key} carries a URL; build-time only"
        if key == "ODOO_MCP_ROTATION_DOC":
            continue  # prose; names a runbook file, not a host
        assert not re.search(r"\b[\w-]+(\.[\w-]+){2,}\b", value), (
            f"{key} looks like it names a host: {value!r}"
        )
