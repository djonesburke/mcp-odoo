#!/usr/bin/env python3
"""Build Burke's read-only Claude Desktop .mcpb bundle for odoo-mcp.

Unlike the upstream bundle (scripts/build_mcpb.py), which resolves
``uvx odoo-mcp==<version>`` from PyPI, this one **vendors the wheel built from
this checkout**. Burke's build carries a ``+burke.N`` local version that was
never published to PyPI, so a PyPI-resolving bundle can only ever install
vanilla upstream -- which contains none of the Burke safety behaviors. A
vendored wheel also pins harder than a git tag and cannot be shadowed by the
unrelated ``odoo-mcp-multi`` package, which owns the bare ``odoo-mcp`` command
name on at least one Burke PC.

The bundle carries three things: the manifest, the wheel, and the field-ACL
policy file. The policy is vendored rather than referenced by absolute path so
that it cannot drift when a git checkout switches branches.

Burke-specific values (URL, database) are supplied on the command line and
baked into the artifact, so nobody installing it has to type a database name.
They are NOT stored in this public repository.

Usage:
  python scripts/build_burke_mcpb.py \
      --instance-label prod --odoo-url https://... --odoo-db ... --out dist
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "mcpb" / "manifest.burke.template.json"
POLICY = ROOT / "odoo_mcp_policy.json"

INSTANCE_TITLES = {"prod": "Production", "staging": "Staging"}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"build_burke_mcpb: {message}")


def project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    if not match:
        fail("version not found in pyproject.toml")
    return match.group(1)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def check_version(version: str) -> None:
    """A bundle without the +burke suffix is indistinguishable from upstream."""
    if "+burke." not in version:
        fail(
            f"version {version!r} carries no '+burke.N' suffix. The suffix is the "
            "only way an installed machine can be told apart from vanilla "
            "upstream from PyPI. Refusing to build an unidentifiable bundle."
        )


def check_tree(allow_dirty: bool) -> str:
    """Refuse to vendor a wheel built from an unrecorded working tree.

    ``git describe --dirty`` only notices modifications to *tracked* files, so
    a tree carrying untracked build inputs -- the manifest template is one --
    describes itself as a clean commit. The marker is appended here instead, so
    an --allow-dirty artifact says so in its own provenance rather than
    claiming a commit that does not contain what went into it.
    """
    dirty = git("status", "--porcelain")
    if dirty and not allow_dirty:
        fail(
            "working tree is dirty; the vendored wheel would not correspond to "
            "any commit and could never be reproduced. Commit first, or pass "
            f"--allow-dirty deliberately.\n{dirty}"
        )
    describe = git("describe", "--always", "--tags")
    return f"{describe}-UNCOMMITTED" if dirty else describe


def check_instance(label: str, url: str, db: str) -> None:
    """Guard the failure mode BURKE-DEPLOY.md section 10 documents.

    Staging is a byte-identical clone regenerated from a neutralized prod
    snapshot, and per-user API keys are the same string on both. So a bundle
    *labelled* staging that carries prod's database name reaches production and
    authenticates fine -- the label is the only thing that would have warned
    anyone, and the label is exactly what is wrong.
    """
    if label not in INSTANCE_TITLES:
        fail(f"--instance-label must be one of {sorted(INSTANCE_TITLES)}")
    looks_staging = "staging" in url.lower() or "staging" in db.lower()
    if label == "prod" and looks_staging:
        fail(
            "--instance-label prod but url/db mention staging "
            f"(url={url!r} db={db!r}). Refusing to mislabel an instance."
        )
    if label == "staging" and not looks_staging:
        fail(
            "--instance-label staging but neither url nor db mentions staging "
            f"(url={url!r} db={db!r}). This is how a 'staging' config reaches "
            "production. Refusing to build."
        )


def check_policy() -> None:
    """A bundle whose policy has no field_acl silently masks nothing."""
    if not POLICY.exists():
        fail(f"policy file missing: {POLICY}")
    try:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"policy file is not valid JSON: {exc}")
    acl = policy.get("field_acl")
    if not isinstance(acl, dict) or not acl:
        fail(
            "policy file has no non-empty 'field_acl' key. The bundle would "
            "install with masking off while claiming to mask margin, cost and "
            "employee data. Refusing to build."
        )


def build_wheel(work: Path) -> Path:
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(work)], cwd=ROOT, check=True
    )
    wheels = sorted(work.glob("*.whl"))
    if len(wheels) != 1:
        fail(f"expected exactly one wheel in {work}, found {len(wheels)}")
    return wheels[0]


def render_manifest(
    *, version: str, wheel: str, url: str, db: str, label: str, describe: str
) -> str:
    manifest = TEMPLATE.read_text(encoding="utf-8")
    for token, value in (
        ("__VERSION__", version),
        ("__WHEEL__", wheel),
        ("__ODOO_URL__", url),
        ("__ODOO_DB__", db),
        ("__INSTANCE_LABEL__", label),
        ("__INSTANCE_TITLE__", INSTANCE_TITLES[label]),
        ("__GIT_DESCRIBE__", describe),
    ):
        manifest = manifest.replace(token, value)
    left = re.findall(r"__[A-Z_]+__", manifest)
    if left:
        fail(f"unreplaced placeholders remain: {sorted(set(left))}")
    parsed = json.loads(manifest)  # fail fast on malformed JSON

    env = parsed["server"]["mcp_config"]["env"]
    # Read-only means read-only. These three are how a bundle stops being that.
    for forbidden in (
        "ODOO_MCP_ENABLE_WRITES",
        "ODOO_MCP_ELICIT_WRITES",
        "MCP_CHATTER_DIRECT",
    ):
        if forbidden in env:
            fail(f"{forbidden} must not appear in a read-only bundle")
    if "execute_method" not in env.get("ODOO_MCP_TOOLS_EXCLUDE", ""):
        fail("ODOO_MCP_TOOLS_EXCLUDE must exclude execute_method (see section 4)")
    if "${__dirname}" not in env.get("ODOO_MCP_POLICY_FILE", ""):
        fail("ODOO_MCP_POLICY_FILE must point at the vendored policy file")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--instance-label", required=True, choices=sorted(INSTANCE_TITLES)
    )
    parser.add_argument("--odoo-url", required=True)
    parser.add_argument("--odoo-db", required=True)
    parser.add_argument("--out", default="dist")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    version = project_version()
    check_version(version)
    describe = check_tree(args.allow_dirty)
    check_instance(args.instance_label, args.odoo_url, args.odoo_db)
    check_policy()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / f"burke-odoo-{args.instance_label}-readonly-{version}.mcpb"

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        wheel = build_wheel(work)
        manifest = render_manifest(
            version=version,
            wheel=wheel.name,
            url=args.odoo_url,
            db=args.odoo_db,
            label=args.instance_label,
            describe=describe,
        )
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("manifest.json", manifest)
            bundle.write(wheel, f"wheels/{wheel.name}")
            bundle.write(POLICY, "odoo_mcp_policy.json")
            icon = ROOT / "mcpb" / "icon.png"
            if icon.exists():
                bundle.write(icon, "icon.png")

    env = json.loads(manifest)["server"]["mcp_config"]["env"]
    print(f"\nbuilt: {bundle_path}")
    print(f"  version   {version}  (git {describe})")
    print(f"  instance  {args.instance_label}  {args.odoo_url}  db={args.odoo_db}")
    print(f"  excluded  {env['ODOO_MCP_TOOLS_EXCLUDE']}")
    print("  writes    disabled (no ODOO_MCP_ENABLE_WRITES in the manifest)")
    print("  prompts   Odoo login + API key only")


if __name__ == "__main__":
    main()
