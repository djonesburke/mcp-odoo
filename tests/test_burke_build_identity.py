"""The build must be able to identify itself.

Burke ships this fork with a PEP 440 local-version suffix (``1.3.0+burke.1``).
Nothing else in the package exposes a version, so without these readouts there
is no way to tell whether a machine is running the Burke build or vanilla
upstream from PyPI when something misbehaves. That question comes up first in
every incident, so it gets tests.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

import pytest

from odoo_mcp import __main__ as cli
from odoo_mcp import server_core


def test_package_version_is_resolvable():
    """The installed distribution version is discoverable, not "unknown"."""
    assert server_core.package_version() != "unknown"


def test_package_version_never_raises(monkeypatch):
    """A metadata failure degrades to "unknown" rather than breaking health."""

    def _boom(_name):
        raise RuntimeError("metadata backend exploded")

    monkeypatch.setattr("importlib.metadata.version", _boom)
    assert server_core.package_version() == "unknown"


def test_runtime_security_report_exposes_package_version():
    """health_check's payload carries the version."""
    report = server_core.runtime_security_report()
    assert "package_version" in report
    assert report["package_version"] == server_core.package_version()


def test_cli_health_payload_exposes_package_version():
    """``odoo-mcp --health`` carries the version, with no Odoo connection."""
    args = argparse.Namespace(
        transport="stdio",
        host="127.0.0.1",
        port=8000,
        path="/mcp",
        log_level="INFO",
        allow_remote_http=False,
    )
    payload = cli.health_payload(args)
    assert payload["package_version"] == server_core.package_version()


def test_cli_version_flag_prints_and_exits():
    """``--version`` is a real flag: prints the version and exits 0.

    Run as a subprocess because argparse's ``action="version"`` exits the
    process, and because this is the exact invocation the per-PC acceptance
    checklist in docs/BURKE-DEPLOY.md tells an operator to run.
    """
    result = subprocess.run(
        [sys.executable, "-m", "odoo_mcp", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert server_core.package_version() in combined


def test_cli_version_flag_shows_burke_suffix_when_present():
    """If this is a Burke build, --version must say so.

    Guards the actual failure mode: a machine silently running vanilla upstream.
    Skipped only on a genuinely unsuffixed build, so it cannot hide a
    Burke build whose suffix went missing.
    """
    version = server_core.package_version()
    if "+burke" not in version:
        pytest.skip(f"not a Burke-suffixed build (version={version})")
    result = subprocess.run(
        [sys.executable, "-m", "odoo_mcp", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "+burke" in (result.stdout + result.stderr)
