"""Bridge configuration from the environment, with startup refusals.

The bridge is configured *only* by ``ODOO_MCP_BRIDGE_*`` variables plus
``ODOO_URL`` / ``ODOO_DB`` (and the usual ``ODOO_TIMEOUT`` / ``ODOO_VERIFY_SSL``).
It never reads a config file and never accepts a service credential.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

INSTANCE_LABELS = ("staging", "production")

#: Variables that would give the process an identity of its own.
SERVICE_CREDENTIAL_ENV = ("ODOO_PASSWORD", "ODOO_API_KEY", "ODOO_USERNAME")
#: Variables that would change the tool surface or add an instance.
FORBIDDEN_ENV = (
    "ODOO_CONFIG_FILE",
    "ODOO_MCP_TOOLS_INCLUDE",
    "ODOO_MCP_TOOLS_EXCLUDE",
    "ODOO_MCP_PLUGINS",
    "ODOO_MCP_ENABLE_WRITES",
)
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

DEFAULT_CALLS_PER_MINUTE = 60
DEFAULT_MAX_LIMIT = 200
DEFAULT_PORT = 8765
DEFAULT_POLICY_INSTANCE = "default"
DEFAULT_REDIRECT_HOSTS = ("claude.ai", "claude.com")
DEFAULT_TRUSTED_PROXIES = ("127.0.0.0/8", "::1/128")
#: The one MCP SDK version the bridge's internals were verified against.
TESTED_MCP_VERSION = "2.0.0"


class BridgeConfigError(ValueError):
    """Startup refused; the message is safe to print (no values)."""


@dataclass(frozen=True)
class BridgeConfig:
    odoo_url: str
    odoo_db: str
    instance: str
    public_url: str
    seal_key_path: str
    state_dir: str
    audit_log: str
    host: str
    port: int
    path: str = "/mcp"
    calls_per_minute: int = DEFAULT_CALLS_PER_MINUTE
    max_limit: int = DEFAULT_MAX_LIMIT
    timeout: int = 30
    verify_ssl: bool = True
    client_ip_header: str | None = None
    #: Key the field-ACL policy file uses for this instance's rules.
    policy_instance: str = DEFAULT_POLICY_INSTANCE
    #: Exact hosts allowed as https OAuth redirect targets.
    allowed_redirect_hosts: tuple[str, ...] = DEFAULT_REDIRECT_HOSTS
    #: Peers (IPs/CIDRs) whose client-IP header is believed. Default: loopback.
    trusted_proxies: tuple[str, ...] = DEFAULT_TRUSTED_PROXIES
    #: Test only: also accept http://localhost redirects. Off by default.
    allow_localhost_redirects: bool = False
    extra_allowed_origins: tuple[str, ...] = ()
    #: Odoo logins (lowercased, as the verifier compares) allowed to sign in. ``None``: any Odoo user.
    allowed_logins: frozenset[str] | None = None
    #: Per-login field-ACL policy files (login lowercased -> absolute path). A
    #: login not named here reads under the instance policy.
    login_policies: tuple[tuple[str, str], ...] = ()

    @property
    def public_host(self) -> str:
        return urlparse(self.public_url).netloc


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(item.strip() for item in (value or "").split(",") if item.strip())


def _networks(raw: str | None) -> tuple[str, ...]:
    import ipaddress

    items = _csv(raw)
    for item in items:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise BridgeConfigError(
                "ODOO_MCP_BRIDGE_TRUSTED_PROXIES must be a list of IPs or CIDRs"
            ) from exc
    return items or DEFAULT_TRUSTED_PROXIES


def _logins(raw: str | None) -> frozenset[str] | None:
    """Parse the sign-in allowlist; unset means any Odoo user may sign in."""
    if raw is None:
        return None
    # Present means on: an empty value (say, an unset template variable) must
    # not quietly open the gate, so it refuses startup instead.
    items = frozenset(item.lower() for item in _csv(raw))
    if not items:
        raise BridgeConfigError("ODOO_MCP_BRIDGE_ALLOWED_LOGINS is set but names no login")
    return items


def _login_policies(
    raw: str | None, allowed: frozenset[str] | None
) -> tuple[tuple[str, str], ...]:
    """Parse ``login=/abs/path,login=/abs/path``; refuse anything ambiguous."""
    if raw is None:
        return ()
    items = _csv(raw)
    if not items:
        raise BridgeConfigError("ODOO_MCP_BRIDGE_LOGIN_POLICIES is set but names no login")
    seen: dict[str, str] = {}
    for item in items:
        login, sep, path = item.partition("=")
        login, path = login.strip().lower(), path.strip()
        if not sep or not login or not path:
            raise BridgeConfigError(
                "ODOO_MCP_BRIDGE_LOGIN_POLICIES entries must be login=/absolute/path"
            )
        if not (path.startswith("/") or Path(path).is_absolute()):
            raise BridgeConfigError("ODOO_MCP_BRIDGE_LOGIN_POLICIES paths must be absolute")
        if login in seen:
            raise BridgeConfigError("ODOO_MCP_BRIDGE_LOGIN_POLICIES names a login twice")
        if allowed is None or login not in allowed:
            # A per-login mask is only for a named, allowlisted person; a typo
            # here must not leave that person on a mask nobody chose.
            raise BridgeConfigError(
                "ODOO_MCP_BRIDGE_LOGIN_POLICIES names a login that is not on "
                "ODOO_MCP_BRIDGE_ALLOWED_LOGINS"
            )
        seen[login] = path
    return tuple(sorted(seen.items()))


def check_sdk_version(installed: str | None = None) -> None:
    """Refuse to run on an MCP SDK other than the one the bridge was verified on."""
    if installed is None:
        from importlib.metadata import PackageNotFoundError, version

        try:
            installed = version("mcp")
        except PackageNotFoundError:
            installed = "not installed"
    if installed != TESTED_MCP_VERSION:
        raise BridgeConfigError(
            f"mcp {installed} is installed but the bridge was verified against "
            f"mcp {TESTED_MCP_VERSION}; install the pinned version "
            "(pip install 'odoo-mcp[bridge]') or re-verify the SDK internals "
            "listed in docs/bridge.md and update TESTED_MCP_VERSION"
        )


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise BridgeConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise BridgeConfigError(f"{name} must be at least {minimum}")
    return value


def _require(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise BridgeConfigError(f"{name} is required")
    return value


def check_environment(env: Mapping[str, str]) -> None:
    """Refuse to start when the environment could weaken the bridge."""
    for name in SERVICE_CREDENTIAL_ENV:
        if env.get(name, "").strip():
            raise BridgeConfigError(
                f"{name} is set: the bridge has no service identity and refuses "
                "to start with Odoo credentials in its environment"
            )
    for name in FORBIDDEN_ENV:
        if env.get(name, "").strip():
            raise BridgeConfigError(
                f"{name} is set: the bridge is read-only by build, single-instance "
                "and env-configured; it refuses to start with this variable"
            )
    url = env.get("ODOO_URL", "")
    if any(sep in url for sep in (",", ";", " ")) or env.get("ODOO_DB", "").count(","):
        raise BridgeConfigError(
            "ODOO_URL/ODOO_DB name more than one Odoo instance: one instance per process"
        )


def load_config(env: Mapping[str, str] | None = None) -> BridgeConfig:
    """Validate the environment and build the configuration."""
    source: Mapping[str, str] = os.environ if env is None else env
    check_environment(source)

    odoo_url = _require(source, "ODOO_URL")
    odoo_db = _require(source, "ODOO_DB")
    instance = _require(source, "ODOO_MCP_BRIDGE_INSTANCE").lower()
    if instance not in INSTANCE_LABELS:
        raise BridgeConfigError(
            f"ODOO_MCP_BRIDGE_INSTANCE must be one of {', '.join(INSTANCE_LABELS)}"
        )
    public_url = _require(source, "ODOO_MCP_BRIDGE_PUBLIC_URL").rstrip("/")
    parsed = urlparse(public_url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.query or parsed.fragment:
        raise BridgeConfigError("ODOO_MCP_BRIDGE_PUBLIC_URL must be an absolute http(s) URL")
    if parsed.scheme != "https" and parsed.hostname not in LOCAL_HOSTS:
        raise BridgeConfigError("ODOO_MCP_BRIDGE_PUBLIC_URL must be https (localhost excepted)")
    if parsed.path not in ("", "/"):
        raise BridgeConfigError("ODOO_MCP_BRIDGE_PUBLIC_URL must not carry a path")

    verify_raw = source.get("ODOO_VERIFY_SSL", "1").strip().lower()
    allowed = _logins(source.get("ODOO_MCP_BRIDGE_ALLOWED_LOGINS"))
    return BridgeConfig(
        odoo_url=odoo_url,
        odoo_db=odoo_db,
        instance=instance,
        public_url=public_url,
        seal_key_path=_require(source, "ODOO_MCP_BRIDGE_SEAL_KEY_FILE"),
        state_dir=_require(source, "ODOO_MCP_BRIDGE_STATE_DIR"),
        audit_log=_require(source, "ODOO_MCP_BRIDGE_AUDIT_LOG"),
        host=source.get("ODOO_MCP_BRIDGE_HOST", "127.0.0.1").strip() or "127.0.0.1",
        port=_int(source, "ODOO_MCP_BRIDGE_PORT", DEFAULT_PORT),
        calls_per_minute=_int(
            source, "ODOO_MCP_BRIDGE_CALLS_PER_MINUTE", DEFAULT_CALLS_PER_MINUTE
        ),
        max_limit=_int(source, "ODOO_MCP_BRIDGE_MAX_LIMIT", DEFAULT_MAX_LIMIT),
        timeout=_int(source, "ODOO_TIMEOUT", 30),
        verify_ssl=verify_raw not in {"0", "false", "no", "off"},
        client_ip_header=(source.get("ODOO_MCP_BRIDGE_CLIENT_IP_HEADER", "").strip() or None),
        policy_instance=(
            source.get("ODOO_MCP_BRIDGE_POLICY_INSTANCE", "").strip()
            or DEFAULT_POLICY_INSTANCE
        ),
        allowed_redirect_hosts=(
            tuple(h.lower() for h in _csv(source.get("ODOO_MCP_BRIDGE_ALLOWED_REDIRECT_HOSTS")))
            or DEFAULT_REDIRECT_HOSTS
        ),
        trusted_proxies=_networks(source.get("ODOO_MCP_BRIDGE_TRUSTED_PROXIES")),
        allow_localhost_redirects=(
            source.get("ODOO_MCP_BRIDGE_ALLOW_LOCALHOST_REDIRECTS", "").strip().lower()
            in {"1", "true", "yes", "on"}
        ),
        extra_allowed_origins=_csv(source.get("ODOO_MCP_BRIDGE_ALLOWED_ORIGINS")),
        allowed_logins=allowed,
        login_policies=_login_policies(
            source.get("ODOO_MCP_BRIDGE_LOGIN_POLICIES"), allowed
        ),
    )
