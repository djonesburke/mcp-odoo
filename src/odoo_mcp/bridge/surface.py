"""The bridge's tool surface: read-only by build, identity per request.

* ``READ_ALLOWLIST`` is a hard-coded constant. After every tool registers,
  anything not on it is removed, then the result is asserted to equal the
  allowlist and to contain nothing from ``WRITE_DENYLIST``. No environment
  variable can widen it.
* ``BridgeAppContext`` replaces the shared lifespan context so no Odoo client
  is cached across users.
* ``wrap_tool`` adds per-user throttling, record-limit caps and the audit line.
"""

from __future__ import annotations

import functools
import inspect
import re
import time
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from .. import server as srv
from ..server_core import READ_ONLY_TOOL, AppContext, mcp, package_version
from .runtime import (
    BridgeIdentityError,
    BridgeRuntime,
    current_user,
)

#: The only tools the bridge exposes. Every one reads Odoo as the signed-in
#: user (or is pure/local and side-effect free). Derived from the registered
#: tools and their annotations; see docs/bridge.md for the reason per tool.
READ_ALLOWLIST = frozenset(
    {
        "aggregate_records",
        "build_domain",
        "data_quality_report",
        "diagnose_access",
        "get_model_fields",
        "get_odoo_profile",
        "health_check",
        "inspect_model_relationships",
        "list_models",
        "read_attachment",
        "read_record",
        "schema_catalog",
        "search_records",
    }
)

#: Tools that must never be present, whatever else happens. A superset of
#: everything excluded from the allowlist, kept explicit on purpose.
WRITE_DENYLIST = frozenset(
    {
        # Writes to Odoo
        "execute_approved_write",
        "preview_write",
        "validate_write",
        "chatter_post",
        "execute_method",
        "generate_json2_payload",
        # Async queue (runs arbitrary operations, shared across callers)
        "submit_async_task",
        "cancel_async_task",
        "get_async_task",
        "list_async_tasks",
        # Local files / shared local index
        "index_knowledge",
        "search_knowledge",
        "knowledge_stats",
        "scan_addons_source",
        # Cross-instance and instance listing
        "search_across_instances",
        "aggregate_across_instances",
        "accounting_health_across_instances",
        "list_instances",
        # Finance, HR, credentials
        "accounting_health_summary",
        "receivable_payable_aging",
        "search_employee",
        "search_holidays",
        "check_api_key_expiry",
    }
)

_FORBIDDEN_NAME = re.compile(
    r"(write|post|execute|submit|cancel|create|unlink|delete|index_|across_instances|accounting|employee|holiday)"
)

#: Parameters that bound how many records a read tool may ask for.
LIMIT_PARAMS = ("limit", "sample_limit", "module_limit")


class SurfaceError(RuntimeError):
    """The tool surface is not exactly the read-only allowlist."""


def _registry(server: Any) -> dict[str, Any]:
    registry = getattr(getattr(server, "_tool_manager", None), "_tools", None)
    if not isinstance(registry, dict):
        raise SurfaceError("the MCP tool registry has an unexpected shape; refusing to start")
    return registry


def restrict_tool_surface(server: Any = mcp) -> list[str]:
    """Remove everything off the allowlist, then assert the final surface."""
    registry = _registry(server)
    for name in list(registry):
        if name not in READ_ALLOWLIST:
            del registry[name]
    final = set(registry)
    leaked = sorted(final & WRITE_DENYLIST)
    if leaked:
        raise SurfaceError(f"denylisted tools present after restriction: {leaked}")
    pattern = sorted(n for n in final if _FORBIDDEN_NAME.search(n))
    if pattern:
        raise SurfaceError(f"write-like tool names present after restriction: {pattern}")
    if final != set(READ_ALLOWLIST):
        raise SurfaceError(
            "final tool set differs from the allowlist "
            f"(missing {sorted(READ_ALLOWLIST - final)}, extra {sorted(final - READ_ALLOWLIST)}); "
            "unset ODOO_MCP_TOOLS_INCLUDE/EXCLUDE and plugins"
        )
    for name, tool in registry.items():
        ann = getattr(tool, "annotations", None)
        if ann is None or ann.read_only_hint is not True or ann.destructive_hint:
            raise SurfaceError(f"tool {name!r} is not annotated read-only")
    return sorted(final)


# --------------------------------------------------------------------------
# Per-request context
# --------------------------------------------------------------------------


class BridgeAppContext(AppContext):
    """Lifespan context that never caches an Odoo client across users."""

    def __init__(self, runtime: BridgeRuntime) -> None:
        self._runtime = runtime
        super().__init__(odoo_factory=self._no_shared_client)
        # Field-ACL rules are looked up by this key, not by the public label.
        self._default_instance_name = runtime.config.policy_instance

    @staticmethod
    def _no_shared_client() -> Any:
        raise BridgeIdentityError("the bridge has no shared Odoo client")

    @property
    def odoo(self) -> Any:  # type: ignore[override]
        return self._runtime.client_for(current_user())

    def get_client(self, instance: Optional[str] = None) -> tuple[str, Any]:  # type: ignore[override]
        config = self._runtime.config
        if instance and instance not in (config.instance, config.policy_instance):
            raise ValueError(f"This bridge serves one instance only ({config.instance!r}).")
        return config.policy_instance, self.odoo

    @property
    def schema_cache(self) -> Any:  # type: ignore[override]
        return self._runtime.schema_cache_for(current_user().uid)

    @schema_cache.setter
    def schema_cache(self, value: Any) -> None:
        return None

    def __repr__(self) -> str:
        return "BridgeAppContext()"


def bridge_lifespan(runtime: BridgeRuntime) -> Callable[[Any], Any]:
    @asynccontextmanager
    async def lifespan(_: Any) -> AsyncIterator[BridgeAppContext]:
        yield BridgeAppContext(runtime)

    return lifespan


def install_seams(runtime: BridgeRuntime) -> Callable[[], None]:
    """Point the ``_srv()`` seams at the per-user runtime; returns an undo."""
    label = runtime.config.instance
    policy_key = runtime.config.policy_instance

    def check(instance: Optional[str]) -> None:
        if instance and instance not in (label, policy_key):
            raise ValueError(f"This bridge serves one instance only ({label!r}).")

    def get_odoo_client() -> Any:
        return runtime.client_for(current_user())

    def get_odoo_client_for(instance: str | None = None) -> tuple[str, Any]:
        check(instance)
        return policy_key, get_odoo_client()

    def resolve_default_instance_name() -> str:
        return policy_key

    def resolve_instance_name(instance: Optional[str]) -> str:
        check(instance)
        return policy_key

    def load_instances_config() -> tuple[str, dict[str, dict[str, Any]]]:
        return policy_key, {policy_key: {}}

    patches = {
        "get_odoo_client": get_odoo_client,
        "get_odoo_client_for": get_odoo_client_for,
        "resolve_default_instance_name": resolve_default_instance_name,
        "resolve_instance_name": resolve_instance_name,
        "load_instances_config": load_instances_config,
    }
    originals = {name: getattr(srv, name) for name in patches}
    for name, value in patches.items():
        setattr(srv, name, value)

    def undo() -> None:
        for name, value in originals.items():
            setattr(srv, name, value)

    return undo


# --------------------------------------------------------------------------
# Tool wrapping: identity, throttle, caps, audit
# --------------------------------------------------------------------------

_RECORD_KEYS = ("records", "rows", "result", "models", "groups")


def _count_records(result: Any) -> int | None:
    if not isinstance(result, dict):
        return None
    count = result.get("count")
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    for key in _RECORD_KEYS:
        value = result.get(key)
        if isinstance(value, list):
            return len(value)
    if isinstance(result.get("record"), dict):
        return 1
    return None


def _field_names(kwargs: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("fields", "field_names", "group_by", "measures"):
        value = kwargs.get(key)
        if isinstance(value, str):
            value = [value]
        if isinstance(value, (list, tuple)):
            names.extend(str(v)[:80] for v in value if isinstance(v, (str, int)))
    return names[:50]


_PROFILE_HIDDEN = (
    "url",
    "hostname",
    "database",
    "timeout",
    "verify_ssl",
    "json2_database_header",
)


def _redact_profile(result: Any) -> Any:
    """Never hand the backend address, DB name or TLS/timeout settings to a user."""
    if not isinstance(result, dict) or not isinstance(result.get("profile"), dict):
        return result
    profile = dict(result["profile"])
    for key in _PROFILE_HIDDEN:
        if key in profile:
            profile[key] = "<redacted>"
    for key in ("server_version", "user_context"):
        value = profile.get(key)
        if isinstance(value, dict) and "error" in value:
            profile[key] = {"error": "unavailable"}
    return {**result, "profile": profile}


_RESULT_FILTERS: dict[str, Callable[[Any], Any]] = {"get_odoo_profile": _redact_profile}


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"success": False, "error": message, **extra}


def wrap_tool(tool: Any, runtime: BridgeRuntime) -> None:
    """Wrap ``tool.fn`` (idempotently) with the bridge's per-call controls."""
    original = getattr(tool.fn, "_bridge_original", tool.fn)
    if inspect.iscoroutinefunction(original):  # pragma: no cover - none allowlisted
        raise SurfaceError(f"async tool {tool.name!r} is not supported by the bridge wrapper")
    signature = inspect.signature(original)
    defaults = {
        name: param.default
        for name, param in signature.parameters.items()
        if name in LIMIT_PARAMS and param.default is not inspect.Parameter.empty
    }
    name = tool.name
    cap = runtime.config.max_limit
    assert runtime.limiter is not None
    limiter = runtime.limiter

    @functools.wraps(original)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        uid: int | None = None
        login: str | None = None
        outcome = "ok"
        result: Any = None
        try:
            user = current_user()
            uid, login = user.uid, user.login
            verdict = limiter.record(runtime.config.instance, f"uid:{uid}")
            if verdict["over_budget"]:
                outcome = "rate_limited"
                result = _error(
                    f"Rate limit exceeded: {runtime.config.calls_per_minute} calls per minute.",
                    rate_limited=True,
                )
            else:
                for param in LIMIT_PARAMS:
                    asked = kwargs.get(param, defaults.get(param))
                    if isinstance(asked, int) and not isinstance(asked, bool) and asked > cap:
                        kwargs[param] = cap
                result = original(*args, **kwargs)
                result_filter = _RESULT_FILTERS.get(name)
                if result_filter is not None:
                    result = result_filter(result)
                if isinstance(result, dict) and result.get("success") is False:
                    outcome = "error"
        except BridgeIdentityError as exc:
            outcome = "unauthenticated"
            result = _error(str(exc))
        except Exception as exc:  # noqa: BLE001 - recorded, then re-raised
            outcome = f"exception:{type(exc).__name__}"
            _audit(runtime, uid, login, name, kwargs, None, started, outcome)
            raise
        _audit(runtime, uid, login, name, kwargs, _count_records(result), started, outcome)
        return result

    wrapper._bridge_original = original  # type: ignore[attr-defined]
    tool.fn = wrapper


def _audit(
    runtime: BridgeRuntime,
    uid: int | None,
    login: str | None,
    tool: str,
    kwargs: dict[str, Any],
    records: int | None,
    started: float,
    outcome: str,
) -> None:
    model = kwargs.get("model")
    runtime.audit.record(
        uid=uid,
        login=login,
        tool=tool,
        model=model if isinstance(model, str) else None,
        fields=_field_names(kwargs),
        records=records,
        duration_ms=int((time.perf_counter() - started) * 1000),
        outcome=outcome,
    )


# --------------------------------------------------------------------------
# Bridge health_check (replaces the upstream one, which reports server posture)
# --------------------------------------------------------------------------


def _bridge_health_check(runtime: BridgeRuntime) -> Callable[[], dict[str, Any]]:
    def health_check() -> dict[str, Any]:
        """Report the bridge's mode, Odoo instance label, tool list and limits."""
        user = current_user()
        return {
            "success": True,
            "tool": "health_check",
            "server": "odoo-mcp-bridge",
            "version": package_version(),
            "mode": "read-only, per-user",
            "instance": runtime.config.instance,
            "signed_in": {"uid": user.uid, "login": user.login},
            "tools": sorted(READ_ALLOWLIST),
            "limits": {
                "calls_per_minute": runtime.config.calls_per_minute,
                "max_record_limit": runtime.config.max_limit,
            },
        }

    return health_check


def replace_health_check(runtime: BridgeRuntime) -> None:
    registry = _registry(mcp)
    registry.pop("health_check", None)
    mcp.tool(
        name="health_check",
        description="Report the bridge mode, Odoo instance label, tools and limits",
        annotations=READ_ONLY_TOOL,
    )(_bridge_health_check(runtime))


def strip_non_tool_surface() -> None:
    """Drop resources and prompts: they bypass the tool controls or name write tools."""
    for manager_name, attrs in (
        ("_resource_manager", ("_resources", "_templates")),
        ("_prompt_manager", ("_prompts",)),
    ):
        manager = getattr(mcp, manager_name, None)
        for attr in attrs:
            store = getattr(manager, attr, None)
            if isinstance(store, dict):
                store.clear()
            else:  # pragma: no cover - SDK shape change
                raise SurfaceError(f"unexpected MCP {manager_name}.{attr}; refusing to start")


def apply_bridge_surface(runtime: BridgeRuntime) -> list[str]:
    """Build the final read-only surface for ``runtime``; returns tool names."""
    replace_health_check(runtime)
    names = restrict_tool_surface(mcp)
    strip_non_tool_surface()
    for tool in _registry(mcp).values():
        wrap_tool(tool, runtime)
    return names


def iter_tools() -> Iterator[Any]:  # pragma: no cover - debugging helper
    yield from _registry(mcp).values()


__all__ = [
    "READ_ALLOWLIST",
    "WRITE_DENYLIST",
    "BridgeAppContext",
    "SurfaceError",
    "apply_bridge_surface",
    "bridge_lifespan",
    "install_seams",
    "restrict_tool_surface",
    "wrap_tool",
]
