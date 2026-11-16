"""Per-request identity, audit trail and throttling for the bridge.

Everything here is keyed by the *authenticated token of the current request*
(read from the SDK's auth context), never by process state. There is no
fallback to environment credentials and no shared client.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token

from ..rate_limit import SlidingWindowRateTracker
from ..schema_cache import BoundedTTLCache, _schema_cache_settings
from .client import UserClientCache, build_user_client
from .config import BridgeConfig, BridgeConfigError
from .provider import BridgeAccessToken

#: ``(login, key) -> client`` seam so tests never touch the network.
ClientFactory = Callable[[str, str], Any]

MAX_AUDIT_FIELDS = 50


_IS_POSIX = os.name == "posix"


def _file_mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class BridgeIdentityError(PermissionError):
    """No authenticated bridge user on this request."""


class BridgeAuditError(OSError):
    """The audit line could not be written; the result is withheld."""


def current_user() -> BridgeAccessToken:
    """The authenticated user of this request, or refuse."""
    token = get_access_token()
    if not isinstance(token, BridgeAccessToken):
        raise BridgeIdentityError("authentication required: no signed-in Odoo user")
    return token


class AuditLog:
    """Append-only JSONL, one line per tool call. Never values, tokens or keys."""

    def __init__(self, path: str, *, instance: str) -> None:
        self.path = path
        self.instance = instance
        self._lock = threading.Lock()

    def check_writable(self) -> None:
        """Create the file (0600 on POSIX) if needed and prove it is appendable."""
        if _IS_POSIX and os.path.exists(self.path):
            mode = _file_mode(self.path)
            if mode & 0o077:
                raise BridgeConfigError(
                    f"audit file {self.path} is group/world accessible "
                    f"(mode {mode:04o}); run chmod 600"
                )
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.close(fd)

    def record(
        self,
        *,
        uid: int | None,
        login: str | None,
        tool: str,
        model: str | None,
        fields: list[str],
        records: int | None,
        duration_ms: int,
        outcome: str,
    ) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "instance": self.instance,
            "uid": uid,
            "login": login,
            "tool": tool,
            "model": model,
            "fields": fields[:MAX_AUDIT_FIELDS],
            "records": records,
            "duration_ms": duration_ms,
            "outcome": outcome,
        }
        line = json.dumps(entry, sort_keys=True, default=str)
        try:
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except OSError as exc:
            raise BridgeAuditError("audit log is not writable") from exc


@dataclass
class BridgeRuntime:
    """Process-wide bridge state (no per-user data lives here beyond caches)."""

    config: BridgeConfig
    audit: AuditLog
    client_factory: ClientFactory
    clients: UserClientCache = field(default_factory=UserClientCache)
    limiter: SlidingWindowRateTracker | None = None
    _schema_caches: dict[int, BoundedTTLCache] = field(default_factory=dict)
    _schema_lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.limiter is None:
            self.limiter = SlidingWindowRateTracker(
                window_seconds=60, max_calls=self.config.calls_per_minute
            )

    @classmethod
    def default_client_factory(cls, config: BridgeConfig) -> ClientFactory:
        def factory(login: str, key: str) -> Any:
            return build_user_client(
                url=config.odoo_url,
                db=config.odoo_db,
                login=login,
                key=key,
                timeout=config.timeout,
                verify_ssl=config.verify_ssl,
            )

        return factory

    def client_for(self, token: BridgeAccessToken) -> Any:
        """One client per token id (jti), expiring with the token."""
        return self.clients.get_or_build(
            token.jti,
            token.expires_at,
            lambda: self.client_factory(token.login, token.odoo_key),
        )

    def schema_cache_for(self, uid: int) -> BoundedTTLCache:
        """Field metadata depends on the caller's rights: cache per user."""
        with self._schema_lock:
            cache = self._schema_caches.get(uid)
            if cache is None:
                if len(self._schema_caches) >= 64:
                    self._schema_caches.pop(next(iter(self._schema_caches)))
                max_entries, ttl = _schema_cache_settings()
                cache = BoundedTTLCache(max_entries, ttl)
                self._schema_caches[uid] = cache
            return cache


def make_runtime(config: BridgeConfig) -> BridgeRuntime:
    audit = AuditLog(config.audit_log, instance=config.instance)
    return BridgeRuntime(
        config=config,
        audit=audit,
        client_factory=BridgeRuntime.default_client_factory(config),
    )


def ensure_state_dir(path: str) -> None:
    """Create the state directory owner-only (POSIX) and tighten an existing one."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
