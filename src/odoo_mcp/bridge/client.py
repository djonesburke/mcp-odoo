"""Per-user, read-only Odoo access for the bridge.

* ``BridgeOdooClient`` refuses any RPC method outside the read set before a
  network call (defense in depth beneath the tool allowlist).
* ``verify_odoo_login`` proves a login/API-key pair over JSON-2 only and
  returns the uid the key belongs to.
* ``UserClientCache`` keeps one client per token digest, never longer than
  the token lives, bounded in size.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from ..diagnostics import READ_ONLY_METHODS
from ..odoo_client import OdooClient

#: ``READ_ONLY_METHODS`` plus the two read-only aggregation methods that
#: ``aggregate_records`` and ``data_quality_report`` call. Nothing that
#: mutates data belongs here.
BRIDGE_RPC_METHODS = frozenset(READ_ONLY_METHODS | {"read_group", "formatted_read_group"})


class BridgeMethodRefused(PermissionError):
    """An RPC method outside the bridge's read-only set was attempted."""


class BridgeAuthError(Exception):
    """Odoo credentials were not accepted (message is deliberately generic)."""


def _guard(method: str) -> None:
    if method not in BRIDGE_RPC_METHODS:
        raise BridgeMethodRefused(
            f"RPC method {method!r} is refused: the bridge is read-only"
        )


class BridgeOdooClient(OdooClient):
    """OdooClient that can only call read-only RPC methods."""

    def _execute(self, model: str, method: str, *args: Any, **kwargs: Any) -> Any:
        _guard(method)
        return super()._execute(model, method, *args, **kwargs)

    def _execute_once(
        self,
        model: str,
        method: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        _guard(method)
        return super()._execute_once(model, method, args, kwargs)

    def _json2_call(self, model: str, method: str, payload: dict[str, Any]) -> Any:
        _guard(method)
        return super()._json2_call(model, method, payload)


def build_user_client(
    *,
    url: str,
    db: str,
    login: str,
    key: str,
    timeout: int = 30,
    verify_ssl: bool = True,
) -> BridgeOdooClient:
    """Build a JSON-2 client authenticated by the user's own API key."""
    return BridgeOdooClient(
        url=url,
        db=db,
        username=login,
        password="",
        timeout=timeout,
        verify_ssl=verify_ssl,
        transport="json2",
        api_key=key,
    )


def verify_odoo_login(
    *,
    url: str,
    db: str,
    login: str,
    key: str,
    timeout: int = 30,
    verify_ssl: bool = True,
) -> int:
    """Authenticate ``login`` + ``key`` against Odoo over JSON-2; return the uid.

    The key identifies its owner; the typed login must match that owner's
    login (case-insensitive). Any failure raises :class:`BridgeAuthError`
    with no detail, so the sign-in page cannot be used as an oracle.
    """
    if not login or not key:
        raise BridgeAuthError("invalid credentials")
    try:
        client = build_user_client(
            url=url, db=db, login=login, key=key, timeout=timeout, verify_ssl=verify_ssl
        )
        context = client.execute_method("res.users", "context_get")
        uid = context.get("uid") if isinstance(context, dict) else None
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 1:
            raise BridgeAuthError("invalid credentials")
        rows = client.execute_method("res.users", "read", ids=[uid], fields=["login"])
        owner = rows[0].get("login") if isinstance(rows, list) and rows else None
    except BridgeAuthError:
        raise
    except Exception as exc:  # noqa: BLE001 - never leak transport detail
        raise BridgeAuthError("invalid credentials") from exc
    if not isinstance(owner, str) or owner.strip().lower() != login.strip().lower():
        raise BridgeAuthError("invalid credentials")
    return uid


def token_digest(token: str) -> str:
    """Opaque cache key for a token id."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserClientCache:
    """One client per token id; TTL capped by the token's own expiry."""

    def __init__(self, max_entries: int = 128, clock: Callable[[], float] = time.time):
        self._max = max(1, max_entries)
        self._clock = clock
        self._entries: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def get_or_build(
        self, token: str, expires_at: float | None, factory: Callable[[], Any]
    ) -> Any:
        digest = token_digest(token)
        now = self._clock()
        with self._lock:
            hit = self._entries.get(digest)
            if hit is not None and hit[0] > now:
                self._entries.move_to_end(digest)
                return hit[1]
            self._entries.pop(digest, None)
        client = factory()
        lifetime = float(expires_at) if expires_at else now + 300.0
        with self._lock:
            self._entries[digest] = (lifetime, client)
            self._entries.move_to_end(digest)
            for stale in [k for k, (exp, _) in self._entries.items() if exp <= now]:
                self._entries.pop(stale, None)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
        return client

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
