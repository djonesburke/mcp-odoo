"""OAuth authorization server for the bridge (per-user, stateless tokens).

Implements the SDK's ``OAuthAuthorizationServerProvider`` protocol:

* dynamic client registration of public PKCE clients (non-secret JSON on disk),
* ``/authorize`` -> bridge-served sign-in page (Odoo login + Odoo API key),
* single-use in-memory auth codes (5 minutes),
* access/refresh tokens sealed with AES-256-GCM (nothing about users at rest),
* refresh re-verifies the key against Odoo, so a revoked key ends access,
* revocation into a bounded in-memory deny set.
"""

from __future__ import annotations

import asyncio
import hmac
import html
import json
import logging
import os
import secrets
import tempfile
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from .client import BridgeAuthError, BridgeUnavailableError
from .config import DEFAULT_REDIRECT_HOSTS
from .netutil import (
    BoundedWindowLimiter,
    TrustedProxies,
    client_ip,
    request_ip_var,
)
from .seal import seal, unseal

logger = logging.getLogger(__name__)

ACCESS_TTL_SECONDS = 3600
REFRESH_TTL_SECONDS = 30 * 24 * 3600
CODE_TTL_SECONDS = 300
PENDING_TTL_SECONDS = 600
MAX_PENDING = 500
MAX_CODES = 500
#: Live denials: every rotated refresh token is denied until its own expiry.
MAX_DENIED = 100_000
#: Live denials one user may hold (an hourly refresher holds about 720 a month).
MAX_DENIED_PER_UID = 1500
MAX_CLIENTS = 1000
#: A client that never completed a sign-in is forgotten after this long.
UNUSED_CLIENT_TTL_SECONDS = 24 * 3600
MAX_PENDING_PER_IP = 5
REVOKED = "revoked"
JTI_BYTES = 16
LOGIN_ATTEMPTS_PER_MINUTE = 5
DEFAULT_SCOPE = "odoo.read"
SIGNIN_PATH = "/signin"

#: ``(login, api_key) -> uid``; raises ``BridgeAuthError`` on rejection and
#: ``BridgeUnavailableError`` when Odoo cannot be reached.
Verifier = Callable[[str, str], int]


class BridgeAuthorizationCode(AuthorizationCode):
    uid: int
    login: str
    odoo_key: str = Field(repr=False, exclude=True)


class BridgeRefreshToken(RefreshToken):
    jti: str
    uid: int
    login: str
    odoo_key: str = Field(repr=False, exclude=True)


class BridgeAccessToken(AccessToken):
    jti: str
    uid: int
    login: str
    odoo_key: str = Field(repr=False, exclude=True)


class _Denial:
    __slots__ = ("expires_at", "owner", "uid")

    def __init__(self, expires_at: float, owner: str, uid: int | None) -> None:
        self.expires_at = expires_at
        self.owner = owner  # REVOKED, or the nonce of the refresh that claimed it
        self.uid = uid


class _Pending:
    __slots__ = ("client_id", "params", "csrf", "expires_at", "ip")

    def __init__(
        self, client_id: str, params: AuthorizationParams, expires_at: float, ip: str
    ):
        self.ip = ip
        self.client_id = client_id
        self.params = params
        self.csrf = secrets.token_urlsafe(32)
        self.expires_at = expires_at


def _restrict(path: Path) -> None:
    """Owner-only permissions on POSIX."""
    if os.name == "posix":
        os.chmod(path, 0o600)


def _new_jti() -> str:
    return secrets.token_urlsafe(JTI_BYTES)


def _secure(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    )
    return response


class BridgeOAuthProvider:
    """Per-user OAuth provider; see module docstring."""

    def __init__(
        self,
        *,
        seal_key: bytes,
        instance: str,
        public_url: str,
        state_dir: str | os.PathLike[str],
        verifier: Verifier,
        allowed_redirect_hosts: tuple[str, ...] = DEFAULT_REDIRECT_HOSTS,
        allow_localhost_redirects: bool = False,
        client_ip_header: str | None = None,
        trusted_proxies: TrustedProxies | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = seal_key
        self.instance = instance
        self.public_url = public_url.rstrip("/")
        self._verifier = verifier
        self._allowed_hosts = tuple(h.lower() for h in allowed_redirect_hosts)
        self._allow_localhost = allow_localhost_redirects
        self._ip_header = client_ip_header.lower() if client_ip_header else None
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: OrderedDict[str, _Pending] = OrderedDict()
        self._codes: OrderedDict[str, BridgeAuthorizationCode] = OrderedDict()
        self._denied: OrderedDict[str, _Denial] = OrderedDict()
        self._trusted = trusted_proxies or TrustedProxies()
        self._login_limiter = BoundedWindowLimiter(LOGIN_ATTEMPTS_PER_MINUTE, clock=clock)
        self._state_dir = Path(state_dir)
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._clients_path = self._state_dir / "clients.json"
        self._meta: dict[str, dict[str, float | None]] = {}
        self._clients: dict[str, OAuthClientInformationFull] = self._load_clients()
        if self._clients_path.exists():
            _restrict(self._clients_path)

    # ------------------------------------------------------------------ clients

    def _load_clients(self) -> dict[str, OAuthClientInformationFull]:
        try:
            raw = json.loads(self._clients_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            logger.warning("bridge clients.json unreadable; starting with no clients")
            return {}
        clients: dict[str, OAuthClientInformationFull] = {}
        if isinstance(raw, dict):
            entries = raw.get("clients", [])
            meta = raw.get("meta", {})
        else:  # first-version file: a bare list
            entries, meta = raw, {}
        now = self._clock()
        for entry in entries if isinstance(entries, list) else []:
            try:
                info = OAuthClientInformationFull.model_validate(entry)
            except ValueError:
                continue
            uris = [str(u) for u in (info.redirect_uris or [])]
            if not uris or not all(self._redirect_allowed(u) for u in uris):
                logger.warning(
                    "bridge dropped registered client %s: redirect URI is not allowed",
                    info.client_id,
                )
                continue
            clients[info.client_id] = info
            entry_meta = meta.get(info.client_id) if isinstance(meta, dict) else None
            registered = entry_meta.get("registered_at") if isinstance(entry_meta, dict) else None
            used = entry_meta.get("last_used") if isinstance(entry_meta, dict) else None
            self._meta[info.client_id] = {
                "registered_at": float(registered) if isinstance(registered, (int, float)) else now,
                "last_used": float(used) if isinstance(used, (int, float)) else None,
            }
        return clients

    def _persist_clients_locked(self) -> None:
        payload = json.dumps(
            {
                "version": 2,
                "clients": [
                    c.model_dump(mode="json", exclude_none=True) for c in self._clients.values()
                ],
                "meta": self._meta,
            },
            indent=1,
        )
        fd, tmp = tempfile.mkstemp(dir=self._state_dir, prefix=".clients-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, self._clients_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _redirect_allowed(self, uri: str) -> bool:
        """Exact-host https allowlist; http://localhost only under a test flag."""
        parsed = urlparse(uri)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "https":
            return host in self._allowed_hosts
        if parsed.scheme == "http" and self._allow_localhost:
            return host in {"localhost", "127.0.0.1", "::1"}
        return False

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris or not all(self._redirect_allowed(u) for u in uris):
            raise RegistrationError(
                "invalid_redirect_uri",
                "redirect URIs must be https on an allowed host",
            )
        # Public PKCE client: never persist (or honour) a secret.
        stored = client_info.model_copy(
            update={
                "client_secret": None,
                "client_secret_expires_at": None,
                "token_endpoint_auth_method": "none",
            }
        )
        now = self._clock()
        with self._lock:
            if len(self._clients) >= MAX_CLIENTS and not self._evict_unused_locked(now):
                raise RegistrationError(
                    "invalid_client_metadata", "client registration is full; try later"
                )
            self._clients[stored.client_id] = stored
            self._meta[stored.client_id] = {"registered_at": now, "last_used": None}
            self._persist_clients_locked()

    def _evict_unused_locked(self, now: float) -> bool:
        """Drop expired never-used clients (oldest first) until there is room."""
        expired = sorted(
            (
                (meta["registered_at"] or 0.0, client_id)
                for client_id, meta in self._meta.items()
                if client_id in self._clients
                and meta.get("last_used") is None
                and (meta["registered_at"] or 0.0) + UNUSED_CLIENT_TTL_SECONDS <= now
            )
        )
        for _, client_id in expired:
            if len(self._clients) < MAX_CLIENTS:
                break
            del self._clients[client_id]
            self._meta.pop(client_id, None)
        return len(self._clients) < MAX_CLIENTS

    def _touch_client(self, client_id: str) -> None:
        with self._lock:
            meta = self._meta.get(client_id)
            if meta is None or client_id not in self._clients:
                return
            meta["last_used"] = self._clock()
            self._persist_clients_locked()

    # ---------------------------------------------------------------- authorize

    def _prune_locked(self, now: float) -> None:
        for key in [k for k, v in self._pending.items() if v.expires_at <= now]:
            del self._pending[key]
        for code in [k for k, v in self._codes.items() if v.expires_at <= now]:
            del self._codes[code]

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        now = self._clock()
        request_id = secrets.token_urlsafe(24)
        if not self._redirect_allowed(str(params.redirect_uri)):
            raise AuthorizeError("invalid_request", "redirect URI is not allowed")
        ip = request_ip_var.get() or "unknown"
        with self._lock:
            self._prune_locked(now)
            if sum(1 for p in self._pending.values() if p.ip == ip) >= MAX_PENDING_PER_IP:
                # one address cannot fill the table for everyone else
                raise AuthorizeError(
                    "temporarily_unavailable", "too many sign-ins from your address"
                )
            if len(self._pending) >= MAX_PENDING:
                # never evict someone mid sign-in; refuse the newcomer
                raise AuthorizeError("temporarily_unavailable", "too many sign-ins in progress")
            self._pending[request_id] = _Pending(
                client.client_id, params, now + PENDING_TTL_SECONDS, ip
            )
        return f"{self.public_url}{SIGNIN_PATH}?req={request_id}"

    def _client_ip(self, request: Request) -> str:
        return client_ip(request, self._ip_header, self._trusted)

    def _form(
        self, request_id: str, pending: _Pending, *, login: str = "", error: str = ""
    ) -> Response:
        client = self._clients.get(pending.client_id)
        label = html.escape((client.client_name if client else None) or "an MCP client")
        host = html.escape(urlparse(str(pending.params.redirect_uri)).netloc)
        notice = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>body{{font-family:system-ui,sans-serif;max-width:26rem;margin:3rem auto;padding:0 1rem}}
label{{display:block;margin-top:1rem}}input{{width:100%;padding:.5rem;box-sizing:border-box}}
button{{margin-top:1.5rem;padding:.6rem 1rem}}.err{{color:#b00020}}.fine{{color:#555;font-size:.85rem}}</style>
</head><body>
<h1>Sign in to Odoo</h1>
<p><strong>{label}</strong> ({host}) is asking for read-only access to Odoo as you.</p>
{notice}
<form method="post" action="{SIGNIN_PATH}" autocomplete="off">
<input type="hidden" name="req" value="{html.escape(request_id)}">
<input type="hidden" name="csrf" value="{html.escape(pending.csrf)}">
<label>Odoo login<input name="login" value="{html.escape(login)}" required autocomplete="username"></label>
<label>Odoo API key<input name="api_key" type="password" required autocomplete="off"></label>
<button type="submit">Sign in</button>
</form>
<p class="fine">Your API key is checked against Odoo and sealed into a token that
expires in one hour. It is never written to disk or logged.</p>
</body></html>"""
        return _secure(HTMLResponse(body))

    async def signin_get(self, request: Request) -> Response:
        request_id = request.query_params.get("req", "")
        with self._lock:
            self._prune_locked(self._clock())
            pending = self._pending.get(request_id)
        if pending is None:
            return _secure(HTMLResponse("This sign-in link has expired.", status_code=400))
        return self._form(request_id, pending)

    async def signin_post(self, request: Request) -> Response:
        form = await request.form()
        request_id = str(form.get("req", ""))
        csrf = str(form.get("csrf", ""))
        login = str(form.get("login", "")).strip()
        api_key = str(form.get("api_key", ""))
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            pending = self._pending.get(request_id)
        if pending is None:
            return _secure(HTMLResponse("This sign-in link has expired.", status_code=400))
        if not hmac.compare_digest(csrf.encode(), pending.csrf.encode()):
            return _secure(HTMLResponse("Invalid request.", status_code=403))
        if not self._login_limiter.hit(self._client_ip(request)):
            return _secure(
                HTMLResponse("Too many attempts. Wait a minute and try again.", status_code=429)
            )
        try:
            uid = await asyncio.to_thread(self._verifier, login, api_key)
        except BridgeUnavailableError:
            return _secure(
                HTMLResponse(
                    "Odoo is not reachable right now. Try again shortly.", status_code=503
                )
            )
        except BridgeAuthError:
            with self._lock:
                pending.csrf = secrets.token_urlsafe(32)
            return self._form(
                request_id,
                pending,
                login=login,
                error="Sign-in failed. Check your login and API key.",
            )
        with self._lock:
            if self._pending.pop(request_id, None) is None:
                return _secure(HTMLResponse("This sign-in link has expired.", status_code=400))
            if len(self._codes) >= MAX_CODES:
                return _secure(HTMLResponse("Busy. Try again shortly.", status_code=503))
            code = secrets.token_urlsafe(32)
            params = pending.params
            self._codes[code] = BridgeAuthorizationCode(
                code=code,
                scopes=params.scopes or [DEFAULT_SCOPE],
                expires_at=now + CODE_TTL_SECONDS,
                client_id=pending.client_id,
                code_challenge=params.code_challenge,
                redirect_uri=params.redirect_uri,
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                resource=params.resource,
                subject=f"{self.instance}:{uid}",
                uid=uid,
                login=login,
                odoo_key=api_key,
            )
        self._touch_client(pending.client_id)
        target = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
        return _secure(RedirectResponse(target, status_code=302))

    def routes(self) -> list[Route]:
        return [
            Route(SIGNIN_PATH, self.signin_get, methods=["GET"]),
            Route(SIGNIN_PATH, self.signin_post, methods=["POST"]),
        ]

    # ------------------------------------------------------------------- tokens

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> BridgeAuthorizationCode | None:
        with self._lock:
            self._prune_locked(self._clock())
            code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        return code

    def _issue(
        self, client_id: str, uid: int, login: str, key: str, scopes: list[str]
    ) -> OAuthToken:
        now = int(self._clock())
        base = {
            "v": 1,
            "uid": uid,
            "login": login,
            "key": key,
            "instance": self.instance,
            "iat": now,
            "cid": client_id,  # binds the token to the connector that obtained it
        }
        access = seal(
            self._key,
            {**base, "typ": "access", "exp": now + ACCESS_TTL_SECONDS, "jti": _new_jti()},
        )
        refresh = seal(
            self._key,
            {**base, "typ": "refresh", "exp": now + REFRESH_TTL_SECONDS, "jti": _new_jti()},
        )
        self._touch_client(client_id)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TTL_SECONDS,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: BridgeAuthorizationCode
    ) -> OAuthToken:
        with self._lock:
            stored = self._codes.pop(authorization_code.code, None)
        if stored is None:  # single use
            raise TokenError("invalid_grant", "authorization code is not valid")
        return self._issue(
            client.client_id, stored.uid, stored.login, stored.odoo_key, stored.scopes
        )

    def _unseal_typed(self, token: str, typ: str) -> dict[str, Any] | None:
        payload = unseal(self._key, token)
        if payload is None or payload.get("v") != 1 or payload.get("typ") != typ:
            return None
        if payload.get("instance") != self.instance:
            return None
        exp, uid = payload.get("exp"), payload.get("uid")
        if not isinstance(exp, int) or exp <= self._clock():
            return None
        if not isinstance(uid, int) or not isinstance(payload.get("login"), str):
            return None
        if not isinstance(payload.get("key"), str):
            return None
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti or self.is_revoked(jti):
            return None
        return payload

    async def load_access_token(self, token: str) -> BridgeAccessToken | None:
        payload = self._unseal_typed(token, "access")
        if payload is None:
            return None
        return BridgeAccessToken(
            jti=payload["jti"],
            token=token,
            client_id=str(payload.get("cid") or "odoo-mcp-bridge"),
            scopes=[DEFAULT_SCOPE],
            expires_at=payload["exp"],
            subject=f"{self.instance}:{payload['uid']}",
            claims={"login": payload["login"], "instance": self.instance},
            uid=payload["uid"],
            login=payload["login"],
            odoo_key=payload["key"],
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> BridgeRefreshToken | None:
        payload = self._unseal_typed(refresh_token, "refresh")
        if payload is None or payload.get("cid") != client.client_id:
            return None
        return BridgeRefreshToken(
            jti=payload["jti"],
            token=refresh_token,
            client_id=client.client_id,
            scopes=[DEFAULT_SCOPE],
            expires_at=payload["exp"],
            subject=f"{self.instance}:{payload['uid']}",
            uid=payload["uid"],
            login=payload["login"],
            odoo_key=payload["key"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: BridgeRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Claim the token first, atomically: of two concurrent refreshes with
        # one token exactly one gets past this line.
        owner = secrets.token_urlsafe(8)
        claimed = self._claim(refresh_token.jti, refresh_token.expires_at, refresh_token.uid, owner)
        if claimed is None:
            raise TokenError("invalid_grant", "refresh token is not valid")
        if claimed is False:
            raise TokenError("invalid_request", "revocation list is full; try again later")
        try:
            uid = await asyncio.to_thread(
                self._verifier, refresh_token.login, refresh_token.odoo_key
            )
            if uid != refresh_token.uid:
                raise BridgeAuthError("invalid credentials")
        except BridgeUnavailableError as exc:
            self._release(refresh_token.jti, owner)
            raise TokenError(
                "invalid_request", "Odoo is temporarily unavailable; retry the refresh"
            ) from exc
        except BridgeAuthError as exc:
            self._release(refresh_token.jti, owner)  # not used up: the key was refused
            raise TokenError("invalid_grant", "credentials are no longer valid") from exc
        return self._issue(
            client.client_id,
            uid,
            refresh_token.login,
            refresh_token.odoo_key,
            scopes or [DEFAULT_SCOPE],
        )

    # --------------------------------------------------------------- revocation

    def _claim(
        self, jti: str, expires_at: int | float | None, uid: int | None, owner: str
    ) -> bool | None:
        """Add ``jti`` to the deny set.

        Returns ``True`` when recorded, ``None`` when it was already denied and
        ``False`` when the set (or this user's share of it) is full. A
        revocation (``owner == REVOKED``) takes over an in-flight refresh's
        claim so that claim can no longer be released. An unexpired denial is
        never evicted; a full set refuses instead.
        """
        now = self._clock()
        with self._lock:
            existing = self._denied.get(jti)
            if existing is not None:
                if owner == REVOKED and existing.owner != REVOKED:
                    existing.owner = REVOKED
                    return True
                return None
            if len(self._denied) >= MAX_DENIED:
                self._reclaim_expired_locked(now)
                if len(self._denied) >= MAX_DENIED:
                    return False
            if uid is not None:
                live = sum(1 for d in self._denied.values() if d.uid == uid)
                if live >= MAX_DENIED_PER_UID:
                    self._reclaim_expired_locked(now)
                    live = sum(1 for d in self._denied.values() if d.uid == uid)
                    if live >= MAX_DENIED_PER_UID:
                        return False
            self._denied[jti] = _Denial(float(expires_at or now + REFRESH_TTL_SECONDS), owner, uid)
            return True

    def _reclaim_expired_locked(self, now: float) -> None:
        for stale in [d for d, entry in self._denied.items() if entry.expires_at <= now]:
            del self._denied[stale]

    def _release(self, jti: str, owner: str) -> None:
        """Un-claim, but only if the entry is still this refresh's own claim."""
        with self._lock:
            entry = self._denied.get(jti)
            if entry is not None and entry.owner == owner:
                del self._denied[jti]

    def is_revoked(self, token_or_jti: str) -> bool:
        """True for a denied jti, or a sealed token whose jti is denied."""
        jti = token_or_jti
        payload = unseal(self._key, token_or_jti)
        if payload is not None and isinstance(payload.get("jti"), str):
            jti = payload["jti"]
        with self._lock:
            return jti in self._denied

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        jti = getattr(token, "jti", None)
        if not isinstance(jti, str):
            return
        uid = getattr(token, "uid", None)
        if self._claim(jti, token.expires_at, uid, REVOKED) is False:
            raise RuntimeError("revocation list is full; the token was not revoked")

    async def exchange_identity_assertion(self, client: Any, params: Any) -> OAuthToken:
        raise TokenError("unsupported_grant_type", "not supported")
