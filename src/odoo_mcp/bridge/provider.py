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

from ..rate_limit import SlidingWindowRateTracker
from .client import BridgeAuthError, token_digest
from .seal import seal, unseal

logger = logging.getLogger(__name__)

ACCESS_TTL_SECONDS = 3600
REFRESH_TTL_SECONDS = 30 * 24 * 3600
CODE_TTL_SECONDS = 300
PENDING_TTL_SECONDS = 600
MAX_PENDING = 500
MAX_CODES = 500
MAX_DENIED = 10_000
MAX_CLIENTS = 1000
LOGIN_ATTEMPTS_PER_MINUTE = 5
DEFAULT_SCOPE = "odoo.read"
SIGNIN_PATH = "/signin"

#: ``(login, api_key) -> uid``; raises ``BridgeAuthError`` on rejection.
Verifier = Callable[[str, str], int]


class BridgeAuthorizationCode(AuthorizationCode):
    uid: int
    login: str
    odoo_key: str = Field(repr=False, exclude=True)


class BridgeRefreshToken(RefreshToken):
    uid: int
    login: str
    odoo_key: str = Field(repr=False, exclude=True)


class BridgeAccessToken(AccessToken):
    uid: int
    login: str
    odoo_key: str = Field(repr=False, exclude=True)


class _Pending:
    __slots__ = ("client_id", "params", "csrf", "expires_at")

    def __init__(self, client_id: str, params: AuthorizationParams, expires_at: float):
        self.client_id = client_id
        self.params = params
        self.csrf = secrets.token_urlsafe(32)
        self.expires_at = expires_at


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
        allowed_redirect_hosts: tuple[str, ...] = (),
        client_ip_header: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._key = seal_key
        self.instance = instance
        self.public_url = public_url.rstrip("/")
        self._verifier = verifier
        self._allowed_hosts = tuple(h.lower() for h in allowed_redirect_hosts)
        self._ip_header = client_ip_header.lower() if client_ip_header else None
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: OrderedDict[str, _Pending] = OrderedDict()
        self._codes: OrderedDict[str, BridgeAuthorizationCode] = OrderedDict()
        self._denied: OrderedDict[str, float] = OrderedDict()
        self._login_limiter = SlidingWindowRateTracker(
            window_seconds=60, max_calls=LOGIN_ATTEMPTS_PER_MINUTE
        )
        self._state_dir = Path(state_dir)
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._clients_path = self._state_dir / "clients.json"
        self._clients: dict[str, OAuthClientInformationFull] = self._load_clients()

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
        for entry in raw if isinstance(raw, list) else []:
            try:
                info = OAuthClientInformationFull.model_validate(entry)
            except ValueError:
                continue
            clients[info.client_id] = info
        return clients

    def _persist_clients_locked(self) -> None:
        payload = json.dumps(
            [c.model_dump(mode="json", exclude_none=True) for c in self._clients.values()],
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
        parsed = urlparse(uri)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "https":
            return not self._allowed_hosts or host in self._allowed_hosts
        # http is only for local tests and native loopback redirects.
        return parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris or not all(self._redirect_allowed(u) for u in uris):
            raise RegistrationError(
                "invalid_redirect_uri",
                "redirect URIs must be https (or http://localhost)",
            )
        # Public PKCE client: never persist (or honour) a secret.
        stored = client_info.model_copy(
            update={
                "client_secret": None,
                "client_secret_expires_at": None,
                "token_endpoint_auth_method": "none",
            }
        )
        with self._lock:
            if len(self._clients) >= MAX_CLIENTS:
                del self._clients[next(iter(self._clients))]
            self._clients[stored.client_id] = stored
            self._persist_clients_locked()

    # ---------------------------------------------------------------- authorize

    def _prune_locked(self, now: float) -> None:
        for key in [k for k, v in self._pending.items() if v.expires_at <= now]:
            del self._pending[key]
        for code in [k for k, v in self._codes.items() if v.expires_at <= now]:
            del self._codes[code]
        while len(self._pending) > MAX_PENDING:
            self._pending.popitem(last=False)
        while len(self._codes) > MAX_CODES:
            self._codes.popitem(last=False)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        now = self._clock()
        request_id = secrets.token_urlsafe(24)
        with self._lock:
            self._prune_locked(now)
            self._pending[request_id] = _Pending(
                client.client_id, params, now + PENDING_TTL_SECONDS
            )
        return f"{self.public_url}{SIGNIN_PATH}?req={request_id}"

    def _client_ip(self, request: Request) -> str:
        if self._ip_header:
            value = request.headers.get(self._ip_header, "")
            if value:
                return value.split(",")[-1].strip() or "unknown"
        return request.client.host if request.client else "unknown"

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
        verdict = self._login_limiter.record("signin", self._client_ip(request))
        if verdict["over_budget"]:
            return _secure(
                HTMLResponse("Too many attempts. Wait a minute and try again.", status_code=429)
            )
        try:
            uid = await asyncio.to_thread(self._verifier, login, api_key)
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
        access = seal(self._key, {**base, "typ": "access", "exp": now + ACCESS_TTL_SECONDS})
        refresh = seal(self._key, {**base, "typ": "refresh", "exp": now + REFRESH_TTL_SECONDS})
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
        if self.is_revoked(token):
            return None
        return payload

    async def load_access_token(self, token: str) -> BridgeAccessToken | None:
        payload = self._unseal_typed(token, "access")
        if payload is None:
            return None
        return BridgeAccessToken(
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
        try:
            uid = await asyncio.to_thread(
                self._verifier, refresh_token.login, refresh_token.odoo_key
            )
        except BridgeAuthError as exc:
            raise TokenError("invalid_grant", "credentials are no longer valid") from exc
        if uid != refresh_token.uid:
            raise TokenError("invalid_grant", "credentials are no longer valid")
        self._deny(refresh_token.token, refresh_token.expires_at)  # rotate
        return self._issue(
            client.client_id,
            uid,
            refresh_token.login,
            refresh_token.odoo_key,
            scopes or [DEFAULT_SCOPE],
        )

    # --------------------------------------------------------------- revocation

    def _deny(self, token: str, expires_at: int | float | None) -> None:
        digest = token_digest(token)
        now = self._clock()
        with self._lock:
            self._denied[digest] = float(expires_at or now + REFRESH_TTL_SECONDS)
            self._denied.move_to_end(digest)
            if len(self._denied) > MAX_DENIED:
                for stale in [d for d, exp in self._denied.items() if exp <= now]:
                    del self._denied[stale]
            while len(self._denied) > MAX_DENIED:
                self._denied.popitem(last=False)

    def is_revoked(self, token: str) -> bool:
        with self._lock:
            return token_digest(token) in self._denied

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self._deny(token.token, token.expires_at)

    async def exchange_identity_assertion(self, client: Any, params: Any) -> OAuthToken:
        raise TokenError("unsupported_grant_type", "not supported")
