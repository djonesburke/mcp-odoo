"""OAuth HTTP surface for the bridge: public-client-only routes and IP throttling.

The SDK's route factory is reused, then three things are tightened:

* registration forces ``token_endpoint_auth_method: "none"`` before the SDK
  sees the request, so no client secret is minted or returned;
* the advertised metadata lists only ``none`` for token and revocation;
* ``/revoke`` accepts a public client that omits the (empty) ``client_secret``.

``IpThrottleMiddleware`` rate-limits ``/register``, ``/authorize``, ``/token``
and ``/revoke`` per client IP (bounded key table), and publishes the client IP
for provider hooks that never see the request.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlencode

from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.server.auth.routes import (
    REGISTRATION_PATH,
    REVOCATION_PATH,
    build_metadata,
    cors_middleware,
    create_auth_routes,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .netutil import BoundedWindowLimiter, TrustedProxies, client_ip, request_ip_var

WELL_KNOWN = "/.well-known/oauth-authorization-server"

#: Calls per minute per client IP.
THROTTLE_LIMITS = {"/register": 10, "/authorize": 30, "/token": 30, "/revoke": 30}


def _replay(request: Request, body: bytes) -> Request:
    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(request.scope, receive)


class PublicOnlyRegistration(RegistrationHandler):
    """Registration that only ever creates public (``none``) clients."""

    async def handle(self, request: Request) -> Response:
        raw = await request.body()
        try:
            data = json.loads(raw)
        except ValueError:
            return await super().handle(_replay(request, raw))
        if isinstance(data, dict):
            data["token_endpoint_auth_method"] = "none"
            raw = json.dumps(data).encode()
        return await super().handle(_replay(request, raw))


def _revoke_with_default_secret(handler: Any) -> Any:
    async def handle(request: Request) -> Response:
        pairs = parse_qsl((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
        if not any(k == "client_secret" for k, _ in pairs):
            pairs.append(("client_secret", ""))
        response: Response = await handler(_replay(request, urlencode(pairs).encode()))
        return response

    return handle


def build_oauth_routes(
    provider: OAuthAuthorizationServerProvider[Any, Any, Any],
    issuer_url: AnyHttpUrl,
    registration: ClientRegistrationOptions,
    revocation: RevocationOptions,
) -> list[Route]:
    """SDK routes with the public-client tightening applied."""
    routes = create_auth_routes(
        provider,
        issuer_url=issuer_url,
        client_registration_options=registration,
        revocation_options=revocation,
    )
    metadata = build_metadata(issuer_url, None, registration, revocation)
    metadata.token_endpoint_auth_methods_supported = ["none"]
    metadata.revocation_endpoint_auth_methods_supported = ["none"]

    out: list[Route] = []
    for route in routes:
        if route.path == WELL_KNOWN:
            route = Route(
                WELL_KNOWN,
                endpoint=cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"]),
                methods=["GET", "OPTIONS"],
            )
        elif route.path == REGISTRATION_PATH:
            route = Route(
                REGISTRATION_PATH,
                endpoint=cors_middleware(
                    PublicOnlyRegistration(provider, options=registration).handle,
                    ["POST", "OPTIONS"],
                ),
                methods=["POST", "OPTIONS"],
            )
        elif route.path == REVOCATION_PATH:
            from mcp.server.auth.handlers.revoke import RevocationHandler
            from mcp.server.auth.middleware.client_auth import ClientAuthenticator

            handler = RevocationHandler(provider, ClientAuthenticator(provider))
            route = Route(
                REVOCATION_PATH,
                endpoint=cors_middleware(
                    _revoke_with_default_secret(handler.handle), ["POST", "OPTIONS"]
                ),
                methods=["POST", "OPTIONS"],
            )
        out.append(route)
    return out


class IpThrottleMiddleware:
    """Per-client-IP sliding-window limits on the OAuth endpoints."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        client_ip_header: str | None = None,
        trusted_proxies: TrustedProxies | None = None,
        limits: dict[str, int] | None = None,
        max_keys: int = 4096,
    ) -> None:
        self.app = app
        self._header = client_ip_header.lower() if client_ip_header else None
        self._trusted = trusted_proxies or TrustedProxies()
        self._limiters = {
            path: BoundedWindowLimiter(calls, max_keys=max_keys)
            for path, calls in (limits or THROTTLE_LIMITS).items()
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        ip = client_ip(Request(scope), self._header, self._trusted)
        limiter = self._limiters.get(scope["path"])
        if limiter is not None and scope.get("method") != "OPTIONS" and not limiter.hit(ip):
            response = JSONResponse(
                {"error": "slow_down", "error_description": "too many requests"},
                status_code=429,
                headers={"Retry-After": "60", "Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
        reset = request_ip_var.set(ip)
        try:
            await self.app(scope, receive, send)
        finally:
            request_ip_var.reset(reset)
