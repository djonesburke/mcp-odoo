"""Assemble the bridge: surface, identity, OAuth server, HTTP app."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Callable

from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..server_core import mcp
from .client import verify_odoo_login
from .config import LOCAL_HOSTS, BridgeConfig
from .provider import DEFAULT_SCOPE, BridgeOAuthProvider, Verifier
from .runtime import BridgeRuntime, make_runtime
from .seal import load_seal_key
from .surface import apply_bridge_surface, bridge_lifespan, install_seams

DEFAULT_ORIGINS = ("https://claude.ai", "https://claude.com")


@dataclass
class BridgeBuild:
    app: Any
    runtime: BridgeRuntime
    provider: BridgeOAuthProvider
    tools: list[str]
    undo: Callable[[], None]


def default_verifier(config: BridgeConfig) -> Verifier:
    def verify(login: str, key: str) -> int:
        return verify_odoo_login(
            url=config.odoo_url,
            db=config.odoo_db,
            login=login,
            key=key,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
        )

    return verify


def transport_security(config: BridgeConfig) -> TransportSecuritySettings:
    host = config.public_host
    hosts = [host, f"{host}:*", "127.0.0.1:*", "localhost:*", "[::1]:*"]
    scheme = "https" if config.public_url.startswith("https") else "http"
    origins = [
        f"{scheme}://{host}",
        *DEFAULT_ORIGINS,
        *config.extra_allowed_origins,
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]
    return TransportSecuritySettings(allowed_hosts=hosts, allowed_origins=origins)


def build_bridge(
    config: BridgeConfig,
    *,
    runtime: BridgeRuntime | None = None,
    verifier: Verifier | None = None,
    seal_key: bytes | None = None,
) -> BridgeBuild:
    """Wire everything onto the shared ``mcp`` server and return the ASGI app.

    Raises on any problem (seal key, audit path, tool surface): the caller
    exits non-zero and nothing is served.
    """
    key = seal_key if seal_key is not None else load_seal_key(config.seal_key_path)
    runtime = runtime or make_runtime(config)
    runtime.audit.check_writable()
    provider = BridgeOAuthProvider(
        seal_key=key,
        instance=config.instance,
        public_url=config.public_url,
        state_dir=config.state_dir,
        verifier=verifier or default_verifier(config),
        allowed_redirect_hosts=config.allowed_redirect_hosts,
        client_ip_header=config.client_ip_header,
    )
    tools = apply_bridge_surface(runtime)
    undo = install_seams(runtime)

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "instance": config.instance})

    mcp._lowlevel_server.lifespan = bridge_lifespan(runtime)  # type: ignore[assignment]
    mcp.settings.auth = AuthSettings(
        issuer_url=config.public_url,  # type: ignore[arg-type]
        resource_server_url=f"{config.public_url}{config.path}",  # type: ignore[arg-type]
        client_registration_options=ClientRegistrationOptions(
            enabled=True, default_scopes=[DEFAULT_SCOPE]
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    mcp._auth_server_provider = provider  # type: ignore[assignment]
    mcp._token_verifier = ProviderTokenVerifier(provider)  # type: ignore[arg-type]
    mcp._custom_starlette_routes[:] = [
        *provider.routes(),
        Route("/healthz", healthz, methods=["GET"]),
    ]
    app = mcp.streamable_http_app(
        streamable_http_path=config.path,
        stateless_http=True,  # identity is per request, never per session
        transport_security=transport_security(config),
        host=config.host,
    )
    return BridgeBuild(app=app, runtime=runtime, provider=provider, tools=tools, undo=undo)


def serve(build: BridgeBuild, config: BridgeConfig) -> None:  # pragma: no cover - runs a server
    import uvicorn

    print(
        f"odoo-mcp-bridge: instance={config.instance} bind={config.host}:{config.port} "
        f"path={config.path} tools={len(build.tools)}",
        file=sys.stderr,
    )
    if config.host not in LOCAL_HOSTS:
        print(
            "odoo-mcp-bridge: binding a non-local host; keep it behind TLS and a proxy.",
            file=sys.stderr,
        )
    uvicorn.run(build.app, host=config.host, port=config.port, log_level="info")
