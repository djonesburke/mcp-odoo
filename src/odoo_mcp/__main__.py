"""
Command line entry point for the Odoo MCP Server
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import time
import traceback

from . import auth as auth_mod
from .auth import build_auth, build_static_auth
from .server import mcp

SUPPORTED_MCP_TRANSPORTS = {"stdio", "streamable-http", "sse"}
HTTP_TRANSPORTS = {"streamable-http", "sse"}
ALLOW_UNAUTH_HTTP_ENV = "MCP_ALLOW_UNAUTHENTICATED_HTTP"
SECRET_ENV_KEYS = {"ODOO_PASSWORD", "ODOO_API_KEY", "MCP_HTTP_AUTH_TOKEN"}
LOCAL_HTTP_HOSTS = {"127.0.0.1", "localhost", "::1"}
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
DEFAULT_LOG_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_LOG_FILE_BACKUPS = 3


class JsonLogFormatter(logging.Formatter):
    """Minimal structured-log formatter using stdlib only."""

    _STANDARD_FIELDS = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key not in self._STANDARD_FIELDS and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload, default=str, sort_keys=True)


def setup_logging(
    *,
    level: str | None = None,
    use_json: bool | None = None,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure the root logger from CLI args or env vars.

    Reads ``ODOO_MCP_LOG_LEVEL``, ``ODOO_MCP_LOG_JSON`` (truthy), and
    ``ODOO_MCP_LOG_FILE`` when explicit kwargs are not supplied. Adds a
    rotating file handler when a log file path is configured.
    """
    resolved_level = (level or os.environ.get("ODOO_MCP_LOG_LEVEL", "INFO")).upper()
    if resolved_level not in LOG_LEVELS:
        resolved_level = "INFO"
    resolved_json = (
        use_json
        if use_json is not None
        else parse_bool(os.environ.get("ODOO_MCP_LOG_JSON"))
    )
    resolved_file = (
        log_file if log_file is not None else os.environ.get("ODOO_MCP_LOG_FILE")
    )

    formatter: logging.Formatter
    if resolved_json:
        formatter = JsonLogFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    root = logging.getLogger()
    root.setLevel(resolved_level)
    # Replace existing handlers so repeated calls (tests) stay deterministic.
    root.handlers.clear()

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(resolved_level)
    root.addHandler(stream_handler)

    if resolved_file:
        file_handler = logging.handlers.RotatingFileHandler(
            resolved_file,
            maxBytes=DEFAULT_LOG_FILE_BYTES,
            backupCount=DEFAULT_LOG_FILE_BACKUPS,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(resolved_level)
        root.addHandler(file_handler)

    return root


def parse_bool(value: str | None) -> bool:
    """Parse common boolean values from environment variables."""
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_csv_env(value: str | None) -> list[str]:
    """Parse comma-separated env/CLI values while ignoring blanks."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def is_secret_env_key(key: str) -> bool:
    """Keep secrets out of startup logs."""
    upper_key = key.upper()
    return (
        upper_key in SECRET_ENV_KEYS
        or upper_key.endswith("_PASSWORD")
        or upper_key.endswith("_TOKEN")
        or upper_key.endswith("_API_KEY")
        or upper_key.endswith("_SECRET")
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments and environment defaults."""
    parser = argparse.ArgumentParser(description="Run the Odoo MCP server.")
    parser.add_argument(
        "--transport",
        choices=sorted(SUPPORTED_MCP_TRANSPORTS),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="MCP transport to serve. Defaults to MCP_TRANSPORT or stdio.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HTTP_HOST", "127.0.0.1"),
        help="HTTP bind host for streamable-http or sse transports.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MCP_HTTP_PORT", "8000")),
        help="HTTP bind port for streamable-http or sse transports.",
    )
    parser.add_argument(
        "--path",
        default=os.environ.get("MCP_HTTP_PATH", "/mcp"),
        help="Streamable HTTP path. Defaults to MCP_HTTP_PATH or /mcp.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=os.environ.get("MCP_LOG_LEVEL", "INFO").upper(),
        help="MCP HTTP server log level.",
    )
    parser.add_argument(
        "--allow-remote-http",
        action="store_true",
        default=parse_bool(os.environ.get("MCP_ALLOW_REMOTE_HTTP")),
        help=(
            "Allow HTTP transports to bind non-local hosts. Use only behind your "
            "own authentication, TLS, and network policy."
        ),
    )
    parser.add_argument(
        "--allowed-hosts",
        default=os.environ.get("MCP_ALLOWED_HOSTS", ""),
        help="Comma-separated Host header allowlist for HTTP transports.",
    )
    parser.add_argument(
        "--allowed-origins",
        default=os.environ.get("MCP_ALLOWED_ORIGINS", ""),
        help="Comma-separated Origin allowlist for HTTP transports.",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Print non-secret runtime health JSON and exit.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help=(
            "Interactive wizard: prompt for connection details, test them, "
            "write a config file, and print client snippets."
        ),
    )
    return parser.parse_args(argv)


def configure_mcp_runtime(args: argparse.Namespace) -> None:
    """Apply CLI/env runtime settings to the FastMCP instance."""
    if (
        args.transport in {"streamable-http", "sse"}
        and args.host not in LOCAL_HTTP_HOSTS
        and not args.allow_remote_http
    ):
        raise ValueError(
            "HTTP transports bind local hosts only by default. "
            "Use --allow-remote-http or MCP_ALLOW_REMOTE_HTTP=1 only behind "
            "external authentication, TLS, and network policy."
        )
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.settings.log_level = args.log_level
    mcp.settings.streamable_http_path = args.path
    allowed_hosts = parse_csv_env(args.allowed_hosts)
    allowed_origins = parse_csv_env(args.allowed_origins)
    security = mcp.settings.transport_security
    if allowed_hosts or allowed_origins:
        if security is None:
            raise ValueError("FastMCP transport security settings are unavailable")
        if allowed_hosts:
            security.allowed_hosts = allowed_hosts
        if allowed_origins:
            security.allowed_origins = allowed_origins
    configure_http_auth(args)


def configure_http_auth(args: argparse.Namespace) -> None:
    """Select and wire the HTTP auth mode, and fail closed when it is absent.

    Two mutually exclusive modes protect HTTP transports:
      * OAuth introspection  — ODOO_MCP_AUTH_* (external IdP)
      * Static shared bearer — MCP_HTTP_AUTH_TOKEN (connector-platform model)

    Configuring both is rejected: the intent is ambiguous and one would silently
    win. When neither is configured on an HTTP transport the server refuses to
    start, so an ungated HTTP endpoint cannot happen by omission. The refusal
    covers *all* HTTP binds — including 127.0.0.1 — because the production
    topology fronts a localhost bind with a Cloudflare tunnel, so "bound to
    localhost" is not evidence the endpoint is private. A deliberate,
    named escape hatch (MCP_ALLOW_UNAUTHENTICATED_HTTP=1) exists for genuinely
    local, no-tunnel development; it is loud and never the default.
    """
    static_on = auth_mod.static_auth_configured()
    oauth_on = auth_mod.oauth_env_present()

    if static_on and oauth_on:
        raise ValueError(
            "Configure only ONE HTTP auth mode: MCP_HTTP_AUTH_TOKEN (static "
            "shared bearer) OR ODOO_MCP_AUTH_* (OAuth introspection), not both."
        )

    if static_on:
        configure_static_auth(args)
    else:
        # build_auth() (inside configure_oauth) still raises on a partial
        # ODOO_MCP_AUTH_* config, preserving that fail-closed behavior.
        configure_oauth(args)

    if args.transport not in HTTP_TRANSPORTS:
        return
    if static_on or oauth_on:
        return
    # HTTP transport with no auth configured.
    if parse_bool(os.environ.get(ALLOW_UNAUTH_HTTP_ENV)):
        print(
            "WARNING: HTTP transport is running with NO authentication "
            f"({ALLOW_UNAUTH_HTTP_ENV} is set). Every request that reaches this "
            "endpoint can call every tool. Use this only for local development "
            "with no network exposure.",
            file=sys.stderr,
        )
        return
    if getattr(args, "health", False):
        # A health probe never serves traffic; do not block introspection.
        return
    raise ValueError(
        "Refusing to start an HTTP transport with no authentication. Set "
        "MCP_HTTP_AUTH_TOKEN (static shared bearer) or the ODOO_MCP_AUTH_* "
        "OAuth vars. For local development only, set "
        f"{ALLOW_UNAUTH_HTTP_ENV}=1 to run ungated deliberately."
    )


def configure_static_auth(args: argparse.Namespace) -> None:
    """Enable the static shared-bearer gate when MCP_HTTP_AUTH_TOKEN is set.

    Wired through the same FastMCP seam as OAuth (settings.auth +
    _token_verifier). Ignored with a warning on stdio, matching configure_oauth.
    """
    built = build_static_auth()
    if built is None:
        return
    if args.transport not in HTTP_TRANSPORTS:
        print(
            "MCP_HTTP_AUTH_TOKEN is set but the transport is stdio; "
            "the static header gate only protects HTTP transports and will be "
            "ignored.",
            file=sys.stderr,
        )
        return
    auth_settings, verifier = built
    mcp.settings.auth = auth_settings
    mcp._token_verifier = verifier
    token_count = len(auth_mod.static_tokens())
    print(
        f"Static header auth enabled ({token_count} token(s) accepted).",
        file=sys.stderr,
    )


def configure_oauth(args: argparse.Namespace) -> None:
    """Enable the OAuth resource server when ODOO_MCP_AUTH_* env vars are set.

    FastMCP reads settings.auth and the token verifier lazily when it builds
    the HTTP app, so wiring them here (before run) is sufficient.
    """
    auth = build_auth()
    if auth is None:
        return
    if args.transport not in {"streamable-http", "sse"}:
        print(
            "ODOO_MCP_AUTH_* is set but the transport is stdio; "
            "OAuth only protects HTTP transports and will be ignored.",
            file=sys.stderr,
        )
        return
    auth_settings, verifier = auth
    mcp.settings.auth = auth_settings
    mcp._token_verifier = verifier
    print(
        f"OAuth resource server enabled (issuer: {auth_settings.issuer_url})",
        file=sys.stderr,
    )


def health_payload(args: argparse.Namespace) -> dict[str, object]:
    """Build a non-secret process/runtime health payload."""
    security = mcp.settings.transport_security
    if security is None:
        transport_security = None
    else:
        transport_security = {
            "dns_rebinding_protection": security.enable_dns_rebinding_protection,
            "allowed_hosts": security.allowed_hosts,
            "allowed_origins": security.allowed_origins,
        }
    return {
        "success": True,
        "transport": args.transport,
        "host": args.host,
        "port": args.port,
        "path": args.path,
        "log_level": args.log_level,
        "allow_remote_http": args.allow_remote_http,
        "transport_security": transport_security,
    }


def main() -> int:
    """
    Run the MCP server
    """
    try:
        args = parse_args()
        if args.setup:
            from .setup_wizard import run_setup

            return run_setup()
        setup_logging()
        configure_mcp_runtime(args)
        if args.health:
            print(json.dumps(health_payload(args), sort_keys=True))
            return 0

        print("=== ODOO MCP SERVER STARTING ===", file=sys.stderr)
        print(f"Python version: {sys.version}", file=sys.stderr)
        print("Environment variables:", file=sys.stderr)
        for key, value in os.environ.items():
            if key.startswith(("ODOO_", "MCP_")):
                if is_secret_env_key(key):
                    print(f"  {key}: ***hidden***", file=sys.stderr)
                else:
                    print(f"  {key}: {value}", file=sys.stderr)

        print(f"Starting MCP server over {args.transport}...", file=sys.stderr)
        if args.transport in {"streamable-http", "sse"}:
            print(f"  Bind: {args.host}:{args.port}", file=sys.stderr)
            if args.transport == "streamable-http":
                print(f"  Path: {args.path}", file=sys.stderr)
        sys.stderr.flush()
        mcp.run(transport=args.transport)

        print("MCP server stopped normally", file=sys.stderr)
        return 0
    except KeyboardInterrupt:
        print("MCP server stopped by user", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        print("Exception details:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
