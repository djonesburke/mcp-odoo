"""``odoo-mcp-bridge`` entrypoint."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence

from .config import BridgeConfigError, check_sdk_version, load_config
from .seal import SealKeyError, generate_seal_key, load_seal_key


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="odoo-mcp-bridge",
        description=(
            "Hosted, read-only, per-user Odoo MCP bridge (streamable HTTP, "
            "OAuth sign-in with each person's Odoo login and API key)."
        ),
    )
    parser.add_argument(
        "--generate-seal-key",
        metavar="PATH",
        help="Write a new 32-byte seal key to PATH (mode 0600) and exit.",
    )
    return parser


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.generate_seal_key:
        try:
            generate_seal_key(args.generate_seal_key)
        except OSError as exc:
            print(f"odoo-mcp-bridge: cannot write seal key: {exc.strerror}", file=sys.stderr)
            return 2
        print(f"odoo-mcp-bridge: wrote seal key to {args.generate_seal_key}", file=sys.stderr)
        return 0
    try:
        check_sdk_version()
        config = load_config(env)
        load_seal_key(config.seal_key_path)
        # Imported only after the environment passed: importing the server
        # registers every tool and reads tool-filter variables.
        from .app import build_bridge, serve

        build = build_bridge(config)
    except (BridgeConfigError, SealKeyError) as exc:
        print(f"odoo-mcp-bridge: refusing to start: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - startup must fail closed
        print(f"odoo-mcp-bridge: refusing to start: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    try:
        serve(build, config)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
