"""End-to-end check of a built .mcpb: extract it, run the exact command its
manifest declares, and interrogate the live server over stdio.

Stands in for Claude Desktop: extracts to a path containing a space (the real
extensions directory has one) and substitutes ${__dirname} the way the host
does. Odoo credentials are deliberately fake -- nothing here touches Odoo.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

WRITE_TOOLS = {
    "execute_method",
    "execute_approved_write",
    "chatter_post",
    "preview_write",
    "validate_write",
}


def send(proc: subprocess.Popen[str], msg: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def notify(proc: subprocess.Popen[str], method: str, params: dict) -> None:
    send(proc, {"jsonrpc": "2.0", "method": method, "params": params})


def rpc(
    proc: subprocess.Popen[str],
    method: str,
    params: dict,
    ident: int,
) -> dict:
    assert proc.stdout is not None
    send(proc, {"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
    while True:
        line = proc.stdout.readline()
        if not line:
            raise SystemExit("server closed stdout before answering")
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        payload: dict = json.loads(line)
        if payload.get("id") == ident:
            return payload


def main() -> int:
    bundle = Path(sys.argv[1]).resolve()
    dest = Path(sys.argv[2]) / "Claude Extensions" / "local.mcpb.burke-odoo"
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle) as z:
        z.extractall(dest)
    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    cfg = manifest["server"]["mcp_config"]

    def sub(value: str) -> str:
        return (
            value.replace("${__dirname}", str(dest))
            .replace("${user_config.odoo_username}", "probe@example.com")
            .replace("${user_config.odoo_api_key}", "not-a-real-key")
        )

    # The host does NOT always use mcp_config.command. Its launcher switches on
    # server.type: `node` and `python` replace the command with an interpreter
    # the host resolves itself, keeping only the manifest args; everything else
    # falls through to using the command as written.
    #
    # Emulating only the written command is what let three broken bundles pass
    # this check. A type-`python` bundle launching uvx ran fine here and could
    # not run at all on a PC with no system Python, because the real host had
    # thrown the uvx away.
    server_type = manifest["server"].get("type")
    if server_type in {"node", "python"}:
        stem = Path(cfg["command"]).stem.lower()
        expected = {"node": {"node"}, "python": {"python", "python3", "py"}}
        if stem not in expected[server_type]:
            print(
                f"FAIL: server.type is {server_type!r}, so the host discards "
                f"mcp_config.command ({cfg['command']!r}) and substitutes its own "
                f"detected {server_type}. This bundle cannot run as written on a "
                f"machine without one. Use type 'binary'."
            )
            return 1

    argv = [cfg["command"]] + [sub(a) for a in cfg["args"]]
    env = dict(os.environ)
    env.pop("ODOO_MCP_ENABLE_WRITES", None)
    env.pop("ODOO_MCP_ELICIT_WRITES", None)
    for key, value in cfg["env"].items():
        env[key] = sub(value)

    print(f"launching: {argv}")
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    try:
        init = rpc(
            proc,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "burke-bundle-verify", "version": "0"},
            },
            1,
        )
        server = init["result"]["serverInfo"]
        print(f"serverInfo: {server}")
        notify(proc, "notifications/initialized", {})

        listed = rpc(proc, "tools/list", {}, 2)
        names = sorted(t["name"] for t in listed["result"]["tools"])
        leaked = sorted(set(names) & WRITE_TOOLS)
        print(f"tools exposed: {len(names)}")
        print(f"write tools exposed: {leaked or 'none'}")

        health = rpc(proc, "tools/call", {"name": "health_check", "arguments": {}}, 3)
        text = health["result"]["content"][0]["text"]
        report = json.loads(text)
        sec = report.get("runtime", {})
        picked = {
            "package_version": report.get("package_version")
            or sec.get("package_version"),
            "field_acl": sec.get("field_acl"),
            "tools_filtered": report.get("plugins", {}).get("tools_filtered"),
            "tool_count": report.get("server", {}).get("tool_count"),
            "side_effect_policy_error": sec.get("side_effect_policy", {}).get("error"),
            "audit_log_enabled": sec.get("audit_log", {}).get("enabled"),
            "write_execution_enabled": sec.get("write_execution_enabled"),
            "elicit_writes_enabled": sec.get("elicit_writes_enabled"),
            "chatter_direct_enabled": sec.get("chatter_direct_enabled"),
        }
        print("health_check:")
        print(json.dumps(picked, indent=2, default=str))

        ok = (
            not leaked
            and picked["write_execution_enabled"] is False
            and (picked["field_acl"] or {}).get("active") is True
            and "burke" in str(picked["package_version"])
            and set(picked["tools_filtered"] or []) == WRITE_TOOLS
            and picked["chatter_direct_enabled"] is False
            and picked["side_effect_policy_error"] is None
        )
        print("\nRESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
