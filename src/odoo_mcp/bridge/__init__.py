"""Hosted, read-only, per-user bridge for odoo-mcp.

One streamable-HTTP MCP endpoint. Each person signs in through the bridge's
own OAuth authorization server with their Odoo login and Odoo API key; every
tool call then reaches Odoo *as that person*. Odoo's own permissions are the
security boundary and there is no service identity. See ``docs/bridge.md``.

Layering: this package sits above the MCP surface (it imports ``server``);
nothing in the core or surface layers may import it (see ``.importlinter``).
"""
