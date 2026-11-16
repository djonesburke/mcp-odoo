# odoo-mcp-bridge: hosted, read-only, per-user mode

`odoo-mcp-bridge` is a second entrypoint of this package. It serves **one
streamable-HTTP MCP endpoint** that an MCP client with OAuth support (for
example a claude.ai custom connector) can add by URL. Each person signs in
once with their own **Odoo login and Odoo API key**; from then on every tool
call reaches Odoo **as that person**. Odoo's own access rights are the security
boundary. The bridge has no service account and refuses to start if it is
given one.

It is read-only **by build**, not by configuration: the tool surface is a
hard-coded allowlist, and the Odoo client refuses write RPC methods before any
network call.

## How a session works

1. The client discovers the bridge's OAuth metadata and registers itself
   (dynamic client registration, public PKCE client).
2. `/authorize` redirects the browser to the bridge's own `/signin` page.
3. The person enters their Odoo login and API key. The bridge verifies them
   against Odoo over the JSON-2 API only: it calls `res.users.context_get`
   with the key (which returns the key owner's uid), reads that user's login,
   and requires it to equal the typed login (case-insensitive).
4. The bridge issues a single-use authorization code (5 minutes) and redirects
   back to the client, which exchanges it (PKCE S256) for tokens.
5. The access token (1 hour) and refresh token (30 days) are AES-256-GCM
   sealed JSON containing the uid, login, **the user's API key**, the instance
   label, the connector id and an expiry. Nothing about users is stored on disk.
6. Every MCP request carries the access token. The bridge unseals it, builds
   (or reuses, per token, until the token expires) an Odoo JSON-2 client for
   that login and key, and runs the tool with it.
7. Refreshing re-verifies the key against Odoo, so a key revoked in Odoo ends
   access at the next refresh (or when the access token expires, at most one
   hour later).

The server runs the MCP transport in **stateless** mode so identity is read
from each request's own token and never from a long-lived session.

## Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `ODOO_MCP_FIELD_POLICY_FILE` | yes | Path to the field-ACL policy file (see [field-acl.md](field-acl.md)). The bridge refuses to start without it, if the file is missing or malformed, or if it has no rules under the policy key. The `./odoo_mcp_policy.json` fallback is never used. No opt-out. |
| `ODOO_URL` | yes | Base URL of the one Odoo instance (JSON-2 API: `/json/2/<model>/<method>`). |
| `ODOO_DB` | yes | Database name, sent as `X-Odoo-Database`. |
| `ODOO_MCP_BRIDGE_INSTANCE` | yes | `staging` or `production`. Reported by `health_check` and written to every audit line. Also the instance name used by field-ACL policy files. |
| `ODOO_MCP_BRIDGE_PUBLIC_URL` | yes | Public base URL, no path, `https` (plain `http` only for localhost). It is the OAuth issuer. |
| `ODOO_MCP_BRIDGE_SEAL_KEY_FILE` | yes | Path to the 32-byte seal key. |
| `ODOO_MCP_BRIDGE_STATE_DIR` | yes | Directory for `clients.json` (registered connectors, non-secret). |
| `ODOO_MCP_BRIDGE_AUDIT_LOG` | yes | JSONL audit file (must be writable at start). |
| `ODOO_MCP_BRIDGE_POLICY_INSTANCE` | no | Key the policy file uses for this instance's rules (default `default`). `health_check` and audit lines still report the `staging`/`production` label. |
| `ODOO_MCP_BRIDGE_HOST` / `_PORT` | no | Bind address (default `127.0.0.1:8765`). |
| `ODOO_MCP_BRIDGE_CALLS_PER_MINUTE` | no | Per-user throttle (default 60). |
| `ODOO_MCP_BRIDGE_MAX_LIMIT` | no | Largest record limit a read may request (default 200). |
| `ODOO_MCP_BRIDGE_ALLOWED_REDIRECT_HOSTS` | no | CSV of exact hosts allowed as OAuth redirect URIs, `https` only. Default `claude.ai,claude.com`. |
| `ODOO_MCP_BRIDGE_ALLOW_LOCALHOST_REDIRECTS` | no | Test only (default off): also accept `http://localhost` redirects. |
| `ODOO_MCP_BRIDGE_CLIENT_IP_HEADER` | no | Header carrying the real client IP behind a proxy (for example `CF-Connecting-IP`); the last value is used. It is honoured **only** when the socket peer is loopback or listed in `ODOO_MCP_BRIDGE_TRUSTED_PROXIES`; otherwise the peer address is used, so a client cannot spoof it. |
| `ODOO_MCP_BRIDGE_TRUSTED_PROXIES` | no | CSV of IPs/CIDRs allowed to set that header (default: loopback only). |
| `ODOO_MCP_BRIDGE_ALLOWED_ORIGINS` | no | Extra CSV of allowed `Origin` values. |
| `ODOO_TIMEOUT`, `ODOO_VERIFY_SSL` | no | As for `odoo-mcp`. |

The process **exits non-zero with a message on stderr** if any of these is
set: `ODOO_PASSWORD`, `ODOO_API_KEY`, `ODOO_USERNAME`, `ODOO_CONFIG_FILE`,
`ODOO_MCP_TOOLS_INCLUDE`, `ODOO_MCP_TOOLS_EXCLUDE`, `ODOO_MCP_PLUGINS`,
`ODOO_MCP_ENABLE_WRITES`; if `ODOO_URL` names more than one instance; or if
the seal key is missing, not exactly 32 bytes, or (POSIX) group/world
accessible. It also exits non-zero if, after registration, the tool set is not
exactly the allowlist.

## Seal key

```bash
odoo-mcp-bridge --generate-seal-key /etc/odoo-mcp-bridge/seal.key
```

Writes 32 random bytes with mode 0600 and refuses to overwrite an existing
file. Keep it out of backups that other people can read. **Rotating the key
(replace the file, restart) revokes every token and every session at once.**

## Running it

```bash
export ODOO_URL=https://odoo.example.com ODOO_DB=exampledb
export ODOO_MCP_BRIDGE_INSTANCE=staging
export ODOO_MCP_BRIDGE_PUBLIC_URL=https://bridge.example.com
export ODOO_MCP_BRIDGE_SEAL_KEY_FILE=/etc/odoo-mcp-bridge/seal.key
export ODOO_MCP_BRIDGE_STATE_DIR=/var/lib/odoo-mcp-bridge
export ODOO_MCP_BRIDGE_AUDIT_LOG=/var/log/odoo-mcp-bridge/audit.jsonl
odoo-mcp-bridge
```

Behind a reverse proxy or tunnel: bind to `127.0.0.1`, terminate TLS at the
proxy, forward the whole origin (the OAuth endpoints `/.well-known/*`,
`/authorize`, `/token`, `/register`, `/revoke`, `/signin` and the MCP endpoint
`/mcp`), and pass the `Host` header through (the bridge only accepts its public
host and localhost). `/healthz` returns `{"status":"ok"}` without
authentication for liveness checks. Add the MCP URL
`https://bridge.example.com/mcp` as the connector URL in the client.

Run **one process per Odoo instance** (separate seal keys, state and audit
files for `staging` and `production`).

## Tools

The bridge exposes exactly these 13 tools, each read-only and run as the
signed-in user:

`aggregate_records`, `build_domain`, `data_quality_report`, `diagnose_access`,
`get_model_fields`, `get_odoo_profile`, `health_check`,
`inspect_model_relationships`, `list_models`, `read_attachment`, `read_record`,
`schema_catalog`, `search_records`.

`health_check` is replaced by a bridge version (instance label, tool list,
limits, the caller's uid and login). Resources and prompts are removed.
Everything else is excluded: the whole write family (`preview_write`,
`validate_write`, `execute_approved_write`, `chatter_post`, `execute_method`,
`generate_json2_payload`), the async queue, the knowledge index and
`scan_addons_source` (local files or shared local state), every
`*_across_instances` tool and `list_instances` (one instance per process),
accounting/finance tools, HR tools, and `check_api_key_expiry` (key metadata).
The remaining advisory tools that do not read Odoo as the user
(`lookup_model_history`, `analyze_upgrade_log`, `diagnose_odoo_call`,
`fit_gap_report`, `upgrade_risk_report`, `business_pack_report`) are left out to
keep the surface small. A hard-coded denylist plus a name check are asserted
after registration.

Limits: every read tool's `limit`, `sample_limit` and `module_limit` is capped
at `ODOO_MCP_BRIDGE_MAX_LIMIT`; each user is throttled to
`ODOO_MCP_BRIDGE_CALLS_PER_MINUTE`; the field-ACL policy applies as in `odoo-mcp`,
keyed by `ODOO_MCP_BRIDGE_POLICY_INSTANCE` (not the instance label). `get_odoo_profile`
returns `<redacted>` for the backend URL, host, database name, TLS-verify setting
and timeout.

The Odoo client used by the bridge refuses any RPC method outside
`READ_ONLY_METHODS` plus `read_group` and `formatted_read_group` (the two
read-only aggregation methods the aggregate tools call).

## Audit

One JSON line per tool call:

```json
{"ts":"...Z","instance":"staging","uid":7,"login":"user@example.com","tool":"search_records","model":"res.partner","fields":["name"],"records":3,"duration_ms":41,"outcome":"ok"}
```

`outcome` is `ok`, `error`, `rate_limited`, `unauthenticated` or
`exception:<Type>`. Field values, domains, tokens and keys are never written.
If the audit line cannot be written the result is withheld (no audit, no data).

## Security model and limits

- **Odoo is the boundary.** The bridge adds no privileges; a user can read what
  their Odoo account can read, nothing more. There is no service identity and no
  fallback to environment credentials.
- **A stolen access token is usable against the bridge for up to one hour**
  (it carries the user's key; only expiry or revocation of that token, or
  rotating the seal key, stops it). A stolen refresh token is usable until it
  expires (30 days) or the Odoo key is revoked: every refresh re-verifies the
  key and rotates the refresh token.
- **Seal key compromise exposes the API keys inside every live token** and lets
  an attacker mint tokens. Protect the file (0600, own account) and rotate on
  suspicion. Rotation revokes everyone.
- **Revocation is a bounded in-memory deny set** of token ids (`jti`, 100,000
  entries, at most 1,500 live per user: a user who refreshes hourly holds about 720
  a month because every rotated refresh token is denied until its own expiry): it is lost on restart and revoking an access token does not revoke its
  refresh token. An unexpired entry is never evicted; when the set is full of live
  entries a refresh is refused (the user signs in again). Token encoding is strict (a padded or re-spelled
  copy of a token is invalid). Refresh rotation is atomic: of two concurrent
  refreshes with one token exactly one succeeds. Revoke the Odoo API key itself to
  end a user's access for good.
- **Client registration is open but constrained.** Anyone who can reach
  `/register` can register a *public* client, but only with an `https` redirect on
  an allowed host (default `claude.ai`, `claude.com`, exact match). The list is
  re-checked when `clients.json` loads (non-conforming clients are dropped with a
  log line) and again at `/authorize`. `/register`, `/authorize` and `/token` are
  throttled per client IP; when the client table (1,000) or the pending sign-in
  table (500) is full, new entries are refused rather than evicting active ones.
  Each address may hold at most 5 pending sign-ins. A client that never completed
  a sign-in expires after 24 hours and is the first thing evicted when the client
  table is full; if none can be evicted, registration is refused. `clients.json`
  records `registered_at` and `last_used` per client.
  Registration always stores and returns `token_endpoint_auth_method: none` and
  no secret (the SDK would otherwise mint one); metadata advertises only `none`.
- The auth code is held in memory with the user's key for up to five minutes.
- Sign-in attempts are limited to 5 a minute per client IP; configure
  `ODOO_MCP_BRIDGE_CLIENT_IP_HEADER` behind a proxy or the limit is shared by all
  users of the proxy.
- **Per-IP limits are shared by everyone behind one address.** `/register`,
  `/authorize`, `/token`, `/revoke` and `/signin` are limited per client IP, so
  people behind one office NAT or egress IP share those budgets (a burst of
  sign-ins or refreshes from one site can be answered with 429 for a minute). The
  limiter's key table is bounded: expired keys go first, then the least recently
  used key that is not over budget; if every key is over budget new keys are
  refused, so rotating keys cannot reset an attacker's bucket or grow memory.
- **Odoo down is not a bad password.** Transport errors, timeouts and 5xx/429 from
  Odoo give the sign-in page a 503 and a refresh an `invalid_request` ("Odoo is
  temporarily unavailable"), and the refresh token is not consumed. Only a refused
  key is `invalid_grant`.
- JSON-2 only: XML-RPC and `/web/*` paths are never used for sign-in or tool
  calls (except the best-effort `/web/version` read inside `get_odoo_profile`,
  whose failure is tolerated).

## Deploy

**Install** the bridge from the lock file, with hashes, not from a loose range:

```bash
uv export --frozen --no-dev --extra bridge --hashes > requirements-bridge.txt
pip install --require-hashes -r requirements-bridge.txt
pip install --no-deps .
```

The `bridge` extra pins `mcp==2.0.0` (and `cryptography`); the core `odoo-mcp`
package keeps its `mcp>=2,<3` range, so upstream installs are unaffected. The
bridge also **refuses to start** when the installed `mcp` is not the tested
version, naming both versions (`TESTED_MCP_VERSION` in
`odoo_mcp/bridge/config.py`).

**Before switching over**, in the target environment (same Python, same lock
file), run the four bridge test files and the full suite:

```bash
python -m pytest tests/test_bridge_core.py tests/test_bridge_oauth.py \
    tests/test_bridge_surface.py tests/test_bridge_hardening.py
python -m pytest
```

Start the new version on a different port, sign in once, and only then move the
tunnel or proxy.

**Upgrading `mcp`.** The bridge reaches into SDK internals that are not public
API. When the SDK changes, re-verify each of these (the tests above exercise them)
and only then bump `TESTED_MCP_VERSION` and the `bridge` extra:

- `MCPServer._tool_manager._tools`, `_resource_manager._resources` /
  `_templates`, `_prompt_manager._prompts` (the surface is trimmed by editing them)
- `Tool.fn` (replaced by a wrapper) and the tool call path passing `ctx` as a
  keyword argument
- `MCPServer._lowlevel_server.lifespan` (replaced so no client is cached across
  users), `MCPServer._auth_server_provider` (left unset so the SDK adds no routes),
  `MCPServer._token_verifier`, `MCPServer._custom_starlette_routes`,
  `MCPServer.settings.auth`
- `streamable_http_app(stateless_http=True)` giving each request its own context,
  and `AuthContextMiddleware` / `get_access_token()` carrying the token into the
  tool call
- `ProviderTokenVerifier`, `create_auth_routes`, `build_metadata`,
  `RegistrationHandler`, `RevocationHandler`, `ClientAuthenticator`,
  `MetadataHandler`, `cors_middleware`, `construct_redirect_uri`
- the `OAuthAuthorizationServerProvider` protocol and the token handler's checks
  (refresh token `client_id` equality, PKCE, revoke matching `token.client_id`)
- `AppContext` field names used by the tools (`schema_cache`,
  `_default_instance_name`, `odoo`, `get_client`) and the `_srv()` seams in
  `odoo_mcp.server`
- `OAuthClientInformationFull.validate_redirect_uri`
