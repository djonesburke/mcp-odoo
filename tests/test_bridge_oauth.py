"""Bridge OAuth provider: register -> authorize -> sign-in -> code -> token -> refresh."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

from odoo_mcp.bridge.client import BridgeAuthError
from odoo_mcp.bridge.oauth_routes import IpThrottleMiddleware, build_oauth_routes
from odoo_mcp.bridge.provider import (
    ACCESS_TTL_SECONDS,
    BridgeAccessToken,
    BridgeOAuthProvider,
)
from odoo_mcp.bridge.seal import seal

SEAL = bytes(range(32))
ISSUER = "http://localhost"
REDIRECT = "https://claude.example.com/callback"
KEY = "odoo-api-key-do-not-leak"


class Odoo:
    """Mocked Odoo authentication: login -> (key, uid)."""

    def __init__(self):
        self.users = {"ann@example.com": (KEY, 7)}
        self.calls = 0

    def __call__(self, login, key):
        self.calls += 1
        entry = self.users.get(login.lower())
        if entry is None or entry[0] != key:
            raise BridgeAuthError("invalid credentials")
        return entry[1]


@pytest.fixture
def odoo():
    return Odoo()


@pytest.fixture
def now():
    return [1_800_000_000.0]


@pytest.fixture
def provider(tmp_path, odoo, now):
    return BridgeOAuthProvider(
        seal_key=SEAL,
        instance="staging",
        public_url=ISSUER,
        state_dir=tmp_path / "state",
        verifier=odoo,
        allowed_redirect_hosts=("claude.example.com",),
        allow_localhost_redirects=True,
        clock=lambda: now[0],
    )


def _app(provider, **throttle):
    routes = build_oauth_routes(
        provider,
        AnyHttpUrl(ISSUER),
        ClientRegistrationOptions(enabled=True),
        RevocationOptions(enabled=True),
    )
    middleware = [Middleware(IpThrottleMiddleware, **throttle)] if throttle else []
    return Starlette(routes=[*routes, *provider.routes()], middleware=middleware)


def _pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _register(client, redirect=REDIRECT, **extra):
    body = {
        "redirect_uris": [redirect],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "Example Connector",
        **extra,
    }
    return client.post("/register", json=body)


def _authorize(client, client_id, challenge, state="st1"):
    return client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
        follow_redirects=False,
    )


def _signin_fields(html):
    return {
        name: re.search(rf'name="{name}" value="([^"]*)"', html).group(1)
        for name in ("req", "csrf")
    }


def _full_flow(client, login="ann@example.com", key=KEY):
    reg = _register(client)
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]
    verifier, challenge = _pkce()
    auth = _authorize(client, client_id, challenge)
    assert auth.status_code == 302
    page = client.get(auth.headers["location"])
    assert page.status_code == 200
    fields = _signin_fields(page.text)
    done = client.post(
        "/signin",
        data={**fields, "login": login, "api_key": key},
        follow_redirects=False,
    )
    return client_id, verifier, done


def _exchange(client, client_id, verifier, code):
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
        },
    )


def test_full_flow_issues_sealed_user_tokens(provider, odoo):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, verifier, done = _full_flow(client)
    assert done.status_code == 302
    location = urlparse(done.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    query = parse_qs(location.query)
    assert query["state"] == ["st1"]
    tokens = _exchange(client, client_id, verifier, query["code"][0])
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["expires_in"] == ACCESS_TTL_SECONDS and body["refresh_token"]
    assert KEY not in tokens.text  # sealed, not plaintext

    loaded = _run(provider.load_access_token(body["access_token"]))
    assert isinstance(loaded, BridgeAccessToken)
    assert (loaded.uid, loaded.login, loaded.odoo_key) == (7, "ann@example.com", KEY)
    assert loaded.expires_at is not None
    # the SDK's own verifier path accepts it too
    assert _run(ProviderTokenVerifier(provider).verify_token(body["access_token"]))


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def test_authorization_code_is_single_use(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, verifier, done = _full_flow(client)
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    assert _exchange(client, client_id, verifier, code).status_code == 200
    assert _exchange(client, client_id, verifier, code).status_code == 400


def test_authorization_code_expires_after_five_minutes(provider, now):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, verifier, done = _full_flow(client)
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    now[0] += 301
    assert _exchange(client, client_id, verifier, code).status_code == 400


def test_pkce_is_enforced(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, _, done = _full_flow(client)
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    wrong = _exchange(client, client_id, "not-the-verifier-" + "x" * 40, code)
    assert wrong.status_code == 400


def test_bad_credentials_get_generic_message_and_no_echo(provider, odoo):
    client = TestClient(_app(provider), base_url=ISSUER)
    reg = _register(client).json()
    _, challenge = _pkce()
    page = client.get(_authorize(client, reg["client_id"], challenge).headers["location"])
    fields = _signin_fields(page.text)
    bad = client.post(
        "/signin",
        data={**fields, "login": "ann@example.com", "api_key": "wrong-key-12345"},
        follow_redirects=False,
    )
    assert bad.status_code == 200
    assert "Sign-in failed" in bad.text
    assert "wrong-key-12345" not in bad.text
    unknown = client.post(
        "/signin",
        data={**_signin_fields(bad.text), "login": "nobody@example.com", "api_key": KEY},
    )
    assert "Sign-in failed" in unknown.text and "nobody" in unknown.text  # login only
    assert KEY not in unknown.text


def test_csrf_and_pending_id_are_required(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    reg = _register(client).json()
    _, challenge = _pkce()
    page = client.get(_authorize(client, reg["client_id"], challenge).headers["location"])
    fields = _signin_fields(page.text)
    forged = client.post(
        "/signin",
        data={**fields, "csrf": "forged", "login": "ann@example.com", "api_key": KEY},
        follow_redirects=False,
    )
    assert forced_status(forged) == 403
    unknown = client.post(
        "/signin",
        data={"req": "nope", "csrf": "x", "login": "ann@example.com", "api_key": KEY},
    )
    assert unknown.status_code == 400
    assert client.get("/signin?req=nope").status_code == 400


def forced_status(response):
    return response.status_code


def test_login_attempts_are_rate_limited_per_ip(provider, odoo):
    client = TestClient(_app(provider), base_url=ISSUER)
    reg = _register(client).json()
    _, challenge = _pkce()
    page = client.get(_authorize(client, reg["client_id"], challenge).headers["location"])
    fields = _signin_fields(page.text)
    statuses = []
    for _ in range(7):
        response = client.post(
            "/signin",
            data={**fields, "login": "ann@example.com", "api_key": "wrong"},
        )
        statuses.append(response.status_code)
        if response.status_code == 200:
            fields = _signin_fields(response.text)
    assert statuses[:5] == [200] * 5
    assert statuses[5:] == [429, 429]
    assert odoo.calls == 5  # throttled attempts never reach Odoo


def test_registration_is_https_only_public_and_persisted(provider, tmp_path, odoo, now):
    client = TestClient(_app(provider), base_url=ISSUER)
    assert _register(client, redirect="http://evil.example.com/cb").status_code == 400
    assert _register(client, redirect="http://localhost:3000/cb").status_code == 201
    reg = _register(client, token_endpoint_auth_method="client_secret_post")
    assert reg.status_code == 201
    persisted = (tmp_path / "state" / "clients.json").read_text()
    assert "client_secret" not in persisted.replace('"client_secret_', "")
    stored = json.loads(persisted)["clients"]
    assert all(c.get("token_endpoint_auth_method") == "none" for c in stored)
    # a restart keeps the connectors registered
    restarted = BridgeOAuthProvider(
        seal_key=SEAL,
        instance="staging",
        public_url=ISSUER,
        state_dir=tmp_path / "state",
        verifier=odoo,
        allowed_redirect_hosts=("claude.example.com",),
        allow_localhost_redirects=True,
        clock=lambda: now[0],
    )
    assert _run(restarted.get_client(reg.json()["client_id"])) is not None


def test_allowed_redirect_hosts_restrict_registration(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    assert _register(client).status_code == 201
    assert _register(client, redirect="https://other.example.com/cb").status_code == 400


def _tokens(provider, client):
    client_id, verifier, done = _full_flow(client)
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    body = _exchange(client, client_id, verifier, code).json()
    return client_id, body


def test_refresh_reverifies_key_and_rotates(provider, odoo):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    before = odoo.calls
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": body["refresh_token"],
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert odoo.calls == before + 1  # re-verified against Odoo
    new = refreshed.json()
    assert new["access_token"] != body["access_token"]
    # rotation: the old refresh token is dead
    again = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": body["refresh_token"],
        },
    )
    assert again.status_code == 400
    assert _run(provider.load_access_token(new["access_token"])) is not None


def test_refresh_fails_when_odoo_key_is_revoked(provider, odoo):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    del odoo.users["ann@example.com"]  # key revoked in Odoo
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": body["refresh_token"],
        },
    )
    assert refreshed.status_code == 400
    assert refreshed.json()["error"] == "invalid_grant"


def test_refresh_token_is_bound_to_its_client(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    _, body = _tokens(provider, client)
    other = _register(client).json()["client_id"]
    stolen = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": other,
            "refresh_token": body["refresh_token"],
        },
    )
    assert stolen.status_code == 400


def test_load_access_token_rejects_bad_tokens(provider, now):
    base = {
        "v": 1,
        "jti": "j1",
        "typ": "access",
        "uid": 1,
        "login": "a@example.com",
        "key": "k",
        "instance": "staging",
        "iat": int(now[0]),
        "exp": int(now[0]) + 100,
    }
    good = seal(SEAL, base)
    assert _run(provider.load_access_token(good)) is not None
    assert _run(provider.load_access_token(seal(bytes(32), base))) is None  # wrong key
    assert _run(provider.load_access_token(good[:-2] + "xx")) is None  # tampered
    assert _run(provider.load_access_token(seal(SEAL, {**base, "typ": "refresh"}))) is None
    assert _run(provider.load_access_token(seal(SEAL, {**base, "instance": "production"}))) is None
    assert _run(provider.load_access_token(seal(SEAL, {**base, "v": 2}))) is None
    now[0] += 101
    assert _run(provider.load_access_token(good)) is None  # expired


def test_refresh_token_cannot_be_used_as_access_token(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    _, body = _tokens(provider, client)
    assert _run(provider.load_access_token(body["refresh_token"])) is None
    reg_client = _run(provider.get_client(_tokens_client(provider)))
    assert reg_client is not None


def _tokens_client(provider):
    return next(iter(provider._clients))


def test_revocation_denies_the_token(provider):
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    assert _run(provider.load_access_token(body["access_token"])) is not None
    revoked = client.post(
        "/revoke",
        data={"client_id": client_id, "client_secret": "", "token": body["access_token"]},
    )
    assert revoked.status_code == 200
    assert _run(provider.load_access_token(body["access_token"])) is None
    assert provider.is_revoked(body["access_token"])


def test_revocation_set_is_bounded(provider, monkeypatch):
    monkeypatch.setattr("odoo_mcp.bridge.provider.MAX_DENIED", 5)
    results = [provider._claim(f"tok{i}", 1_800_000_000 + 100, None, "o") for i in range(8)]
    assert results == [True] * 5 + [False] * 3  # full of live denials: refuse, never evict
    assert len(provider._denied) == 5 and "tok0" in provider._denied


def test_no_key_in_provider_repr_or_client_file(provider, tmp_path):
    client = TestClient(_app(provider), base_url=ISSUER)
    _, body = _tokens(provider, client)
    loaded = _run(provider.load_access_token(body["access_token"]))
    assert KEY not in repr(loaded) and KEY not in loaded.model_dump_json()
    for path in (tmp_path / "state").rglob("*"):
        if path.is_file():
            assert KEY not in path.read_text()


# --------------------------------------------------------------- login allowlist


def _allowlisted(tmp_path, odoo, now, logins):
    return BridgeOAuthProvider(
        seal_key=SEAL,
        instance="staging",
        public_url=ISSUER,
        state_dir=tmp_path / "state",
        verifier=odoo,
        allowed_redirect_hosts=("claude.example.com",),
        allow_localhost_redirects=True,
        allowed_logins=logins,
        clock=lambda: now[0],
    )


def test_allowlist_admits_listed_login_case_insensitive(tmp_path, odoo, now):
    provider = _allowlisted(tmp_path, odoo, now, frozenset({"Ann@Example.com"}))
    client = TestClient(_app(provider), base_url=ISSUER)
    _, _, done = _full_flow(client, login="ANN@example.com")
    assert done.status_code == 302
    assert "code=" in done.headers["location"]


def test_allowlist_refuses_unlisted_login_after_key_verifies(tmp_path, odoo, now):
    odoo.users["bob@example.com"] = ("bob-key", 9)
    provider = _allowlisted(tmp_path, odoo, now, frozenset({"ann@example.com"}))
    client = TestClient(_app(provider), base_url=ISSUER)
    _, _, done = _full_flow(client, login="bob@example.com", key="bob-key")
    assert done.status_code == 302
    location = urlparse(done.headers["location"])
    query = parse_qs(location.query)
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["st1"]
    assert "code" not in query
    assert "bob-key" not in done.headers["location"]


def test_allowlist_wrong_key_same_answer_listed_or_not(tmp_path, odoo, now):
    odoo.users["bob@example.com"] = ("bob-key", 9)
    provider = _allowlisted(tmp_path, odoo, now, frozenset({"ann@example.com"}))
    client = TestClient(_app(provider), base_url=ISSUER)
    _, _, unlisted = _full_flow(client, login="bob@example.com", key="wrong")
    _, _, listed = _full_flow(client, login="ann@example.com", key="wrong")
    for done in (unlisted, listed):
        assert done.status_code == 200
        assert "Sign-in failed" in done.text
        assert "location" not in done.headers


def test_allowlist_unlisted_request_cannot_be_retried(tmp_path, odoo, now):
    odoo.users["bob@example.com"] = ("bob-key", 9)
    provider = _allowlisted(tmp_path, odoo, now, frozenset({"ann@example.com"}))
    client = TestClient(_app(provider), base_url=ISSUER)
    reg = _register(client)
    client_id = reg.json()["client_id"]
    _, challenge = _pkce()
    auth = _authorize(client, client_id, challenge)
    page = client.get(auth.headers["location"])
    fields = _signin_fields(page.text)
    first = client.post(
        "/signin",
        data={**fields, "login": "bob@example.com", "api_key": "bob-key"},
        follow_redirects=False,
    )
    assert "error=access_denied" in first.headers["location"]
    again = client.post(
        "/signin",
        data={**fields, "login": "ann@example.com", "api_key": KEY},
        follow_redirects=False,
    )
    assert again.status_code == 400  # the pending sign-in was consumed


def test_allowlist_removal_cuts_off_existing_tokens(tmp_path, odoo, now):
    open_provider = _allowlisted(tmp_path, odoo, now, None)
    client = TestClient(_app(open_provider), base_url=ISSUER)
    client_id, verifier, done = _full_flow(client)
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    tokens = _exchange(client, client_id, verifier, code).json()
    assert _run(open_provider.load_access_token(tokens["access_token"])) is not None

    # Restart with Ann no longer listed: same seal key, same state dir.
    closed = _allowlisted(tmp_path, odoo, now, frozenset({"someone@example.com"}))
    assert _run(closed.load_access_token(tokens["access_token"])) is None
    info = _run(closed.get_client(client_id))
    assert info is not None
    assert _run(closed.load_refresh_token(info, tokens["refresh_token"])) is None
    refused = TestClient(_app(closed), base_url=ISSUER).post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": tokens["refresh_token"],
        },
    )
    assert refused.status_code == 400


def test_allowlist_off_by_default(provider):
    assert provider.login_allowed("anyone@example.com")


def test_allowlist_uses_verifier_lowercase_not_casefold(tmp_path, odoo, now):
    provider = _allowlisted(tmp_path, odoo, now, frozenset({"strasse@example.com"}))
    assert provider.login_allowed("STRASSE@example.com")
    assert not provider.login_allowed("straße@example.com")
