"""AES-256-GCM sealing of bridge tokens, and the seal-key file.

Tokens carry everything the bridge needs (uid, login, the user's Odoo API
key, expiry) inside the ciphertext, so nothing about users is stored at rest.
Rotating the seal key therefore revokes every token at once.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEAL_KEY_BYTES = 32
_NONCE_BYTES = 12
_PREFIX = "obt1."
_AAD = b"odoo-mcp-bridge|token|v1"


class SealKeyError(ValueError):
    """The seal-key file is missing, the wrong size, or too permissive."""


def generate_seal_key(path: str | os.PathLike[str]) -> None:
    """Write 32 random bytes to ``path`` with mode 0600; never overwrite."""
    target = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(SEAL_KEY_BYTES))
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise


def load_seal_key(path: str | os.PathLike[str]) -> bytes:
    """Read and validate the seal key; refuse a missing/short/loose file."""
    target = Path(path)
    try:
        info = target.stat()
    except OSError as exc:
        raise SealKeyError(f"seal key file is not readable: {target} ({exc.strerror})") from exc
    if not stat.S_ISREG(info.st_mode):
        raise SealKeyError(f"seal key path is not a regular file: {target}")
    if os.name == "posix" and info.st_mode & 0o077:
        raise SealKeyError(
            f"seal key file {target} is group/world accessible "
            f"(mode {stat.S_IMODE(info.st_mode):04o}); run chmod 600"
        )
    data = target.read_bytes()
    if len(data) != SEAL_KEY_BYTES:
        raise SealKeyError(
            f"seal key file {target} must hold exactly {SEAL_KEY_BYTES} bytes, "
            f"found {len(data)}; create it with --generate-seal-key"
        )
    return data


def seal(key: bytes, payload: dict[str, Any]) -> str:
    """Encrypt and authenticate ``payload``; returns an opaque URL-safe token."""
    if len(key) != SEAL_KEY_BYTES:
        raise SealKeyError("seal key must be 32 bytes")
    nonce = secrets.token_bytes(_NONCE_BYTES)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _AAD)
    return _PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode().rstrip("=")


def unseal(key: bytes, token: str) -> dict[str, Any] | None:
    """Return the payload, or ``None`` for anything not minted by this key."""
    if not isinstance(token, str) or not token.startswith(_PREFIX):
        return None
    body = token[len(_PREFIX) :]
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, TypeError):
        return None
    if len(raw) <= _NONCE_BYTES + 16:
        return None
    try:
        plaintext = AESGCM(key).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], _AAD)
        payload = json.loads(plaintext)
    except (InvalidTag, ValueError):
        return None
    return payload if isinstance(payload, dict) else None
