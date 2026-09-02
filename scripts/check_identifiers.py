"""Fail the build if a Burke-specific identifier lands in a tracked file.

This repo is public. The forbidden values themselves must never appear here --
not as plaintext, not in a comment, not in this script, not in CI logs. So the
comparison never touches the literal words: every tracked file is walked with
`git ls-files`, lowercased, split into tokens, and each token is hashed with
SHA-256. A match is reported against the embedded hash set below, never
against the word itself, and only a file path and line number are printed --
never the token, never the hash's plaintext.

To regenerate FORBIDDEN_HASHES for a token:

    python -c "import hashlib; print(hashlib.sha256(b'<lowercase token>').hexdigest())"

The two tokens currently guarded against are the Burke hostname token (the
Burke Truck & Equipment Odoo hostname's distinguishing word) and the
production database token (the production Odoo database name). Ask Dalton for
the literal values if you need to add or verify one; do not write them down
here.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# SHA-256 hex digests of lowercase, single-word forbidden tokens.
# Regenerate per the docstring above -- never add a plaintext token to this file.
FORBIDDEN_HASHES: set[str] = {
    "9e1bd0a74a00c24905a00d92923977c57bdc4222ed29931aaaae97c4e03eec5d",  # Burke hostname token
    "8cc03af9df1fa65817aed391491a26ff314bd3c083f5e4c39231b2fda1b08b27",  # production database token
}

TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

# check_identifiers.py itself is intentionally not excluded: it contains only
# hex digests and English prose, none of which hash to a forbidden value.


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    )
    return [root / p for p in out.stdout.split("\0") if p]


def scan_file(path: Path) -> list[int]:
    """Return the 1-based line numbers where a forbidden token is found."""
    try:
        raw = path.read_bytes()
    except OSError:
        return []

    if b"\0" in raw:
        # Binary file -- not text, nothing to tokenize.
        return []

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []

    hits: list[int] = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        for token in TOKEN_SPLIT_RE.split(line.lower()):
            if not token:
                continue
            if hashlib_sha256(token) in FORBIDDEN_HASHES:
                hits.append(line_num)
                break
    return hits


def hashlib_sha256(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def main() -> int:
    root = repo_root()
    violations: list[str] = []

    for path in tracked_files(root):
        if not path.is_file():
            continue
        for line_num in scan_file(path):
            rel = path.relative_to(root).as_posix()
            violations.append(f"{rel}:{line_num}")

    if violations:
        print(
            "Forbidden identifier detected (value withheld -- this repo is "
            "public). Locations:",
            file=sys.stderr,
        )
        for loc in violations:
            print(f"  {loc}", file=sys.stderr)
        print(
            "\nRemove the identifier and, if it belongs, replace it with a "
            "<PLACEHOLDER> per docs/BURKE-DEPLOY.md.",
            file=sys.stderr,
        )
        return 1

    print("check_identifiers: no forbidden identifiers found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
