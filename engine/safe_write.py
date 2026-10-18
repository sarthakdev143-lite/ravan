#!/usr/bin/env python3
"""
safe_write.py — path containment helper. Fixes REV-002.

Import and call check() before any open(path, "w") in a script.
Raises ValueError if the resolved path escapes all allowed roots.
"""

import os
import sys

# Absolute roots that scripts are allowed to write under.
_ALLOWED = [
    "reports",
    os.path.join(".opencode", "security"),
]


def check(path: str, extra_roots: list[str] | None = None) -> str:
    """
    Validate that *path* resolves under an allowed root.

    Returns the realpath on success.
    Raises ValueError if the path escapes all allowed roots.
    """
    real = os.path.realpath(path)

    roots = [os.path.realpath(r) for r in _ALLOWED]
    if extra_roots:
        roots += [os.path.realpath(r) for r in extra_roots]

    for root in roots:
        try:
            common = os.path.commonpath([real, root])
            if common == root:
                return real
        except ValueError:
            # Different drives on Windows — not the same root.
            pass

    allowed_str = ", ".join(f"{os.path.realpath(r)!r}" for r in _ALLOWED)
    raise ValueError(
        f"[safe_write] Path {path!r} resolves to {real!r}, "
        f"which is outside allowed directories: {allowed_str}"
    )


def makedirs_safe(path: str, extra_roots: list[str] | None = None) -> str:
    """makedirs + check in one call. Returns the validated realpath."""
    safe = check(path, extra_roots)
    parent = os.path.dirname(safe)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return safe


if __name__ == "__main__":
    # Simple CLI for testing: python3 engine/safe_write.py <path>
    if len(sys.argv) < 2:
        print("usage: safe_write.py <path>", file=sys.stderr)
        sys.exit(1)
    try:
        result = check(sys.argv[1])
        print(f"OK: {result}")
    except ValueError as e:
        print(f"BLOCKED: {e}", file=sys.stderr)
        sys.exit(1)
