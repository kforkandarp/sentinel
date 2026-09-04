"""Deterministic hashing utilities for Sentinel."""

import hashlib


def compute_artifact_hash(content: bytes | str) -> str:
    """Compute the deterministic SHA-256 hex digest of the given content.

    Strings are strictly encoded as UTF-8 bytes prior to hashing.
    """
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray)):
        content_bytes = bytes(content)
    else:
        raise TypeError(f"Expected bytes or str, got {type(content).__name__}")

    return hashlib.sha256(content_bytes).hexdigest()