"""API-key authentication. The key identifies a NAMED analyst, so the identity used for
approvals and the audit log comes from authentication, never from a request field.
Demo-grade: no HTTPS, hashing, rotation or rate limiting."""
import os
import secrets
from typing import Annotated

from fastapi import Header, HTTPException


def parse_keys(raw):
    """'key1:analyst_1,key2:analyst_2' -> {'key1': 'analyst_1', ...}"""
    keys = {}
    for part in raw.split(","):
        key, sep, name = part.strip().partition(":")
        if sep and key and name.strip():
            keys[key] = name.strip().lower()
    return keys


def current_analyst(x_api_key: Annotated[str | None, Header()] = None) -> str:
    keys = parse_keys(os.getenv("ANALYST_KEYS", ""))  # read per request so tests can change it
    if not keys:
        raise HTTPException(status_code=503, detail="authentication is not configured")  # fail closed
    found = None
    if x_api_key:
        for key, name in keys.items():  # no early exit, and a constant-time comparison
            if secrets.compare_digest(x_api_key.encode(), key.encode()):
                found = name
    if found is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key",
                            headers={"WWW-Authenticate": "ApiKey"})
    return found
