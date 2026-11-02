"""Unambiguous byte encodings shared by every entity.

The protocol's concatenation operator ``‖`` is implemented by :func:`cat`: every
field is written as a 4-byte big-endian length followed by its bytes, so
``cat("ab", "c") != cat("a", "bc")``.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

Field = bytes | str | int

INT_WIDTH = 8  # timestamps (Unix ms) and counters are encoded as 64-bit big-endian


def to_bytes(value: Field) -> bytes:
    """Convert a protocol field to bytes (str → UTF-8, int → 8-byte big-endian)."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bool):
        raise TypeError("bool is not a protocol field")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative integers are not protocol fields")
        return value.to_bytes(INT_WIDTH, "big")
    raise TypeError(f"unsupported field type: {type(value).__name__}")


def cat(*fields: Field) -> bytes:
    """Length-prefixed concatenation: the protocol's ``‖`` operator."""
    out = bytearray()
    for field in fields:
        data = to_bytes(field)
        out += len(data).to_bytes(4, "big")
        out += data
    return bytes(out)


def split(data: bytes, expected: int | None = None) -> list[bytes]:
    """Inverse of :func:`cat`. Raises ``ValueError`` on malformed input."""
    fields: list[bytes] = []
    i = 0
    while i < len(data):
        if i + 4 > len(data):
            raise ValueError("truncated length prefix")
        n = int.from_bytes(data[i : i + 4], "big")
        i += 4
        if i + n > len(data):
            raise ValueError("truncated field")
        fields.append(data[i : i + n])
        i += n
    if expected is not None and len(fields) != expected:
        raise ValueError(f"expected {expected} fields, got {len(fields)}")
    return fields


def to_int(data: bytes) -> int:
    if len(data) != INT_WIDTH:
        raise ValueError("integer field must be 8 bytes")
    return int.from_bytes(data, "big")


def to_str(data: bytes) -> str:
    return data.decode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64") from exc


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON (sorted keys, no whitespace) used for signatures."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def short_hex(data: bytes, n: int = 8) -> str:
    """Truncated hex for readable logs: ``3fa1c2…9e04 (16B)``."""
    hx = data.hex()
    if len(hx) <= 2 * n:
        return f"{hx} ({len(data)}B)"
    return f"{hx[:n]}…{hx[-4:]} ({len(data)}B)"
