"""Signed, hash-chained audit log (Section 6) — non-repudiation of AS decisions.

Each line of ``logs/access_log.jsonl`` is a JSON object with
    seq, timestamp, ID_U, role, ID_DL, decision, reason, transcript_hash, prev_hash, signature
where prev_hash = SHA-256 of the previous line (bytes as written, without the newline;
64 zeros for the first entry) and signature = ECDSA(sk_AS) over the canonical JSON of
all other fields.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common import crypto_utils as cu
from common.encoding import b64d, b64e, canonical_json

GENESIS = "0" * 64
FIELDS = (
    "seq",
    "timestamp",
    "ID_U",
    "role",
    "ID_DL",
    "decision",
    "reason",
    "transcript_hash",
    "prev_hash",
)


class AuditLog:
    def __init__(self, path: Path, sk_AS: cu.PrivateKey) -> None:
        self.path = path
        self.sk_AS = sk_AS
        path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev_hash = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open("rb") as f:
            for raw in f:
                if raw.strip():
                    last = raw.rstrip(b"\r\n")
        if last is None:
            return 0, GENESIS
        return int(json.loads(last)["seq"]), cu.h(last).hex()

    def append(
        self,
        *,
        timestamp: int,
        ID_U: str | None,
        role: str | None,
        ID_DL: str,
        decision: str,
        reason: str,
        transcript_hash: bytes,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "seq": self._seq + 1,
            "timestamp": timestamp,
            "ID_U": ID_U,
            "role": role,
            "ID_DL": ID_DL,
            "decision": decision,
            "reason": reason,
            "transcript_hash": transcript_hash.hex(),
            "prev_hash": self._prev_hash,
        }
        entry["signature"] = b64e(cu.ecdsa_sign(self.sk_AS, canonical_json(entry)))
        line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        with self.path.open("ab") as f:
            f.write(line + b"\n")
        self._seq += 1
        self._prev_hash = cu.h(line).hex()
        return entry


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    first_bad_line: int | None = None
    error: str | None = None


def _check_entry(line: bytes, pk_AS: cu.PublicKey, prev_hash: str, expected_seq: int) -> str | None:
    """Return None if the line is valid, else a description of the problem."""
    try:
        entry = json.loads(line)
        sig = b64d(entry.pop("signature"))
    except (ValueError, KeyError, AttributeError, TypeError):
        return "unparseable entry"
    if set(entry) != set(FIELDS):
        return "unexpected or missing fields"
    if not cu.ecdsa_verify(pk_AS, sig, canonical_json(entry)):
        return "invalid ECDSA signature (entry content was modified)"
    if entry["prev_hash"] != prev_hash:
        return "hash chain broken (prev_hash mismatch: a previous line was altered, removed or inserted)"
    if entry["seq"] != expected_seq:
        return f"sequence gap (expected seq {expected_seq}, found {entry['seq']})"
    return None


def verify_log(path: Path, pk_AS: cu.PublicKey) -> VerifyResult:
    """Check every signature, the hash chain and sequence numbers."""
    if not path.exists():
        return VerifyResult(True, 0)
    prev_hash, expected_seq, count = GENESIS, 1, 0
    with path.open("rb") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.rstrip(b"\r\n")
            if not line.strip():
                continue

            error = _check_entry(line, pk_AS, prev_hash, expected_seq)
            if error:
                return VerifyResult(False, count, lineno, error)
            prev_hash = cu.h(line).hex()
            expected_seq += 1
            count += 1
    return VerifyResult(True, count)
