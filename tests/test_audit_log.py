from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from common import crypto_utils as cu
from common.audit_log import GENESIS, AuditLog, verify_log
from common.config import Config
from common.encoding import b64e, canonical_json
from common.keystore import load_as_keys
from tests.helpers import MONDAY_1830, login, run_testbed


def _fill(path: Path, sk: cu.PrivateKey, n: int = 5) -> AuditLog:
    log = AuditLog(path, sk)
    for i in range(n):
        log.append(
            timestamp=1_000 + i,
            ID_U=f"user{i}",
            role="student",
            ID_DL="CSE-101",
            decision="DENY" if i % 2 else "ALLOW",
            reason=f"reason {i}",
            transcript_hash=cu.h(bytes([i])),
        )
    return log


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def sk() -> cu.PrivateKey:
    return cu.ecdsa_keygen()


def test_intact_log_verifies_and_is_chained(tmp_path: Path, sk: cu.PrivateKey) -> None:
    path = tmp_path / "log.jsonl"
    _fill(path, sk)
    result = verify_log(path, sk.public_key())
    assert result.ok and result.entries == 5
    lines = _lines(path)
    entries = [json.loads(line) for line in lines]
    assert entries[0]["prev_hash"] == GENESIS
    for prev_line, entry in zip(lines, entries[1:], strict=False):
        assert entry["prev_hash"] == cu.h(prev_line.encode()).hex()
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]


def test_log_resumes_after_restart(tmp_path: Path, sk: cu.PrivateKey) -> None:
    path = tmp_path / "log.jsonl"
    _fill(path, sk, 3)
    _fill(path, sk, 2)  # a new AuditLog instance continues seq and chain
    result = verify_log(path, sk.public_key())
    assert result.ok and result.entries == 5


def test_modified_field_detected(tmp_path: Path, sk: cu.PrivateKey) -> None:
    path = tmp_path / "log.jsonl"
    _fill(path, sk)
    lines = _lines(path)
    lines[1] = lines[1].replace('"decision":"DENY"', '"decision":"ALLOW"')
    _write(path, lines)
    result = verify_log(path, sk.public_key())
    assert not result.ok and result.first_bad_line == 2 and "signature" in (result.error or "")


def test_deleted_line_detected(tmp_path: Path, sk: cu.PrivateKey) -> None:
    path = tmp_path / "log.jsonl"
    _fill(path, sk)
    lines = _lines(path)
    del lines[2]
    _write(path, lines)
    result = verify_log(path, sk.public_key())
    assert not result.ok and result.first_bad_line == 3 and "hash chain" in (result.error or "")


def test_reordered_lines_detected(tmp_path: Path, sk: cu.PrivateKey) -> None:
    path = tmp_path / "log.jsonl"
    _fill(path, sk)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write(path, lines)
    result = verify_log(path, sk.public_key())
    assert not result.ok and result.first_bad_line == 2


def test_forged_entry_with_other_key_detected(tmp_path: Path, sk: cu.PrivateKey) -> None:
    path = tmp_path / "log.jsonl"
    _fill(path, sk, 2)
    lines = _lines(path)
    forged = {
        "seq": 3,
        "timestamp": 9,
        "ID_U": "mallory",
        "role": "admin",
        "ID_DL": "LAB-3",
        "decision": "ALLOW",
        "reason": "x",
        "transcript_hash": "00" * 32,
        "prev_hash": cu.h(lines[-1].encode()).hex(),
    }
    forged["signature"] = b64e(cu.ecdsa_sign(cu.ecdsa_keygen(), canonical_json(forged)))
    lines.append(json.dumps(forged, separators=(",", ":")))
    _write(path, lines)
    result = verify_log(path, sk.public_key())
    assert not result.ok and result.first_bad_line == 3 and "signature" in (result.error or "")


def test_protocol_run_produces_verifiable_log(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            await login(tb, "fac01", "CSE-101")
            await login(tb, "stu01", "CSE-102")  # DENY
        async with run_testbed(world, policy_time=MONDAY_1830) as tb:
            await login(tb, "stu01", "CSE-101")  # DENY outside timetable

    asyncio.run(go())
    result = verify_log(world.access_log_path, load_as_keys(world).pk_AS)
    assert result.ok and result.entries == 3
    decisions = [json.loads(line)["decision"] for line in _lines(world.access_log_path)]
    assert decisions == ["ALLOW", "DENY", "DENY"]
