from __future__ import annotations

import asyncio
import json

from common.config import Config
from common.keystore import load_card
from db.store import Store
from tests.helpers import login, run_testbed


def test_faculty_login_unlocks_and_rotates_tid(world: Config) -> None:
    async def go() -> None:
        TID0 = load_card(world.card_path("fac01")).TID
        async with run_testbed(world) as tb:
            result, _ = await login(tb, "fac01", "CSE-101")
            assert result.status == "UNLOCKED", result.reason
            assert result.reason == "UNLOCKED CSE-101 for 5 s"  # arrived over the Enc_SK channel
            assert tb.DL["CSE-101"].unlocked
            assert [e.kind for e in tb.DL["CSE-101"].events] == ["UNLOCKED"]

        card = load_card(world.card_path("fac01"))
        row = Store(world.db_path).get_user("fac01")
        assert row is not None
        assert result.TID_used == TID0
        assert card.TID == result.TID_new == row.TID_cur != TID0
        assert row.TID_old == TID0 and row.failed_attempts == 0

    asyncio.run(go())


def test_student_in_slot_and_admin_any_door(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            r1, _ = await login(tb, "stu01", "CSE-101")
            r2, _ = await login(tb, "adm01", "CSE-102")
            r3, _ = await login(tb, "cr01", "CSE-101")
        assert (r1.status, r2.status, r3.status) == ("UNLOCKED",) * 3

    asyncio.run(go())


def test_consecutive_logins_use_fresh_pseudonyms(world: Config) -> None:
    async def go() -> list[bytes]:
        tids = []
        async with run_testbed(world) as tb:
            for _ in range(3):
                result, _ = await login(tb, "fac01", "CSE-102")
                assert result.ok, result.reason
                assert result.TID_used is not None
                tids.append(result.TID_used)
        return tids

    tids = asyncio.run(go())
    assert len(set(tids)) == 3


def test_session_traffic_is_protected_with_SK(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            result, _ = await login(tb, "fac01", "CSE-101", commands=("LOCK",))
            assert result.session_replies == ["UNLOCKED CSE-101 for 5 s", "LOCKED CSE-101"]
            assert not tb.DL["CSE-101"].unlocked
            assert [e.kind for e in tb.DL["CSE-101"].events] == ["UNLOCKED", "LOCKED"]

    asyncio.run(go())


def test_successful_login_is_audit_logged(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            await login(tb, "fac01", "CSE-101")

    asyncio.run(go())
    lines = world.access_log_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    assert (entry["ID_U"], entry["ID_DL"], entry["decision"]) == ("fac01", "CSE-101", "ALLOW")
