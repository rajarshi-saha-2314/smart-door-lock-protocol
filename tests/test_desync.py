from __future__ import annotations

import asyncio

from common.config import Config
from common.keystore import load_card
from db.store import Store
from tests.helpers import device, login, run_testbed, send_and_close


async def _drop_M4(world: Config, tb, ID_U: str) -> None:  # type: ignore[no-untyped-def]
    """The SD sends M1 but never receives M4 (attacker drops it)."""
    store = Store(world.db_path)
    before = store.get_user(ID_U).TID_cur  # type: ignore[union-attr]
    m1, _ = device(world, ID_U).build_M1("CSE-101")
    await send_and_close(world.host, tb.ports["CSE-101"], m1.to_wire())
    for _ in range(100):  # wait until the AS has processed the request and rotated TID_cur
        await asyncio.sleep(0.02)
        if store.get_user(ID_U).TID_cur != before:  # type: ignore[union-attr]
            return
    raise AssertionError("AS never processed the dropped session")


def test_dropped_M4_then_login_with_TID_old(world: Config) -> None:
    store = Store(world.db_path)
    TID0 = load_card(world.card_path("stu01")).TID

    async def go() -> None:
        async with run_testbed(world) as tb:
            await _drop_M4(world, tb, "stu01")
            row = store.get_user("stu01")
            assert row is not None
            TID1 = row.TID_cur
            assert row.TID_old == TID0 and TID1 != TID0
            assert load_card(world.card_path("stu01")).TID == TID0  # SD never got TID1

            result, _ = await login(tb, "stu01", "CSE-101")
            assert result.ok, result.reason
            assert result.TID_used == TID0

            row = store.get_user("stu01")
            assert row is not None
            assert row.TID_old == TID0  # the TID just used
            assert row.TID_cur == result.TID_new == load_card(world.card_path("stu01")).TID
            assert store.find_by_tid(TID1) is None  # never-delivered TID1 is discarded

    asyncio.run(go())


def test_repeated_drops_still_recover(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            for _ in range(3):
                await _drop_M4(world, tb, "fac01")
            result, _ = await login(tb, "fac01", "CSE-101")
            assert result.ok
            follow_up, _ = await login(tb, "fac01", "CSE-101")  # and the new TID works too
            assert follow_up.ok and follow_up.TID_used == result.TID_new

    asyncio.run(go())
