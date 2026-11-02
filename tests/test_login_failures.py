from __future__ import annotations

import asyncio

from common import crypto_utils as cu
from common.clock import FakeClock
from common.config import Config
from common.keystore import load_card, load_door_config, save_card
from common.messages import M1, M2, M3, Reject
from common.protocol import compute_Tag2
from db.store import Store
from entities.user_device import SmartDevice
from tests.helpers import MONDAY_1830, device, login, run_testbed


def make_M2(cfg: Config, m1: M1, *, T2: int | None = None, door: str | None = None) -> M2:
    """What an honest door lock would forward for this M1."""
    dc = load_door_config(cfg, door or m1.ID_DL)
    N2, T2 = cu.rand(16), T2 if T2 is not None else m1.T1
    return M2(M1=m1, N2=N2, T2=T2, Tag2=compute_Tag2(dc.K_DL, m1.encode(), N2, T2, dc.ID_DL))


def test_wrong_password_rejected_locally(world: Config) -> None:
    sd = SmartDevice(world, world.card_path("stu01"))
    # a wrong password passes the fuzzy verifier with probability ~1/n0; try several to be sure
    rejected = sum(not sd.local_login("stu01", f"wrong-{i}") for i in range(20))
    assert rejected >= 15
    assert not sd.local_login("someone-else", "Student#Pass1")


def test_revoked_user_rejected(world: Config) -> None:
    Store(world.db_path).set_revoked("stu01", True)

    async def go() -> None:
        async with run_testbed(world) as tb:
            result, _ = await login(tb, "stu01", "CSE-101")
            assert result.status == "REJECTED" and "revoked" in result.reason
            assert not tb.DL["CSE-101"].unlocked

    asyncio.run(go())


def test_outside_timetable_is_denied_but_authenticated(world: Config) -> None:
    TID0 = load_card(world.card_path("stu01")).TID

    async def go() -> None:
        async with run_testbed(world, policy_time=MONDAY_1830) as tb:
            result, sd = await login(tb, "stu01", "CSE-101")
            assert result.status == "DENIED"
            assert "outside CSE-4A's timetable" in result.reason
            assert sd.online_verified  # the AS still authenticated itself to the user
            assert not tb.DL["CSE-101"].unlocked
            assert [e.kind for e in tb.DL["CSE-101"].events] == ["DENIED"]
            # faculty is still fine at 18:30
            r2, _ = await login(tb, "fac01", "CSE-101")
            assert r2.ok

    asyncio.run(go())
    assert load_card(world.card_path("stu01")).TID != TID0  # pseudonym rotated even on DENY


def test_student_wrong_room_denied(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            result, _ = await login(tb, "stu01", "CSE-102")
            assert result.status == "DENIED" and "no class in CSE-102" in result.reason

    asyncio.run(go())


def test_expired_timestamp_rejected_by_door(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            slow = FakeClock()
            slow.advance(-(world.delta_t_ms + 5_000))  # SD clock 35 s behind
            result, _ = await login(tb, "fac01", "CSE-101", clock=slow)
            assert result.status == "REJECTED" and "stale timestamp T1" in result.reason

    asyncio.run(go())


def test_expired_timestamps_rejected_by_AS(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            m1, _ = device(world, "fac01").build_M1("CSE-101")
            stale = m1.T1 - world.delta_t_ms - 1_000
            r = tb.AS.handle_M2(make_M2(world, m1, T2=stale))
            assert isinstance(r, Reject) and "stale timestamp T2" in r.reason

            old_sd = device(world, "fac01", clock=FakeClock(stale))
            m1_old, _ = old_sd.build_M1("CSE-101")
            r = tb.AS.handle_M2(make_M2(world, m1_old, T2=m1.T1))
            assert isinstance(r, Reject) and "stale timestamp T1" in r.reason

    asyncio.run(go())


def test_unknown_tid_rejected(world: Config) -> None:
    card = load_card(world.card_path("fac01"))
    card.TID = cu.rand(16)
    save_card(world.card_path("fac01"), card)

    async def go() -> None:
        async with run_testbed(world) as tb:
            result, _ = await login(tb, "fac01", "CSE-101")
            assert result.status == "REJECTED" and "unknown TID" in result.reason

    asyncio.run(go())


def test_replayed_M1_rejected(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            m1, _ = device(world, "fac01").build_M1("CSE-101")
            first = tb.AS.handle_M2(make_M2(world, m1))
            assert isinstance(first, M3)
            again = tb.AS.handle_M2(make_M2(world, m1))  # same M1, fresh N2/T2/Tag2
            assert isinstance(again, Reject) and "replay detected" in again.reason

    asyncio.run(go())


def test_forged_Tag2_rejected_and_does_not_poison_replay_cache(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            m1, _ = device(world, "fac01").build_M1("CSE-101")
            forged = make_M2(world, m1)
            forged.Tag2 = cu.rand(32)
            r = tb.AS.handle_M2(forged)
            assert isinstance(r, Reject) and "Tag2 invalid" in r.reason
            # the genuine M2 for the same M1 still goes through (design note D4)
            assert isinstance(tb.AS.handle_M2(make_M2(world, m1)), M3)
            # a door cannot forward an M1 addressed to another door
            m1b, _ = device(world, "fac01").build_M1("CSE-101")
            r = tb.AS.handle_M2(make_M2(world, m1b, door="CSE-102"))
            assert isinstance(r, Reject) and "Tag2 invalid" in r.reason

    asyncio.run(go())


def test_lockout_after_five_failures(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            for i in range(world.max_failed_attempts):
                attacker = device(world, "stu01")
                attacker._A = cu.rand(32)  # wrong A (e.g. a fuzzy-verifier false accept)
                r = await attacker.login("CSE-101", world.host, tb.ports["CSE-101"])
                assert r.status == "REJECTED" and f"failed_attempts={i + 1}/5" in r.reason
            result, _ = await login(tb, "stu01", "CSE-101")  # even the genuine user is now blocked
            assert result.status == "REJECTED" and "locked after 5 failed attempts" in result.reason

    asyncio.run(go())
    Store(world.db_path).reset_failed("stu01")

    async def again() -> None:
        async with run_testbed(world) as tb:
            result, _ = await login(tb, "stu01", "CSE-101")
            assert result.ok

    asyncio.run(again())


def test_successful_login_resets_failed_attempts(world: Config) -> None:
    async def go() -> None:
        async with run_testbed(world) as tb:
            attacker = device(world, "fac01")
            attacker._A = cu.rand(32)
            await attacker.login("CSE-101", world.host, tb.ports["CSE-101"])
            assert Store(world.db_path).get_user("fac01").failed_attempts == 1  # type: ignore[union-attr]
            assert (await login(tb, "fac01", "CSE-101"))[0].ok
            assert Store(world.db_path).get_user("fac01").failed_attempts == 0  # type: ignore[union-attr]

    asyncio.run(go())


def test_reissued_card_kills_old_card_even_with_password(world: Config) -> None:
    """D2: A = h(ID_U ‖ x ‖ v). Old card + correct password + a currently valid TID → still rejected."""
    from admin.register_user import register_user
    from tests.conftest import PASSWORDS

    old = device(world, "fac01")  # attacker holds the old card AND knows the password
    register_user(world, "fac01", "brand-new-pw", "faculty", reissue=True)

    async def go() -> None:
        async with run_testbed(world) as tb:
            victim = device(world, "fac01", password="brand-new-pw")
            ok = await victim.login("CSE-101", world.host, tb.ports["CSE-101"])
            assert ok.ok and ok.TID_used is not None
            old.card.TID = ok.TID_used  # TID seen on the wire, still accepted as TID_old
            r = await old.login("CSE-101", world.host, tb.ports["CSE-101"])
            assert r.status == "REJECTED" and "C1 failed AES-GCM" in r.reason
            assert PASSWORDS["fac01"]  # (password was known to the attacker)

    asyncio.run(go())
