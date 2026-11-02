from __future__ import annotations

from datetime import datetime

import pytest

from admin.register_door import register_door
from admin.register_user import register_user
from admin.setup_system import setup_system
from common.config import Config
from common.keystore import load_as_keys, load_card, load_door_config
from common.protocol import (
    ALLOW,
    DENY,
    compute_A,
    compute_K_DL,
    compute_RPW,
    fuzzy_verifier,
    recover_A,
)
from db.store import Store
from entities.access_policy import AccessPolicy
from tests.conftest import PASSWORDS


def test_setup_creates_keys_and_refuses_overwrite(cfg: Config) -> None:
    keys = load_as_keys(cfg)
    assert len(keys.x) == 32 and len(keys.Q_AS) == 33
    assert cfg.sign_pk_path.exists() and cfg.db_path.exists()
    assert not setup_system(cfg)  # second run without --force is a no-op
    assert load_as_keys(cfg).x == keys.x


def test_door_registration(cfg: Config) -> None:
    d1 = register_door(cfg, "CSE-101")
    d2 = register_door(cfg, "CSE-102")
    x = load_as_keys(cfg).x
    assert d1.K_DL == compute_K_DL("CSE-101", x)
    assert d1.K_DL != d2.K_DL
    assert (d1.port, d2.port) == (cfg.dl_base_port, cfg.dl_base_port + 1)
    assert load_door_config(cfg, "CSE-101") == d1
    with pytest.raises(ValueError):
        register_door(cfg, "CSE-101")


def test_user_registration_card_and_db(world: Config) -> None:
    x = load_as_keys(world).x
    card = load_card(world.card_path("stu01"))
    RPW = compute_RPW(PASSWORDS["stu01"], card.r)
    assert recover_A(card.B, "stu01", RPW) == compute_A("stu01", x, 1)
    assert card.V == fuzzy_verifier("stu01", RPW, world.n0)
    assert len(card.TID) == 16

    row = Store(world.db_path).get_user("stu01")
    assert row is not None
    assert row.TID_cur == card.TID and row.TID_old is None
    assert (row.revoked, row.failed_attempts, row.card_version) == (False, 0, 1)


def test_db_never_stores_password_rpw_or_A(world: Config) -> None:
    rows = Store(world.db_path).raw_rows()
    columns = set(rows[0])
    assert columns == {
        "ID_U",
        "role",
        "class_id",
        "card_version",
        "TID_cur",
        "TID_old",
        "revoked",
        "failed_attempts",
    }
    x = load_as_keys(world).x
    blob = repr(rows)
    for ID_U, pw in PASSWORDS.items():
        assert pw not in blob
        assert compute_A(ID_U, x, 1).hex() not in blob


def test_duplicate_and_bad_registration(cfg: Config) -> None:
    register_user(cfg, "u1", "pw", "faculty")
    with pytest.raises(ValueError):
        register_user(cfg, "u1", "pw", "faculty")
    with pytest.raises(ValueError):
        register_user(cfg, "u2", "pw", "student")  # missing class
    with pytest.raises(ValueError):
        register_user(cfg, "u3", "pw", "janitor")
    with pytest.raises(ValueError):
        register_user(cfg, "ghost", "pw", "faculty", reissue=True)


def test_reissue_bumps_version_tid_and_A(world: Config) -> None:
    store = Store(world.db_path)
    x = load_as_keys(world).x
    old_card = load_card(world.card_path("fac01"))
    store.set_revoked("fac01", True)
    register_user(world, "fac01", "NewPass!", "faculty", reissue=True)
    new_card = load_card(world.card_path("fac01"))
    row = store.get_user("fac01")
    assert row is not None
    assert row.card_version == 2 and not row.revoked
    assert row.TID_cur == new_card.TID != old_card.TID
    assert store.find_by_tid(old_card.TID) is None
    A_new = recover_A(new_card.B, "fac01", compute_RPW("NewPass!", new_card.r))
    A_old = recover_A(old_card.B, "fac01", compute_RPW(PASSWORDS["fac01"], old_card.r))
    assert A_new == compute_A("fac01", x, 2) != A_old


def test_store_tid_rotation_and_lockout(world: Config) -> None:
    store = Store(world.db_path)
    row = store.get_user("stu01")
    assert row is not None
    TID0, TID1, TID2 = row.TID_cur, b"\x01" * 16, b"\x02" * 16
    store.rotate_tid("stu01", TID0, TID1)
    assert store.find_by_tid(TID0)[1] == "old"  # type: ignore[index]
    assert store.find_by_tid(TID1)[1] == "cur"  # type: ignore[index]
    store.rotate_tid("stu01", TID0, TID2)  # login with TID_old again (desync)
    assert store.find_by_tid(TID1) is None
    assert store.find_by_tid(TID0)[1] == "old"  # type: ignore[index]
    assert [store.increment_failed("stu01") for _ in range(3)] == [1, 2, 3]
    store.reset_failed("stu01")
    assert store.get_user("stu01").failed_attempts == 0  # type: ignore[union-attr]
    assert store.set_revoked("stu01", True) and store.get_user("stu01").revoked  # type: ignore[union-attr]
    assert not store.set_revoked("nobody", True)


# ---------------------------------------------------------------- access policy


@pytest.mark.parametrize(
    ("role", "class_id", "door", "when", "expected"),
    [
        ("admin", None, "LAB-3", "2026-11-08 03:00", ALLOW),  # Sunday 3am
        ("faculty", None, "CSE-102", "2026-11-02 07:00", ALLOW),
        ("faculty", None, "CSE-102", "2026-11-02 21:01", DENY),
        ("student", "CSE-4A", "CSE-101", "2026-11-02 09:30", ALLOW),  # Mon slot 09-10
        ("student", "CSE-4A", "CSE-101", "2026-11-02 08:50", DENY),
        ("student", "CSE-4A", "CSE-101", "2026-11-03 09:30", DENY),  # Tuesday
        ("student", "CSE-4A", "CSE-102", "2026-11-02 10:30", DENY),  # not their room
        ("cr", "CSE-4A", "CSE-101", "2026-11-02 08:50", ALLOW),  # within -15 min grace
        ("cr", "CSE-4A", "CSE-101", "2026-11-02 10:15", ALLOW),  # within +15 min grace
        ("cr", "CSE-4A", "CSE-101", "2026-11-02 10:16", DENY),
        ("faculty", None, "ROOF", "2026-11-02 10:00", DENY),  # not in policy
    ],
)
def test_access_policy(cfg: Config, role: str, class_id: str | None, door: str, when: str, expected: str) -> None:
    policy = AccessPolicy.load(cfg.policy_path)
    d = policy.evaluate("u", role, class_id, door, datetime.strptime(when, "%Y-%m-%d %H:%M"))
    assert d.decision == expected, d.reason
