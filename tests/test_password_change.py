from __future__ import annotations

import asyncio

import pytest

from common.config import Config
from common.keystore import load_as_keys, load_card
from common.protocol import compute_A, compute_RPW, recover_A
from entities.user_device import SmartDevice
from tests.helpers import device, run_testbed


def test_password_change_requires_online_login(world: Config) -> None:
    sd = device(world, "stu01")  # local login only
    with pytest.raises(PermissionError):
        sd.change_password("new-pass")


def test_password_change_after_login(world: Config) -> None:
    old_card = load_card(world.card_path("fac01"))

    async def go() -> None:
        async with run_testbed(world) as tb:
            sd = device(world, "fac01")
            result = await sd.login("CSE-101", world.host, tb.ports["CSE-101"])
            assert result.ok
            sd.change_password("N3w-Secret!")

            card = load_card(world.card_path("fac01"))
            assert card.r != old_card.r and card.B != old_card.B
            assert card.TID == result.TID_new  # TID update from the login is kept
            # A is unchanged and the AS was not involved
            A = recover_A(card.B, "fac01", compute_RPW("N3w-Secret!", card.r))
            assert A == compute_A("fac01", load_as_keys(world).x, 1)

            fresh = SmartDevice(world, world.card_path("fac01"))
            assert fresh.local_login("fac01", "N3w-Secret!")
            again = await fresh.login("CSE-101", world.host, tb.ports["CSE-101"])
            assert again.ok

    asyncio.run(go())
