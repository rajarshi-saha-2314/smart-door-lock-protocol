"""In-process test bed: the real AS and DL servers on ephemeral localhost ports, one event loop."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime

from common.clock import Clock, FakeClock, SystemClock
from common.config import Config
from common.keystore import load_door_config
from entities.auth_server import AuthServer
from entities.door_lock import DoorLock
from entities.user_device import LoginResult, SmartDevice
from tests.conftest import PASSWORDS

MONDAY_0930 = datetime(2026, 11, 2, 9, 30)  # CSE-4A has CSE-101 Mon 09:00-10:00
MONDAY_1830 = datetime(2026, 11, 2, 18, 30)


@dataclass
class Testbed:
    cfg: Config
    AS: AuthServer
    DL: dict[str, DoorLock]
    ports: dict[str, int]
    as_port: int


@asynccontextmanager
async def run_testbed(
    cfg: Config, *, clock: Clock | None = None, policy_time: datetime = MONDAY_0930
) -> AsyncIterator[Testbed]:
    clock = clock or SystemClock()
    AS = AuthServer(cfg, clock=clock, policy_clock=FakeClock(policy_time))
    servers = [await AS.start(port=0)]
    as_port = servers[0].sockets[0].getsockname()[1]
    DL: dict[str, DoorLock] = {}
    ports: dict[str, int] = {}
    for door in ("CSE-101", "CSE-102"):
        dl = DoorLock(cfg, load_door_config(cfg, door), clock=clock, as_port=as_port)
        srv = await dl.start(port=0)
        servers.append(srv)
        DL[door], ports[door] = dl, srv.sockets[0].getsockname()[1]
    try:
        yield Testbed(cfg, AS, DL, ports, as_port)
    finally:
        for srv in servers:
            srv.close()
            await srv.wait_closed()
        for dl in DL.values():
            if dl._relock_task:
                dl._relock_task.cancel()


def device(cfg: Config, ID_U: str, password: str | None = None, clock: Clock | None = None) -> SmartDevice:
    sd = SmartDevice(cfg, cfg.card_path(ID_U), clock=clock)
    assert sd.local_login(ID_U, password if password is not None else PASSWORDS[ID_U])
    return sd


async def login(
    tb: Testbed, ID_U: str, door: str = "CSE-101", commands: tuple[str, ...] = (), clock: Clock | None = None
) -> tuple[LoginResult, SmartDevice]:
    sd = device(tb.cfg, ID_U, clock=clock)
    result = await sd.login(door, tb.cfg.host, tb.ports[door], commands)
    return result, sd


async def send_and_close(host: str, port: int, frame_obj: dict) -> None:
    """Send one frame and hang up without reading the reply (simulates a dropped M4)."""
    from common import net

    reader, writer = await asyncio.open_connection(host, port)
    await net.send_frame(writer, frame_obj)
    await net.close(writer)
