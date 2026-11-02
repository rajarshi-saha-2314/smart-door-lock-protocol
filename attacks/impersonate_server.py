"""Server impersonation: answer for the AS without knowing x (hence without K_DL or A).

(a) The attacker sits between SD and DL and replies to M1 with a forged M4 (posing as DL + AS).
(b) The attacker redirects a door lock's AS traffic (DNS/ARP spoofing) to a rogue AS that
    returns a forged M3.

  python -m attacks.impersonate_server
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

from attacks.harness import Verdicts, banner, cfg, fresh_victim, proxy, run, run_sd
from common import console, net
from common import crypto_utils as cu
from common.clock import SystemClock
from common.encoding import b64e, cat
from common.messages import M2, M3

VICTIM, PW = "victim-imp-s", "ImpS#Victim1"
ROGUE_AS_PORT = 9300
REDIRECTED_DL_PORT = 9150


def forged_M4(_m1: dict) -> dict:
    now = SystemClock().now_ms()
    return {
        "type": "M4",
        "C_U": b64e(cu.rand(12 + 69 + 16)),  # right length, wrong key
        "T3": now,
        "T4": now,
        "Auth_DL": b64e(cu.rand(32)),
    }


async def rogue_as(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        m2 = await net.recv(reader, 5)
        assert isinstance(m2, M2)
        T3 = SystemClock().now_ms()
        K_guess = cu.rand(32)  # the rogue AS cannot compute K_DL = h(ID_DL ‖ x)
        C_DL = cu.Enc(K_guess, cat("ALLOW", cu.rand(32), "admin", T3), b"")
        m3 = M3(T3=T3, C_DL=C_DL, C_U=cu.rand(97))
        console.warn("ATTACKER", f"rogue AS answering door {m2.M1.ID_DL} with forged M3 (decision=ALLOW)")
        await net.send(writer, m3)
    finally:
        await net.close(writer)


async def wait_port(port: int, timeout: float = 8.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            _, w = await asyncio.open_connection(cfg.host, port)
            await net.close(w)
            return
        except OSError:
            await asyncio.sleep(0.1)
    raise TimeoutError(f"port {port} never opened")


async def attack(v: Verdicts) -> None:
    banner("Server impersonation", "answer on behalf of the AS without knowing x")
    fresh_victim(VICTIM, PW)

    # (a) forged M4 straight back to the SD
    console.rule("(a) forged M4 to the smart device")
    async with proxy("forge", forge=forged_M4):
        r = await run_sd(VICTIM, PW, "CSE-101")
    v.add("impersonate AS+DL to the user (forged M4)", r.status != "UNLOCKED", f"{r.status}: {r.reason}")

    # (b) rogue AS behind a genuine door lock
    console.rule("(b) rogue AS behind a genuine door lock")
    srv = await asyncio.start_server(rogue_as, cfg.host, ROGUE_AS_PORT)
    console.info("ATTACKER", f"rogue AS on :{ROGUE_AS_PORT}; door CSE-101's AS traffic is redirected there")
    dl = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "entities.door_lock",
        "--door",
        "CSE-101",
        "--port",
        str(REDIRECTED_DL_PORT),
        "--as-port",
        str(ROGUE_AS_PORT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    async def echo() -> None:
        assert dl.stdout is not None
        async for raw in dl.stdout:
            print(f"    ┃ {raw.decode('utf-8', 'replace').rstrip()}", flush=True)

    echo_task = asyncio.create_task(echo())
    try:
        await wait_port(REDIRECTED_DL_PORT)
        r = await run_sd(VICTIM, PW, "CSE-101", via_proxy=False, extra=("--port", str(REDIRECTED_DL_PORT)))
        v.add("impersonate AS to the door (forged M3)", r.status != "UNLOCKED", f"{r.status}: {r.reason}")
    finally:
        dl.terminate()
        await dl.wait()
        echo_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await echo_task
        srv.close()
        await srv.wait_closed()


if __name__ == "__main__":
    run(attack)
