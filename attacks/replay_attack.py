"""Replay attack: record a genuine session, then re-send its messages to the door.

python -m attacks.replay_attack [--wait]     (--wait also replays after ΔT has expired)
"""

from __future__ import annotations

import asyncio
import sys

from attacks.attacker_proxy import exchange
from attacks.harness import Verdicts, banner, cfg, door, fresh_victim, proxy, run, run_sd
from common import console

VICTIM, PW = "victim-replay", "Replay#Victim1"


async def attack(v: Verdicts) -> None:
    wait = "--wait" in sys.argv
    banner("Replay", "record a genuine login through the proxy, then replay M1 / M5 to the door")
    fresh_victim(VICTIM, PW)

    async with proxy("record") as p:
        legit = await run_sd(VICTIM, PW, "CSE-101")
    console.info("DEMO", f"genuine login through the proxy in record mode → {legit.status}")
    if legit.status != "UNLOCKED":
        v.add("replay (setup)", False, f"genuine login through the proxy failed: {legit.reason}")
        return
    M1 = p.frames("M1", "SD->DL")[0]
    M5 = p.frames("M5", "SD->DL")[0]
    host, port = door("CSE-101")

    # 1. replay the whole SD side of the transcript immediately (within ΔT)
    replies = await exchange(host, port, [M1, M5])
    reason = replies[0].get("reason", "") if replies else "connection closed"
    v.add("replay M1+M5 within ΔT", bool(replies) and replies[0]["type"] == "REJECT", reason)

    # 2. replay M5 alone on a new connection (no pending session)
    replies = await exchange(host, port, [M5])
    reason = replies[0].get("reason", "") if replies else "connection closed"
    v.add("replay M5 alone", bool(replies) and replies[0]["type"] == "REJECT", reason)

    # 3. replay M1 with T1 refreshed to "now" so the timestamp check passes
    refreshed = dict(M1, T1=M1["T1"] + 10)  # any change to T1 breaks the AES-GCM aad / k1
    replies = await exchange(host, port, [refreshed])
    reason = replies[0].get("reason", "") if replies else "connection closed"
    v.add("replay M1 with refreshed T1", bool(replies) and replies[0]["type"] == "REJECT", reason)

    # 4. replay after ΔT
    if wait:
        delay = cfg.delta_t_ms / 1000 + 2
        console.info("ATTACKER", f"waiting {delay:.0f}s for the replay cache entry's freshness window to pass …")
        await asyncio.sleep(delay)
        replies = await exchange(host, port, [M1])
        reason = replies[0].get("reason", "") if replies else "connection closed"
        v.add("replay M1 after ΔT", bool(replies) and replies[0]["type"] == "REJECT", reason)


if __name__ == "__main__":
    run(attack)
