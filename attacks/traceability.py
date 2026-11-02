"""Traceability: can an eavesdropper link two sessions of the same user, or learn who they are?

python -m attacks.traceability
"""

from __future__ import annotations

import json

from attacks.harness import Verdicts, banner, fresh_victim, proxy, run, run_sd
from common import console
from common.encoding import b64e

VICTIM, PW = "victim-trace", "Trace#Victim1"


async def attack(v: Verdicts) -> None:
    banner("Traceability / anonymity", "record two logins by the same user and compare everything on the wire")
    fresh_victim(VICTIM, PW)
    async with proxy("record") as p:
        await run_sd(VICTIM, PW, "CSE-101")
        await run_sd(VICTIM, PW, "CSE-101")
    m1a, m1b = p.frames("M1", "SD->DL")[:2]
    for name in ("TID", "E", "C1"):
        console.info("ATTACKER", f"{name}: session 1 = {m1a[name][:16]}…  session 2 = {m1b[name][:16]}…")

    # any value (other than the public door id / type) that repeats across the two sessions?
    def values(direction_frames: list[tuple[str, dict]]) -> set[str]:
        out = set()
        for _, frame in direction_frames:
            for k, val in frame.items():
                if k not in ("type", "ID_DL") and isinstance(val, str):
                    out.add(val)
        return out

    half = len(p.captured) // 2
    common_values = values(p.captured[:half]) & values(p.captured[half:])
    wire = json.dumps([f for _, f in p.captured])
    id_visible = VICTIM in wire or b64e(VICTIM.encode()) in wire
    console.info(
        "ATTACKER", f"values repeated across sessions: {len(common_values)}; ID_U visible on wire: {id_visible}"
    )
    v.add(
        "traceability (link two sessions / learn ID_U)",
        m1a["TID"] != m1b["TID"] and not common_values and not id_visible,
        "TID rotates every session, ID_U only inside C1 — sessions unlinkable",
    )


if __name__ == "__main__":
    run(attack)
