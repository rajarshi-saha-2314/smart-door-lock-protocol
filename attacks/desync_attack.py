"""Desynchronization: drop M4 so the SD never learns TID_new.

python -m attacks.desync_attack
"""

from __future__ import annotations

from attacks.harness import Verdicts, banner, cfg, fresh_victim, proxy, run, run_sd
from common import console
from common.keystore import load_card
from db.store import Store

VICTIM, PW = "victim-desync", "Desync#Victim1"


def observer_state(label: str) -> None:
    row = Store(cfg.db_path).get_user(VICTIM)
    card = load_card(cfg.card_path(VICTIM))
    assert row is not None
    console.info(
        "DEMO",
        f"[observer] {label}: card TID={card.TID.hex()[:8]}…  AS TID_cur={row.TID_cur.hex()[:8]}…  "
        f"TID_old={row.TID_old.hex()[:8] + '…' if row.TID_old else None}",
    )


async def attack(v: Verdicts) -> None:
    banner("Desynchronization", "drop M4 (which carries TID_new) so the card and the AS disagree on the TID")
    fresh_victim(VICTIM, PW)
    observer_state("before")
    for i in (1, 2):
        async with proxy("drop", msg="M4") as p:
            r = await run_sd(VICTIM, PW, "CSE-101")
        console.info("DEMO", f"drop #{i}: proxy {p.actions}, SD result {r.status}")
        observer_state(f"after drop #{i}")

    async with proxy("pass"):
        r = await run_sd(VICTIM, PW, "CSE-101")
    observer_state("after recovery login")
    v.add(
        "desynchronization (drop M4 twice)",
        r.status == "UNLOCKED",
        f"next login used TID_old and succeeded ({r.status}); AS issued a fresh TID_new",
    )


if __name__ == "__main__":
    run(attack)
