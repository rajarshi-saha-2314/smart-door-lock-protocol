"""Compromised door lock: K_DL of CSE-101 leaks. Does it help against CSE-102?

python -m attacks.door_compromise
"""

from __future__ import annotations

from attacks.attacker_proxy import exchange
from attacks.harness import Verdicts, banner, cfg, fresh_victim, proxy, run, run_sd
from common import console
from common import crypto_utils as cu
from common.clock import SystemClock
from common.encoding import b64d, cat
from common.keystore import load_door_config
from common.messages import M1, M2
from common.protocol import compute_Tag2

VICTIM, PW = "victim-door", "Door#Victim1"


async def attack(v: Verdicts) -> None:
    banner("Door lock compromise", "extract K_DL from CSE-101's firmware and attack door CSE-102")
    fresh_victim(VICTIM, PW)
    K_101 = load_door_config(cfg, "CSE-101").K_DL
    console.warn("ATTACKER", f"extracted K_DL(CSE-101) = {K_101.hex()[:16]}…")

    async with proxy("record") as p:
        await run_sd(VICTIM, PW, "CSE-102")
    TID = b64d(p.frames("M1", "SD->DL")[0]["TID"])

    # 1. pose as door CSE-102 towards the AS using CSE-101's key
    now = SystemClock().now_ms()
    m1 = M1(TID=TID, T1=now, ID_DL="CSE-102", E=cu.ecdh_keygen()[1], C1=cu.rand(60))
    N2 = cu.rand(16)
    m2 = M2(M1=m1, N2=N2, T2=now, Tag2=compute_Tag2(K_101, m1.encode(), N2, now, "CSE-102"))
    console.info("ATTACKER", "sending M2 for door CSE-102 straight to the AS, tagged with K_DL(CSE-101)")
    replies = await exchange(cfg.host, cfg.as_port, [m2.to_wire()])
    reason = replies[0].get("reason", "closed") if replies else "closed"
    v.add("door compromise: pose as CSE-102", bool(replies) and replies[0]["type"] == "REJECT", reason)

    # 2. try to derive CSE-102's key or x from K_DL(CSE-101)
    K_102 = load_door_config(cfg, "CSE-102").K_DL  # [observer] ground truth, not known to the attacker
    guesses = [K_101, cu.h(cat("CSE-102", K_101)), cu.h(K_101), cu.xor(K_101, cu.h(b"CSE-102"))]
    derived = any(cu.ct_eq(g, K_102) for g in guesses)
    console.info(
        "ATTACKER",
        "K_DL = h(ID_DL ‖ x): recovering x from K_DL(CSE-101) is a SHA-256 preimage problem; "
        f"naive derivations of K_DL(CSE-102) matched: {derived}",
    )
    async with proxy("pass"):
        r = await run_sd(VICTIM, PW, "CSE-102")
    v.add(
        "door compromise: derive other door keys",
        not derived and r.status == "UNLOCKED",
        f"K_DL(CSE-102) independent of K_DL(CSE-101); CSE-102 keeps working ({r.status})",
    )
    console.info(
        "DEMO",
        "expected, limited impact: with K_DL(CSE-101) the attacker can act as door CSE-101 and read SK for "
        "sessions at CSE-101 only — never A, x, or any other door's key",
    )


if __name__ == "__main__":
    run(attack)
