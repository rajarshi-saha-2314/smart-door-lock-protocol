"""User impersonation: forge M1 without knowing A.

The attacker knows the victim's ID_U (public roll number), a TID observed on the wire,
and the AS's public ECDH key Q_AS. It still cannot produce a C1 the AS accepts.

    python -m attacks.impersonate_user
"""

from __future__ import annotations

from attacks.attacker_proxy import exchange
from attacks.harness import Verdicts, banner, cfg, door, fresh_victim, proxy, run, run_sd
from common import console
from common import crypto_utils as cu
from common.clock import SystemClock
from common.encoding import b64d, cat
from common.keystore import load_card
from common.messages import M1
from common.protocol import aad_C1, derive_k1

VICTIM, PW = "victim-imp-u", "ImpU#Victim1"


def forge_M1(TID: bytes, ID_U: str, ID_DL: str, Q_AS: bytes, A_guess: bytes) -> M1:
    T1 = SystemClock().now_ms()
    e, E = cu.ecdh_keygen()
    Z = cu.ecdh(e, Q_AS)  # the attacker CAN do this part — Q_AS is public
    k1 = derive_k1(A_guess, Z, TID, T1, E)
    C1 = cu.Enc(k1, cat(cu.rand(16), ID_U), aad_C1(TID, T1, ID_DL, E))
    return M1(TID=TID, T1=T1, ID_DL=ID_DL, E=E, C1=C1)


async def attack(v: Verdicts) -> None:
    banner("User impersonation", "forge M1 for a victim from their ID_U and an eavesdropped TID, without A")
    fresh_victim(VICTIM, PW)
    async with proxy("record") as p:
        await run_sd(VICTIM, PW, "CSE-101")
    observed_TID = b64d(p.frames("M1", "SD->DL")[0]["TID"])
    Q_AS = load_card(cfg.card_path(VICTIM)).Q_AS  # public value
    host, port = door("CSE-101")

    console.info("ATTACKER", "forging M1 with the observed TID (still valid as TID_old) and a guessed A")
    replies = await exchange(host, port, [forge_M1(observed_TID, VICTIM, "CSE-101", Q_AS, cu.rand(32)).to_wire()])
    reason = replies[0].get("reason", "closed") if replies else "closed"
    v.add("impersonate user (observed TID, guessed A)", bool(replies) and replies[0]["type"] == "REJECT", reason)

    console.info("ATTACKER", "forging M1 with an invented TID")
    replies = await exchange(host, port, [forge_M1(cu.rand(16), VICTIM, "CSE-101", Q_AS, cu.rand(32)).to_wire()])
    reason = replies[0].get("reason", "closed") if replies else "closed"
    v.add("impersonate user (invented TID)", bool(replies) and replies[0]["type"] == "REJECT", reason)


if __name__ == "__main__":
    run(attack)
