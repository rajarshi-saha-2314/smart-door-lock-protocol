"""MITM tampering: modify one field of M1, M4 or M5 in transit.

python -m attacks.mitm_tamper
"""

from __future__ import annotations

from attacks.harness import Verdicts, banner, fresh_victim, proxy, run, run_sd
from common import console

VICTIM, PW = "victim-mitm", "Mitm#Victim1"

CASES = [
    ("M1", "C1", "AS: C1 fails AES-GCM"),
    ("M1", "T1", "T1 is bound into k1 and the GCM aad"),
    ("M1", "E", "E is bound into k1 (wrong Z)"),
    ("M4", "C_U", "SD: C_U fails AES-GCM → AS not authenticated"),
    ("M4", "Auth_DL", "SD: Auth_DL invalid → door not authenticated"),
    ("M5", "Auth_U", "DL: Auth_U invalid → door stays locked"),
]


async def attack(v: Verdicts) -> None:
    banner("MITM tampering", "flip one bit / value in a field of M1, M4 or M5 while relaying")
    fresh_victim(VICTIM, PW)
    for msg, field, expect in CASES:
        console.rule(f"tamper {msg}.{field}")
        async with proxy("tamper", msg=msg, field=field) as p:
            r = await run_sd(VICTIM, PW, "CSE-101")
        tampered = any(a.startswith("tampered") for a in p.actions)
        blocked = tampered and r.status != "UNLOCKED"
        v.add(f"MITM tamper {msg}.{field}", blocked, f"{r.status}: {r.reason or expect}")

    console.rule("genuine login after the attacks (proxy in pass mode)")
    async with proxy("pass"):
        r = await run_sd(VICTIM, PW, "CSE-101")
    console.info("DEMO", f"legitimate login through the proxy (pass mode) → {r.status}")
    v.add("MITM leaves no lasting damage", r.status == "UNLOCKED", f"genuine user still logs in: {r.status}")


if __name__ == "__main__":
    run(attack)
