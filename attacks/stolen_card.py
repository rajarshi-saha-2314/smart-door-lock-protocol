"""Stolen smart device + password guessing.

The attacker extracts everything stored on the victim's device {B, V, TID, n0, Q_AS, r}
(power-analysis assumption) and has also recorded one of the victim's past logins.

  1. Offline guessing: many dictionary words pass the fuzzy verifier V (≈ 1/n0 of them),
     and the recorded transcript gives no way to tell which one is right (design change D1).
     For comparison, the same attack against the ORIGINAL spec's M1 identifies the password exactly.
  2. Online guessing: trying the candidates at a real door locks the account after 5 failures.
  3. Card re-issue: even if the attacker later learns the password, the old card's A is dead (D2).

    python -m attacks.stolen_card
"""

from __future__ import annotations

import itertools
import shutil
import tempfile
import time
from pathlib import Path

from admin.register_user import register_user
from attacks.harness import Verdicts, banner, cfg, door, fresh_victim, proxy, run, run_sd, setup_step
from common import console
from common import crypto_utils as cu
from common.encoding import b64d, cat, split
from common.keystore import load_card
from common.protocol import aad_C1, compute_RPW, fuzzy_verifier, recover_A
from entities.user_device import SmartDevice

VICTIM, PW = "victim-stolen", "Sunshine#2024"

WORDS = """password admin welcome sunshine dragon monkey letmein football iloveyou master
shadow qwerty abc123 princess baseball superman trustno1 hello freedom whatever nitw warangal
cse student faculty india cricket secret summer winter""".split()
SUFFIXES = ["", "1", "12", "123", "1234", "!", "@123", "#1", "2023", "2024", "2025", "#2023", "#2024", "@2024"]


def dictionary() -> list[str]:
    words = [w.capitalize() for w in WORDS] + WORDS
    guesses = [w + s for w, s in itertools.product(words, SUFFIXES)]
    guesses += [f"{n:04d}" for n in range(10_000)]
    guesses = [g for g in dict.fromkeys(guesses) if g != PW]
    return guesses + [PW]  # for a reproducible demo the real password is placed last


def original_spec_k1(A: bytes, TID: bytes, T1: int) -> bytes:
    """k1 as in the ORIGINAL spec, before design change D1 (no ECDH)."""
    return cu.KDF(A, cat("M1", TID, T1))


async def attack(v: Verdicts) -> None:
    banner("Stolen smart device / password guessing", "extract the card, guess offline, then try online")
    fresh_victim(VICTIM, PW)
    async with proxy("record") as p:
        await run_sd(VICTIM, PW, "CSE-101")  # a past login the attacker recorded
    rec = p.frames("M1", "SD->DL")[0]

    stolen_path = Path(tempfile.mkdtemp()) / "stolen_card.json"
    shutil.copy(cfg.card_path(VICTIM), stolen_path)
    card = load_card(stolen_path)
    console.warn("ATTACKER", f"stole the device and extracted B, V={card.V}, TID, r, n0={card.n0}, Q_AS")

    # ---- 1. offline dictionary attack against V --------------------------------
    guesses = dictionary()
    t0 = time.perf_counter()
    candidates = [g for g in guesses if fuzzy_verifier(VICTIM, compute_RPW(g, card.r), card.n0) == card.V]
    dt = time.perf_counter() - t0
    console.info(
        "ATTACKER",
        f"offline: tried {len(guesses)} passwords in {dt:.2f}s → {len(candidates)} pass the fuzzy verifier V "
        f"(expected ≈ {len(guesses) / card.n0:.0f}); real password is one of them, but which?",
    )

    # can the recorded transcript single out the right candidate?
    TID, T1, ID_DL, E, C1 = b64d(rec["TID"]), rec["T1"], rec["ID_DL"], b64d(rec["E"]), b64d(rec["C1"])
    hits = 0
    for g in candidates:
        A = recover_A(card.B, VICTIM, compute_RPW(g, card.r))
        try:  # without Z = d_AS·E the attacker can only try the key derivation without it
            cu.Dec(original_spec_k1(A, TID, T1), C1, aad_C1(TID, T1, ID_DL, E))
            hits += 1
        except cu.IntegrityError:
            pass
    console.info(
        "ATTACKER",
        f"checking {len(candidates)} candidate A values against the recorded C1: {hits} confirmed "
        "(k1 = KDF(A ‖ Z, …) needs Z = e·Q_AS — computing it from E and Q_AS is the ECDH problem)",
    )

    # counterfactual: the same attack against an M1 built the ORIGINAL way (no ECDH)
    A_true = recover_A(card.B, VICTIM, compute_RPW(PW, card.r))
    old_C1 = cu.Enc(original_spec_k1(A_true, TID, T1), cat(cu.rand(16), VICTIM), cat(TID, T1, ID_DL))
    old_hits = []
    for g in candidates:
        A = recover_A(card.B, VICTIM, compute_RPW(g, card.r))
        try:
            split(cu.Dec(original_spec_k1(A, TID, T1), old_C1, cat(TID, T1, ID_DL)))
            old_hits.append(g)
        except cu.IntegrityError:
            pass
    console.warn(
        "DEMO",
        f'counterfactual — original spec (k1 = KDF(A, "M1"‖TID‖T1)): the transcript confirms {len(old_hits)} '
        f"candidate(s) {old_hits} → password recovered offline. This is why D1 adds ECDH.",
    )
    v.add(
        "stolen smart device: offline password guessing",
        hits == 0 and len(candidates) > 1,
        f"{len(candidates)} candidates pass V, transcript confirms none",
    )

    # ---- 2. online guessing at the door ----------------------------------------
    host, port = door("CSE-101")
    attempts = []
    for g in candidates[: cfg.max_failed_attempts + 1]:
        sd = SmartDevice(cfg, stolen_path)
        assert sd.local_login(VICTIM, g)  # every candidate passes the local check by construction
        r = await sd.login("CSE-101", host, port)
        attempts.append((g, r.status, r.reason))
        console.info("ATTACKER", f"online guess {len(attempts)}: {g!r} → {r.status}: {r.reason}")
    sd = SmartDevice(cfg, stolen_path)
    sd.local_login(VICTIM, PW)  # suppose the attacker now even hits the right password
    final = await sd.login("CSE-101", host, port)
    console.info("ATTACKER", f"guess with the CORRECT password after lockout → {final.status}: {final.reason}")
    v.add(
        "online password guessing",
        final.status == "REJECTED" and "locked" in final.reason and all(s != "UNLOCKED" for _, s, _ in attempts),
        f"account locked after {cfg.max_failed_attempts} failures; right password then refused",
    )

    # ---- 3. re-issue makes the stolen card useless even with the password ------
    setup_step("victim reports the device stolen → admin re-issues the card (v ← v+1)")
    register_user(cfg, VICTIM, PW, "faculty", reissue=True)
    async with proxy("record") as p2:
        ok = await run_sd(VICTIM, PW, "CSE-101")  # victim uses the new card; attacker watches
    console.info("DEMO", f"victim's new card works → {ok.status}")
    new_TID = b64d(p2.frames("M1", "SD->DL")[0]["TID"])
    sd = SmartDevice(cfg, stolen_path)
    sd.card.TID = new_TID  # observed on the wire, still accepted by the AS as TID_old
    sd.local_login(VICTIM, PW)
    r = await sd.login("CSE-101", host, port)
    v.add(
        "old card + known password after re-issue",
        r.status == "REJECTED" and ok.status == "UNLOCKED",
        r.reason,
    )
    shutil.rmtree(stolen_path.parent, ignore_errors=True)


if __name__ == "__main__":
    run(attack)
