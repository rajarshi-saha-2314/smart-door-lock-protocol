"""Computation and communication cost of the login phase → benchmarks/results.md

    python -m benchmarks.cost_analysis      (run benchmarks.primitive_timing first)

Operation counts follow Section 3 (with design changes D1-D3) for one successful
(ALLOW) login, Steps 1-7, including the door's Enc_SK confirmation.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from benchmarks.primitive_timing import CSV_PATH
from common.console import ensure_utf8_stdio

OUT = Path(__file__).with_name("results.md")

# ---------------------------------------------------------------- computation
# symbol → count, per entity. Where each count comes from is listed in WHERE.
COUNTS: dict[str, dict[str, int]] = {
    "SD": {"T_h": 4, "T_xor": 1, "T_ecm": 2, "T_kdf": 2, "T_enc": 1, "T_dec": 2, "T_hmac": 2},
    "DL": {"T_hmac": 3, "T_dec": 1, "T_enc": 1},
    "AS": {"T_h": 4, "T_hmac": 1, "T_ecm": 1, "T_kdf": 2, "T_dec": 1, "T_enc": 2},
}
AUDIT_EXTRA = {"T_h": 1, "T_sig": 1}  # AS: transcript hash + ECDSA signature of the log entry
D1_EXTRA = {"SD": {"T_ecm": 2}, "AS": {"T_ecm": 1}}  # what design change D1 added

WHERE = {
    "SD": "RPW, h(ID‖RPW), V check, SK (4 h); A = B ⊕ … (1 xor); E = e·G, Z = e·Q_AS (2 ecm); "
    "k1, k_u (2 kdf); C1 (1 enc); C_U, door confirmation (2 dec); verify Auth_DL, compute Auth_U (2 hmac)",
    "DL": "Tag2, Auth_DL, verify Auth_U (3 hmac); C_DL (1 dec); Enc_SK confirmation (1 enc)",
    "AS": "h(C1) replay cache, K_DL, A, SK (4 h); verify Tag2 (1 hmac); Z = d_AS·E (1 ecm); k1, k_u (2 kdf); "
    "C1 (1 dec); C_DL, C_U (2 enc)",
}
ORDER = ["T_h", "T_xor", "T_hmac", "T_kdf", "T_enc", "T_dec", "T_ecm", "T_fe", "T_sig"]

# ---------------------------------------------------------------- communication (bits)
SIZE = {
    "ID": 128,  # ID_U, ID_DL
    "TID": 128,
    "N": 128,  # nonces
    "T": 32,  # timestamps
    "H": 256,  # hash / HMAC / SK
    "GCM": 96 + 128,  # nonce + tag added by every AES-GCM ciphertext
    "E": 264,  # compressed P-256 point (D1) — not in the given size list
    "flag": 8,  # decision / role enumerations — not in the given size list
}


def gcm(*plain: int) -> int:
    return sum(plain) + SIZE["GCM"]


C1 = gcm(SIZE["N"], SIZE["ID"])
C_DL = gcm(SIZE["flag"], SIZE["H"], SIZE["flag"], SIZE["T"])
C_U = gcm(SIZE["flag"], SIZE["N"], SIZE["N"], SIZE["TID"], SIZE["T"])
MESSAGES: list[tuple[str, str, str, int]] = []
M1 = SIZE["TID"] + SIZE["T"] + SIZE["ID"] + SIZE["E"] + C1
MESSAGES.append(("M1", "SD → DL", "TID, T1, ID_DL, E, C1", M1))
M2 = M1 + SIZE["N"] + SIZE["T"] + SIZE["H"]
MESSAGES.append(("M2", "DL → AS", "M1, N2, T2, Tag2", M2))
M3 = SIZE["T"] + C_DL + C_U
MESSAGES.append(("M3", "AS → DL", "T3, C_DL, C_U", M3))
M4 = C_U + SIZE["T"] + SIZE["T"] + SIZE["H"]
MESSAGES.append(("M4", "DL → SD", "C_U, T3, T4, Auth_DL", M4))
M5 = SIZE["T"] + SIZE["H"]
MESSAGES.append(("M5", "SD → DL", "T5, Auth_U", M5))


def load_timings() -> tuple[dict[str, float], str]:
    if not CSV_PATH.exists():
        raise SystemExit(f"{CSV_PATH} missing — run `python -m benchmarks.primitive_timing` first")
    lines = CSV_PATH.read_text(encoding="utf-8").splitlines()
    header = lines[0].lstrip("# ") if lines[0].startswith("#") else ""
    rows = csv.DictReader(line for line in lines if not line.startswith("#"))
    return {r["symbol"]: float(r["mean_ms"]) for r in rows}, header


def symbolic(counts: dict[str, int]) -> str:
    return " + ".join(f"{counts[s]}{s}" for s in ORDER if counts.get(s))


def total_ms(counts: dict[str, int], t: dict[str, float]) -> float:
    return sum(n * t[s] for s, n in counts.items())


def merge(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return out


# ---------------------------------------------------------------- comparison with published schemes
RELATED_PATH = Path(__file__).with_name("related_schemes.json")
MARK = {"yes": "✔", "no": "✘", "n/r": "n/r"}
FEATURES = [
    ("offline_guessing_stolen_device", "Offline guessing with stolen device"),
    ("mutual_auth", "Mutual auth."),
    ("anonymity", "User anonymity"),
    ("untraceability", "Untraceability"),
    ("revocation", "Revocation"),
    ("desync", "Desync resistance"),
    ("forward_secrecy", "Forward secrecy"),
]


def comparison(t: dict[str, float], our_bits: int, our_messages: int) -> list[str]:
    """Section 4, generated entirely from related_schemes.json so a rerun never loses it."""
    data = json.loads(RELATED_PATH.read_text(encoding="utf-8"))
    schemes = data["schemes"]
    missing = {s for sc in schemes for ent in sc["counts"].values() for s in ent} - set(t)
    if missing:
        raise SystemExit(f"timings missing for {sorted(missing)} — rerun `python -m benchmarks.primitive_timing`")
    ours = {"user": COUNTS["SD"], "server": COUNTS["AS"], "device": COUNTS["DL"]}
    rows = [(f"[{i}] {s['label']}", s["counts"]) for i, s in enumerate(schemes, 1)]
    rows.append(("**This protocol**", ours))
    totals = {name: sum(total_ms(c, t) for c in counts.values()) for name, counts in rows}

    out = [
        "## 4. Comparison with existing schemes",
        "",
        "Four peer-reviewed schemes (2020–2025) were read in full; how they were chosen, every extracted value,",
        "its location in the paper and our recounts are in [related_schemes.json](related_schemes.json).",
        "All times below use **this machine's** timings from Section 1, never the papers' own timings.",
        "",
        "### 4.1 Computation cost (login + authentication, one session)",
        "",
        "| Scheme | User device (symbolic) | User (ms) | Server (symbolic) | Server (ms) "
        "| Door / sensor (symbolic, ms) | Total (ms) |",
        "|---|---|---:|---|---:|---|---:|",
    ]
    for name, c in rows:
        u, srv, dev = c["user"], c["server"], c["device"]
        out.append(
            f"| {name} | {symbolic(u)} | {total_ms(u, t):.4f} | {symbolic(srv)} | {total_ms(srv, t):.4f} "
            f"| {symbolic(dev)} ({total_ms(dev, t):.4f}) | {totals[name]:.4f} |"
        )

    out += [
        "",
        "### 4.2 Communication cost (as reported by each paper, under its own field sizes)",
        "",
        "| Scheme | Messages | Total bits | Hash / ID / EC-point size assumed (bits) |",
        "|---|---:|---:|---|",
    ]
    for i, s in enumerate(schemes, 1):
        out.append(f"| [{i}] {s['label']} | {s['messages']} | {s['comm_bits']} | {s['sizes_short']} |")
    out.append(f"| **This protocol** | {our_messages} | {our_bits} | 256 / 128 / 264 (compressed) |")

    out += [
        "",
        "### 4.3 Security features",
        "",
        "| Scheme | " + " | ".join(label for _, label in FEATURES) + " | Formal verification |",
        "|---|" + "---|" * len(FEATURES) + "---|",
    ]
    for i, s in enumerate(schemes, 1):
        cells = [MARK[s["security"][k]["value"]] for k, _ in FEATURES]
        out.append(f"| [{i}] {s['label']} | " + " | ".join(cells) + f" | {s['security']['formal']} |")
    o = data["ours"]["security"]
    out.append("| **This protocol** | " + " | ".join(MARK[o[k]["value"]] for k, _ in FEATURES) + f" | {o['formal']} |")
    out += [
        "",
        "✔ = claimed by the paper (for our protocol: verified by ProVerif and/or the attack scripts); "
        "✘ = not provided; n/r = not reported or not analysed by the paper. "
        "Claims of the other schemes are their authors' and were not re-verified here.",
        "",
        "### Notes",
        "",
    ]

    notes = [
        "**Primitive mappings.** "
        + "; ".join(
            f"[{i}] " + ", ".join(f"{k} → {v}" for k, v in s["primitive_map"].items()) for i, s in enumerate(schemes, 1)
        )
        + ". Our T_h is SHA-256 and T_ecm is a P-256 scalar multiplication (OpenSSL via `cryptography`).",
        "**T_fe** is a code-offset fuzzy extractor `Rep()` built on the `reedsolo` Reed–Solomon decoder "
        "(pure Python), so it is slow relative to the C-backed primitives; the papers themselves assume "
        "T_fe ≈ T_ecm. It only affects [1] and [3].",
        "**XOR** is not counted for the published schemes (none of the papers count it); our row includes "
        f"1T_xor ({t['T_xor']:.4f} ms).",
        "**Our row**: user = SD, server = AS, door = DL; the AS's audit-log signature (1T_h + 1T_sig) is excluded "
        "because no other scheme keeps a signed log.",
    ]
    for i, s in enumerate(schemes, 1):
        verdict = "matches the paper" if s["recount_matches_paper"] else "**differs from the paper**"
        pr = s["paper_reported"]
        reported = (
            f"paper: user {pr['user']}, server {pr['server']}, device {pr['device']}, total {pr['total']} "
            f"({pr['where']})"
        )
        recount = s["recount_notes"]
        notes.append(f"**[{i}] counts** — {reported}; our recount from the protocol steps {verdict}. {recount}")
    for i, s in enumerate(schemes, 1):
        extra = f" {s['comm_notes']}" if s["comm_notes"] else ""
        notes.append(f"**[{i}] communication** — {s['comm_where']}; sizes: {s['field_sizes']}.{extra}")
    for i, s in enumerate(schemes, 1):
        for k, label in FEATURES:
            note = s["security"][k].get("note")
            if note:
                notes.append(f"**[{i}] {label.lower()}** — {note}")
    for k, label in FEATURES:
        if o[k]["value"] != "yes":
            notes.append(f"**This protocol, {label.lower()}** — {o[k]['where']}.")
    out += [f"{n}. {text}" for n, text in enumerate(notes, 1)]

    # interpretation — numbers computed, so it stays consistent with the tables
    by = {s["key"]: (f"[{i}] {s['label']}", s) for i, s in enumerate(schemes, 1)}
    me = totals["**This protocol**"]
    oh_name = by["oh2021"][0]
    ecc = [by["zhao2022"][0], by["sudhakar2025"][0]]
    ecm = {name: sum(c.get("T_ecm", 0) for c in counts.values()) for name, counts in rows}
    dev_ms = {name: total_ms(counts["device"], t) for name, counts in rows}
    largest_comm = our_bits > max(s["comm_bits"] for s in schemes)
    out += [
        "",
        "### Interpretation",
        "",
        f"On this machine one login costs {me:.3f} ms across all three entities for our protocol, against "
        f"{totals[oh_name]:.3f} ms for the hash-only scheme {oh_name}, {totals[by['banerjee2020'][0]]:.3f} ms for "
        f"{by['banerjee2020'][0]} (mostly its fuzzy extractor), and {totals[ecc[0]]:.3f} / {totals[ecc[1]]:.3f} ms "
        f"for the ECC schemes {ecc[0]} and {ecc[1]}. "
        f"Our 3 EC scalar multiplications, all added by design change D1, make us about "
        f"{me / totals[oh_name]:.0f}× more expensive than {oh_name}, which has no public-key step at all; "
        "that step is what stops an attacker holding a stolen device from confirming password guesses against a "
        f"recorded login, whereas {oh_name} relies on the user's identity staying unguessable. "
        f"Among the ECC-based designs ours needs the fewest EC multiplications ({ecm['**This protocol**']} versus "
        f"{ecm[ecc[0]]} and {ecm[ecc[1]]}), and our door lock does only symmetric work "
        f"({dev_ms['**This protocol**']:.4f} ms) where their sensor nodes perform EC multiplications "
        f"({dev_ms[ecc[0]]:.4f} and {dev_ms[ecc[1]]:.4f} ms). "
        + (
            f"Our communication cost ({our_bits} bits) is the highest of the five, mainly because we size every "
            "hash/MAC at 256 bits (SHA-256) where the papers assume 128–160 bits, the door forwards the whole M1 "
            "inside M2, and each AES-GCM ciphertext carries a 96-bit nonce and a 128-bit tag. "
            if largest_comm
            else f"Our communication cost is {our_bits} bits. "
        )
        + "The security columns for the other schemes are their authors' claims; ours are checked by ProVerif and "
        "the attack scripts, and we do not offer forward secrecy against compromise of the AS secrets.",
        "",
        "### References",
        "",
    ]
    out += [
        f"{i}. {s['authors']}, “{s['title']},” *{s['venue']}*, {s['year']}. "
        f"doi:[{s['doi']}](https://doi.org/{s['doi']})"
        for i, s in enumerate(schemes, 1)
    ]
    out.append("")
    return out


def main() -> None:
    ensure_utf8_stdio()
    t, machine = load_timings()
    lines = [
        "# Performance analysis — login phase",
        "",
        "Generated by `python -m benchmarks.cost_analysis` from `benchmarks/primitive_timing.csv`.",
        "",
        f"Machine: {machine}",
        "",
        "## 1. Primitive timings",
        "",
        "| Symbol | Primitive | Mean (ms) |",
        "|---|---|---:|",
    ]
    desc = {
        r["symbol"]: r["primitive"]
        for r in csv.DictReader(
            line for line in CSV_PATH.read_text(encoding="utf-8").splitlines() if not line.startswith("#")
        )
    }
    lines += [f"| {s} | {desc[s]} | {t[s]:.4f} |" for s in t]

    lines += [
        "",
        "## 2. Computation cost per entity (one successful login, Steps 1–7)",
        "",
        "| Entity | Operations | Symbolic cost | Time (ms) |",
        "|---|---|---|---:|",
    ]
    grand = 0.0
    for entity, counts in COUNTS.items():
        ms = total_ms(counts, t)
        grand += ms
        lines.append(f"| {entity} | {WHERE[entity]} | {symbolic(counts)} | {ms:.4f} |")
    as_audit = merge(COUNTS["AS"], AUDIT_EXTRA)
    lines.append(
        f"| AS + audit log | above + transcript hash + ECDSA signature | {symbolic(as_audit)} | "
        f"{total_ms(as_audit, t):.4f} |"
    )
    total_counts = merge(merge(COUNTS["SD"], COUNTS["DL"]), COUNTS["AS"])
    lines.append(f"| **Total (protocol)** | | {symbolic(total_counts)} | **{grand:.4f}** |")
    d1_ms = sum(total_ms(c, t) for c in D1_EXTRA.values())
    lines += [
        "",
        f"Cost of design change D1 (ephemeral ECDH): 2T_ecm on SD + 1T_ecm on AS = {d1_ms:.4f} ms, "
        f"i.e. {100 * d1_ms / grand:.0f}% of the total — the price of resisting offline guessing with a stolen device.",
        "Fixed costs outside the login (password change, registration) and random-number generation are not included.",
        "",
        "## 3. Communication cost (bits)",
        "",
        "Field sizes: IDs 128, TID 128, nonces 128, timestamps 32, hash/HMAC/SK 256, AES-GCM nonce 96 + tag 128.",
        "Added assumptions (not in the given list): E = 264 (compressed P-256 point, D1); decision and role = 8 each.",
        "",
        "| Message | Direction | Fields | Bits |",
        "|---|---|---|---:|",
    ]
    lines += [f"| {m} | {d} | {f} | {b} |" for m, d, f, b in MESSAGES]
    total_bits = sum(b for *_, b in MESSAGES)
    air = sum(b for m, d, _, b in MESSAGES if "SD" in d)
    lines += [
        f"| **Total** | | | **{total_bits}** |",
        "",
        f"Ciphertexts: |C1| = {C1}, |C_DL| = {C_DL}, |C_U| = {C_U} bits. "
        f"SD ↔ DL (wireless link) carries M1 + M4 + M5 = {air} bits; D1 adds {SIZE['E']} bits (E) to M1 and M2.",
        "",
        "The implementation's wire format (JSON + base64, 64-bit timestamps, length-prefixed fields) is larger;",
        "the figures above are the protocol-level sizes conventionally used for comparison.",
        "",
    ]
    lines += comparison(t, total_bits, len(MESSAGES))
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"→ {OUT}")


if __name__ == "__main__":
    main()
