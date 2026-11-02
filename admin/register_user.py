"""Phase 2 — User registration (offline, over the secure channel at the department office).

Simulates both sides of the in-person registration:
  SD:  r ← random, RPW = h(PW_U ‖ r)
  U → AS (secure channel): {ID_U, RPW, role}
  AS:  A = h(ID_U ‖ x ‖ v), B = A ⊕ h(ID_U ‖ RPW), V = int(h(h(ID_U ‖ RPW))) mod n0, fresh TID
       stores {ID_U, role, TID_cur, TID_old=NULL, revoked=0, failed_attempts=0, v}
       issues {B, V, TID, n0, pk_AS, Q_AS}; SD adds r → cards/<ID_U>.json

With --reissue (Phase 5): new TID, new r, v ← v+1 (so A changes and the old card is dead).

    python -m admin.register_user --id 23CSB0A07 --role student --class CSE-4A [--password ...] [--reissue]
"""

from __future__ import annotations

import argparse
import getpass
from dataclasses import dataclass
from pathlib import Path

from common import console
from common import crypto_utils as cu
from common.config import Config, load_config
from common.keystore import Card, load_as_keys, save_card
from common.protocol import compute_A, compute_B, compute_RPW, fuzzy_verifier
from db.store import Store

ROLES = ("admin", "faculty", "cr", "student")


@dataclass(frozen=True)
class IssuedCard:
    """What the AS hands over the secure channel (everything except r)."""

    B: bytes
    V: int
    TID: bytes
    n0: int
    pk_AS_pem: str
    Q_AS: bytes


def sd_prepare(PW_U: str) -> tuple[bytes, bytes]:
    """SD side: pick r and compute RPW = h(PW_U ‖ r). PW_U never leaves the device."""
    r = cu.rand(16)
    return r, compute_RPW(PW_U, r)


def as_register(
    cfg: Config, ID_U: str, RPW: bytes, role: str, class_id: str | None, reissue: bool = False
) -> IssuedCard:
    """AS side of registration. Never stores PW_U, RPW or A."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if role in ("student", "cr") and not class_id:
        raise ValueError(f"role {role} needs --class")
    keys = load_as_keys(cfg)
    store = Store(cfg.db_path)
    existing = store.get_user(ID_U)
    TID = cu.rand(16)

    if reissue:
        if not existing:
            raise ValueError(f"user {ID_U} does not exist; cannot re-issue")
        v = store.reissue(ID_U, TID)
    else:
        if existing:
            raise ValueError(f"user {ID_U} already registered (use --reissue for a replacement card)")
        store.add_user(ID_U, role, class_id, TID)
        v = 1

    A = compute_A(ID_U, keys.x, v)
    B = compute_B(A, ID_U, RPW)
    V = fuzzy_verifier(ID_U, RPW, cfg.n0)
    return IssuedCard(
        B=B,
        V=V,
        TID=TID,
        n0=cfg.n0,
        pk_AS_pem=cu.public_key_to_pem(keys.pk_AS).decode("ascii"),
        Q_AS=keys.Q_AS,
    )


def register_user(
    cfg: Config,
    ID_U: str,
    PW_U: str,
    role: str,
    class_id: str | None = None,
    reissue: bool = False,
    card_path: Path | None = None,
) -> Path:
    """Full offline registration; writes the card file and returns its path."""
    r, RPW = sd_prepare(PW_U)
    issued = as_register(cfg, ID_U, RPW, role, class_id, reissue=reissue)
    card = Card(
        B=issued.B,
        V=issued.V,
        TID=issued.TID,
        n0=issued.n0,
        pk_AS_pem=issued.pk_AS_pem,
        Q_AS=issued.Q_AS,
        r=r,
    )
    path = card_path or cfg.card_path(ID_U)
    save_card(path, card)
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True, dest="ID_U")
    ap.add_argument("--role", choices=ROLES, help="required for new users")
    ap.add_argument("--class", dest="class_id", help="class, e.g. CSE-4A (students and CRs)")
    ap.add_argument("--password", help="omit to be prompted (recommended)")
    ap.add_argument("--reissue", action="store_true", help="issue a replacement card (Phase 5)")
    args = ap.parse_args()
    cfg = load_config()

    role, class_id = args.role, args.class_id
    if args.reissue:
        existing = Store(cfg.db_path).get_user(args.ID_U)
        if existing:
            role, class_id = existing.role, existing.class_id
    if not role:
        ap.error("--role is required for a new user")

    PW_U = args.password
    if PW_U is None:
        PW_U = getpass.getpass(f"Choose password for {args.ID_U}: ")
        if getpass.getpass("Repeat password: ") != PW_U:
            console.reject("ADMIN", "passwords do not match")
            raise SystemExit(1)
    try:
        path = register_user(cfg, args.ID_U, PW_U, role, class_id, reissue=args.reissue)
    except (ValueError, FileNotFoundError) as exc:
        console.reject("ADMIN", str(exc))
        raise SystemExit(1) from exc
    what = "re-issued card for" if args.reissue else "registered"
    console.ok("ADMIN", f"{what} {args.ID_U} (role={role}, class={class_id}) → card {path}")


if __name__ == "__main__":
    main()
