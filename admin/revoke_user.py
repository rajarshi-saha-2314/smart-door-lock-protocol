"""Phase 5 — Revocation (offline admin CLI).

    python -m admin.revoke_user --id 23CSB0A07              # revoke (lost card, left course)
    python -m admin.revoke_user --id 23CSB0A07 --undo       # reinstate
    python -m admin.revoke_user --id 23CSB0A07 --reset-lockout

To replace a lost card use `python -m admin.register_user --id ... --reissue`.
"""

from __future__ import annotations

import argparse

from common import console
from common.config import load_config
from db.store import Store


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True, dest="ID_U")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--undo", action="store_true", help="clear the revoked flag")
    group.add_argument("--reset-lockout", action="store_true", help="reset failed_attempts to 0")
    args = ap.parse_args()
    store = Store(load_config().db_path)

    if not store.get_user(args.ID_U):
        console.reject("ADMIN", f"unknown user {args.ID_U}")
        raise SystemExit(1)
    if args.reset_lockout:
        store.reset_failed(args.ID_U)
        console.ok("ADMIN", f"failed_attempts reset for {args.ID_U}")
    else:
        store.set_revoked(args.ID_U, not args.undo)
        console.ok("ADMIN", f"{args.ID_U} {'reinstated' if args.undo else 'REVOKED'}")


if __name__ == "__main__":
    main()
