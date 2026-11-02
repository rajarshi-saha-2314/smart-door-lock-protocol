"""Phase 0 — System setup at the AS (offline).

Generates the master secret x, the ECDSA audit-log key pair (sk_AS, pk_AS) and the
static ECDH key pair (d_AS, Q_AS), then initialises the database.

    python -m admin.setup_system [--force]
"""

from __future__ import annotations

import argparse
import os
import shutil

from common import console
from common import crypto_utils as cu
from common.config import Config, load_config
from common.keystore import write_atomic
from db.store import Store


def setup_system(cfg: Config, force: bool = False) -> bool:
    """Create AS keys + DB. Returns False if the system already exists and force is not set."""
    if cfg.master_key_path.exists() and not force:
        return False
    if force:
        # a new x invalidates every K_DL, A and card — wipe all dependent state
        cfg.door_directory_path.unlink(missing_ok=True)
        for d in (cfg.keys_dir, cfg.cards_dir, cfg.logs_dir):
            shutil.rmtree(d, ignore_errors=True)
        for f in cfg.db_path.parent.glob(cfg.db_path.name + "*"):
            f.unlink()

    x = cu.rand(32)
    sk_AS = cu.ecdsa_keygen()
    d_AS, _ = cu.ecdh_keygen()

    write_atomic(cfg.master_key_path, x)
    write_atomic(cfg.sign_sk_path, cu.private_key_to_pem(sk_AS))
    write_atomic(cfg.sign_pk_path, cu.public_key_to_pem(sk_AS.public_key()))
    write_atomic(cfg.dh_sk_path, cu.private_key_to_pem(d_AS))
    write_atomic(cfg.dh_pk_path, cu.public_key_to_pem(d_AS.public_key()))
    for secret in (cfg.master_key_path, cfg.sign_sk_path, cfg.dh_sk_path):
        os.chmod(secret, 0o600)  # best effort (no-op on Windows)
    for d in (cfg.cards_dir, cfg.logs_dir, cfg.doors_dir):
        d.mkdir(parents=True, exist_ok=True)
    Store(cfg.db_path).init_schema()
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="regenerate x and wipe all users, doors, cards, logs")
    args = ap.parse_args()
    cfg = load_config()
    if setup_system(cfg, force=args.force):
        console.ok("ADMIN", f"Phase 0 complete: x (256-bit), ECDSA and ECDH P-256 keys in {cfg.keys_dir}")
        console.info("ADMIN", f"published pk_AS → {cfg.sign_pk_path}, Q_AS → {cfg.dh_pk_path}")
    else:
        console.warn("ADMIN", f"system already set up ({cfg.master_key_path} exists); use --force to reset")


if __name__ == "__main__":
    main()
