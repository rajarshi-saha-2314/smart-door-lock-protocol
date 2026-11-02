"""Verify the AS audit log: every ECDSA signature, the hash chain and the sequence numbers.

    python -m tools.verify_log [--log logs/access_log.jsonl] [--pk keys/as_sign_pk.pem]

Exit code 0 if the whole log is intact, 1 if a tampered line is found (its line number is reported).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import console
from common import crypto_utils as cu
from common.audit_log import verify_log
from common.config import load_config


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", type=Path, help="default: logs/access_log.jsonl")
    ap.add_argument("--pk", type=Path, help="AS public key pk_AS (default: keys/as_sign_pk.pem)")
    args = ap.parse_args()
    cfg = load_config()
    log_path = args.log or cfg.access_log_path
    pk_AS = cu.load_public_key_pem((args.pk or cfg.sign_pk_path).read_bytes())

    result = verify_log(log_path, pk_AS)
    if result.ok:
        console.ok("AUDIT", f"{log_path}: {result.entries} entries, all signatures valid, hash chain intact")
        sys.exit(0)
    console.reject(
        "AUDIT",
        f"{log_path}: TAMPERED at line {result.first_bad_line} — {result.error} "
        f"({result.entries} entries before it verified)",
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
