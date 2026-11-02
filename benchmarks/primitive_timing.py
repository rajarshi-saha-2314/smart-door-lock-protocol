"""Average running time of each cryptographic primitive on this machine (1000 runs each).

python -m benchmarks.primitive_timing [--runs 1000]   → benchmarks/primitive_timing.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import statistics
import time
from collections.abc import Callable
from pathlib import Path

import cryptography

from common import crypto_utils as cu
from common.console import ensure_utf8_stdio

CSV_PATH = Path(__file__).with_name("primitive_timing.csv")


# symbol used in the cost formulas → (description, function)
def primitives() -> dict[str, tuple[str, Callable[[], object]]]:
    k32, m64, aad = cu.rand(32), cu.rand(64), cu.rand(48)
    ct = cu.Enc(k32, m64, aad)
    sk = cu.ecdsa_keygen()
    sig = cu.ecdsa_sign(sk, m64)
    d_AS, Q_AS = cu.ecdh_keygen()
    a, b = cu.rand(32), cu.rand(32)
    return {
        "T_h": ("SHA-256, 64-byte input", lambda: cu.h(m64)),
        "T_hmac": ("HMAC-SHA256, 64-byte message", lambda: cu.HMAC(k32, m64)),
        "T_kdf": ("HKDF-SHA256, 32-byte output", lambda: cu.KDF(k32, m64)),
        "T_enc": ("AES-256-GCM encrypt, 64-byte plaintext", lambda: cu.Enc(k32, m64, aad)),
        "T_dec": ("AES-256-GCM decrypt + verify, 64-byte plaintext", lambda: cu.Dec(k32, ct, aad)),
        "T_ecm": ("P-256 ECDH (key generation or shared secret)", lambda: cu.ecdh(d_AS, Q_AS)),
        "T_sig": ("ECDSA P-256 sign", lambda: cu.ecdsa_sign(sk, m64)),
        "T_ver": ("ECDSA P-256 verify", lambda: cu.ecdsa_verify(sk.public_key(), sig, m64)),
        "T_xor": ("XOR of two 32-byte strings", lambda: cu.xor(a, b)),
        "T_rand": ("128-bit random nonce (secrets)", lambda: cu.rand(16)),
    }


def measure(fn: Callable[[], object], runs: int) -> tuple[float, float]:
    for _ in range(min(50, runs)):  # warm-up
        fn()
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return statistics.fmean(samples), statistics.stdev(samples)


def main() -> None:
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=1000)
    args = ap.parse_args()
    rows = []
    for symbol, (desc, fn) in primitives().items():
        mean, sd = measure(fn, args.runs)
        rows.append({"symbol": symbol, "primitive": desc, "mean_ms": f"{mean:.6f}", "stdev_ms": f"{sd:.6f}"})
        print(f"{symbol:7s} {mean:10.4f} ms  ± {sd:.4f}   {desc}")
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        f.write(
            f"# runs={args.runs}; {platform.processor() or platform.machine()}; {os.cpu_count()} CPUs; "
            f"{platform.system()} {platform.release()}; Python {platform.python_version()}; "
            f"cryptography {cryptography.__version__}\n"
        )
        writer = csv.DictWriter(f, fieldnames=["symbol", "primitive", "mean_ms", "stdev_ms"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"→ {CSV_PATH}")


if __name__ == "__main__":
    main()
