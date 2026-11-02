"""Cross-platform task runner (same targets as the Makefile, for systems without `make`).

python tasks.py setup | run-as | run-dl [DOOR] | demo | attacks | test | lint | proverif | bench | clean
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def run(*cmd: str) -> None:
    print("$", " ".join(cmd), flush=True)
    rc = subprocess.call(list(cmd), cwd=ROOT)
    if rc != 0:
        sys.exit(rc)


def clean() -> None:
    (ROOT / "doors.json").unlink(missing_ok=True)
    for d in ("keys", "cards", "logs"):
        shutil.rmtree(ROOT / d, ignore_errors=True)
    for f in (ROOT / "db").glob("*.db*"):
        f.unlink()
    print("removed keys/ cards/ logs/ db/*.db")


def main(argv: list[str]) -> None:
    if not argv:
        print(__doc__)
        return
    target, rest = argv[0], argv[1:]
    match target:
        case "setup":
            run(PY, "-m", "pip", "install", "-r", "requirements.txt")
            run(PY, "-m", "admin.setup_system")
        case "run-as":
            run(PY, "-m", "entities.auth_server", *rest)
        case "run-dl":
            door = rest[0] if rest else "CSE-101"
            run(PY, "-m", "entities.door_lock", "--door", door, *rest[1:])
        case "demo":
            run(PY, "run_demo.py", *rest)
        case "attacks":
            run(PY, "run_demo.py", "--attacks-only", *rest)
        case "test":
            run(PY, "-m", "pytest", *rest)
        case "lint":
            run(PY, "-m", "ruff", "check", ".")
            run(PY, "-m", "ruff", "format", "--check", ".")
        case "proverif":
            run("bash", "formal/run_proverif.sh")
        case "bench":
            run(PY, "-m", "benchmarks.primitive_timing")
            run(PY, "-m", "benchmarks.cost_analysis")
        case "clean":
            clean()
        case _:
            print(f"unknown target {target!r}\n{__doc__}")
            sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
