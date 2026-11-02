"""One-command end-to-end demo.

  1. Phase 0-2: fresh system, 2 doors (CSE-101, CSE-102), 1 faculty + 1 student (offline registration)
  2. Starts the AS and one door-lock process per door (separate processes, TCP on localhost)
  3. Allowed logins, password change, a denied login (student outside timetable), revocation
  4. Runs every attack script and verifies the signed audit log
  5. Prints a summary

    python run_demo.py [--fast] [--attacks-only] [--no-attacks]

--fast skips the 32-second "replay after ΔT" case. The demo RESETS keys/, cards/, logs/ and the DB.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta

from rich.table import Table

from admin.register_door import register_door
from admin.register_user import register_user
from admin.setup_system import setup_system
from common import console
from common.config import load_config
from db.store import Store

PY = sys.executable
FACULTY, FAC_PW = "F-1001", "Faculty#Rao1"
STUDENT, STU_PW = "23CSB0A07", "Student#Saha1"
ATTACKS = [
    "replay_attack",
    "mitm_tamper",
    "impersonate_user",
    "impersonate_server",
    "stolen_card",
    "desync_attack",
    "insider_attack",
    "door_compromise",
    "traceability",
]

cfg = load_config()
CHILD_ENV = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
if sys.stdout.isatty():
    CHILD_ENV["FORCE_COLOR"] = "1"


def this_monday(hh: int, mm: int) -> datetime:
    today = datetime.now().replace(hour=hh, minute=mm, second=0, microsecond=0)
    return today - timedelta(days=today.weekday())


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex((cfg.host, port)) == 0


def wait_ports(*ports: int, timeout: float = 10) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all(port_open(p) for p in ports):
            return
        time.sleep(0.1)
    raise RuntimeError(f"ports {ports} did not open")


def start(*args: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen([PY, "-m", *args], env=CHILD_ENV)


def stop(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def step(title: str) -> None:
    print(flush=True)
    console.rule(title)


def sd(ID_U: str, PW: str, door: str, *extra: str) -> int:
    """Run the Smart Device CLI as its own process."""
    console.info("DEMO", f"$ python -m entities.user_device --id {ID_U} --door {door} {' '.join(extra)}".rstrip())
    rc = subprocess.call(
        [PY, "-m", "entities.user_device", "--id", ID_U, "--password", PW, "--door", door, *extra], env=CHILD_ENV
    )
    time.sleep(0.3)  # let the AS / DL processes finish printing
    return rc


def start_as(sim: datetime) -> subprocess.Popen[bytes]:
    proc = start("entities.auth_server", "--sim-time", sim.isoformat(timespec="minutes"))
    wait_ports(cfg.as_port)
    return proc


def run_attack(name: str, fast: bool) -> list[tuple[str, str, str]]:
    cmd = [PY, "-m", f"attacks.{name}"] + ([] if fast or name != "replay_attack" else ["--wait"])
    proc = subprocess.Popen(cmd, env=CHILD_ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert proc.stdout is not None
    found = []
    pattern = re.compile(r"ATTACK: (.+?) → RESULT: (BLOCKED|NOT BLOCKED) \((.*)\)")
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace")
        sys.stdout.write(line)
        sys.stdout.flush()
        if m := pattern.search(re.sub(r"\x1b\[[0-9;]*m", "", line)):
            found.append((m.group(1), m.group(2), m.group(3)))
    if proc.wait() != 0 and not found:
        found.append((name, "NOT BLOCKED", f"script exited with {proc.returncode}"))
    return found


def tamper_log_demo() -> list[tuple[str, str, str]]:
    """Copy the log, turn a DENY (or any entry) into ALLOW, and show the verifier catches it."""
    lines = cfg.access_log_path.read_text(encoding="utf-8").splitlines()
    idx = next((i for i, line in enumerate(lines) if '"decision":"DENY"' in line), 0)
    original = json.loads(lines[idx])["decision"]
    forged = "DENY" if original == "ALLOW" else "ALLOW"
    lines[idx] = lines[idx].replace(f'"decision":"{original}"', f'"decision":"{forged}"', 1)
    tampered = cfg.logs_dir / "access_log_TAMPERED_demo.jsonl"
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.warn("DEMO", f"insider edits line {idx + 1} of a copy of the log: decision {original} → {forged}")
    rc = subprocess.call([PY, "-m", "tools.verify_log", "--log", str(tampered)], env=CHILD_ENV)
    console.info("DEMO", f"[dim]left for inspection: {tampered}[/]")
    return [("audit log tampering", "BLOCKED" if rc == 1 else "NOT BLOCKED", f"verify_log flags line {idx + 1}")]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fast", action="store_true", help="skip the replay-after-ΔT wait")
    ap.add_argument("--attacks-only", action="store_true")
    ap.add_argument("--no-attacks", action="store_true")
    args = ap.parse_args()

    busy = [p for p in (cfg.as_port, cfg.dl_base_port, cfg.dl_base_port + 1, cfg.proxy_port) if port_open(p)]
    if busy:
        console.reject("DEMO", f"ports {busy} are already in use — stop running AS/DL/proxy processes first")
        sys.exit(1)

    step("Phase 0-2 — offline setup and registration (secure channel)")
    setup_system(cfg, force=True)
    console.ok("ADMIN", "Phase 0: generated x, ECDSA (sk_AS, pk_AS) and ECDH (d_AS, Q_AS)")
    for room in ("CSE-101", "CSE-102"):
        d = register_door(cfg, room)
        console.ok("ADMIN", f"Phase 1: door {room} installed with K_DL = h(ID_DL ‖ x) on port {d.port}")
    register_user(cfg, FACULTY, FAC_PW, "faculty")
    register_user(cfg, STUDENT, STU_PW, "student", "CSE-4A")
    console.ok("ADMIN", f"Phase 2: registered faculty {FACULTY} and student {STUDENT} (class CSE-4A) → cards/")

    morning, evening = this_monday(9, 30), this_monday(18, 30)
    procs: list[subprocess.Popen[bytes]] = []
    summary: list[tuple[str, str, str]] = []
    try:
        step(f"Starting processes — AS (policy time {morning:%a %H:%M}) and door locks")
        as_proc = start_as(morning)
        procs += [
            as_proc,
            start("entities.door_lock", "--door", "CSE-101"),
            start("entities.door_lock", "--door", "CSE-102"),
        ]
        wait_ports(cfg.dl_base_port, cfg.dl_base_port + 1)

        if not args.attacks_only:
            step(f"Allowed login — faculty {FACULTY} at CSE-101 (Mon 09:30), then LOCK over Enc_SK")
            sd(FACULTY, FAC_PW, "CSE-101", "--lock")

            step(f"Allowed login + password change — student {STUDENT} at CSE-101 during the CSE-4A slot")
            sd(STUDENT, STU_PW, "CSE-101", "--new-password", "Student#Saha2")
            step("Login with the new password")
            sd(STUDENT, "Student#Saha2", "CSE-101")

            step(
                f"Denied login — student at CSE-101 at {evening:%a %H:%M} (outside timetable); "
                "AS restarted with the new policy time"
            )
            stop(as_proc)
            procs.remove(as_proc)
            as_proc = start_as(evening)
            procs.append(as_proc)
            sd(STUDENT, "Student#Saha2", "CSE-101")

            step("Revocation (Phase 5) — admin revokes the student; next login is rejected")
            Store(cfg.db_path).set_revoked(STUDENT, True)
            console.ok("ADMIN", f"{STUDENT} REVOKED")
            sd(STUDENT, "Student#Saha2", "CSE-101")
            Store(cfg.db_path).set_revoked(STUDENT, False)

        if not args.no_attacks:
            for name in ATTACKS:
                print(flush=True)
                summary += run_attack(name, args.fast)

        step("Audit log verification (non-repudiation)")
        subprocess.call([PY, "-m", "tools.verify_log"], env=CHILD_ENV)
        summary += tamper_log_demo()
    finally:
        for p in procs:
            stop(p)

    if summary:
        step("Attack summary")
        table = Table(show_lines=False)
        table.add_column("#")
        table.add_column("Attack")
        table.add_column("Result")
        table.add_column("Reason", overflow="fold")
        for i, (name, res, why) in enumerate(summary, 1):
            table.add_row(str(i), name, f"[green]{res}[/]" if res == "BLOCKED" else f"[red]{res}[/]", why)
        console.console.print(table)
        blocked = sum(r == "BLOCKED" for _, r, _ in summary)
        console.console.print(f"[bold]{blocked}/{len(summary)} attacks blocked[/]")
        sys.exit(0 if blocked == len(summary) else 1)


if __name__ == "__main__":
    main()
