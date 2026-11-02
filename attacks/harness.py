"""Shared helpers for the attack scripts.

Every attack assumes the AS and the door locks are already running (``run_demo.py``
starts them). The victim's Smart Device is launched as a real separate process
(``python -m entities.user_device``) so the attacker only ever touches the network.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from admin.register_door import door_address
from admin.register_user import register_user
from attacks.attacker_proxy import AttackerProxy
from common import console
from common.config import Config, load_config
from db.store import Store

cfg: Config = load_config()


@dataclass
class Verdicts:
    """Collects ATTACK lines; exit code 0 only if every attack was blocked."""

    results: list[tuple[str, bool, str]] = field(default_factory=list)

    def add(self, name: str, blocked: bool, reason: str) -> None:
        self.results.append((name, blocked, reason))
        style = "bold green" if blocked else "bold white on red"
        word = "BLOCKED" if blocked else "NOT BLOCKED"
        console.console.print(f"[{style}]ATTACK: {name} → RESULT: {word} ({reason})[/]")

    def exit(self) -> None:
        sys.exit(0 if all(b for _, b, _ in self.results) else 1)


def banner(title: str, story: str) -> None:
    console.rule(f"ATTACK — {title}")
    console.info("ATTACKER", story)


def setup_step(text: str) -> None:
    console.info("ADMIN", f"[dim]\\[scenario setup] {text}[/]")


def fresh_victim(ID_U: str, password: str, role: str = "faculty", class_id: str | None = None) -> None:
    """(Offline) register — or re-issue — a dedicated victim so each attack starts from a clean state."""
    exists = Store(cfg.db_path).get_user(ID_U) is not None
    register_user(cfg, ID_U, password, role, class_id, reissue=exists)
    setup_step(f"{'re-issued' if exists else 'registered'} victim {ID_U} ({role}) at the office")


@dataclass
class SDResult:
    status: str
    reason: str
    TID_used: str | None
    TID_new: str | None
    raw: dict


async def run_sd(
    ID_U: str, password: str, door: str = "CSE-101", via_proxy: bool = True, extra: tuple[str, ...] = ()
) -> SDResult:
    """Run the victim's Smart Device as its own process and parse its RESULT line."""
    cmd = [sys.executable, "-m", "entities.user_device", "--id", ID_U, "--door", door, "--password", password, "--json"]
    if via_proxy:
        cmd.append("--via-proxy")
    cmd += list(extra)
    console.info(
        "SD", f"[dim]victim runs: user_device --id {ID_U} --door {door}{' --via-proxy' if via_proxy else ''}[/]"
    )
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    assert proc.stdout is not None
    result: dict = {"status": "ERROR", "reason": "no RESULT line", "TID_used": None, "TID_new": None}
    async for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").rstrip()
        if line.startswith("RESULT "):
            result = json.loads(line[len("RESULT ") :])
        else:
            print(f"    │ {line}", flush=True)
    await proc.wait()
    return SDResult(result["status"], result["reason"], result.get("TID_used"), result.get("TID_new"), result)


@asynccontextmanager
async def proxy(mode: str = "pass", **kw: object) -> AsyncIterator[AttackerProxy]:
    p = AttackerProxy(cfg, mode, **kw)  # type: ignore[arg-type]
    srv = await p.start()
    console.info("ATTACKER", f"proxy up on :{cfg.proxy_port} (mode={mode}{', ' + str(kw) if kw else ''})")
    try:
        yield p
    finally:
        srv.close()
        await srv.wait_closed()
        await asyncio.sleep(0.1)


def door(ID_DL: str) -> tuple[str, int]:
    return door_address(cfg, ID_DL)


def run(coro_fn) -> None:  # type: ignore[no-untyped-def]
    verdicts = Verdicts()
    asyncio.run(coro_fn(verdicts))
    verdicts.exit()
