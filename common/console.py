"""Readable, colour-coded logging of protocol events (rich)."""

from __future__ import annotations

import sys
from collections.abc import Mapping

from rich.console import Console
from rich.markup import escape

from common.encoding import short_hex


def ensure_utf8_stdio() -> None:
    """Windows consoles/pipes default to cp1252, which cannot encode ✔ → Δ ‖; switch stdout/stderr to UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure") and (stream.encoding or "").lower().replace("-", "") != "utf8":
            stream.reconfigure(encoding="utf-8", errors="replace")


ensure_utf8_stdio()

console = Console(highlight=False, soft_wrap=True)

ENTITY_STYLE = {
    "SD": "bold cyan",
    "DL": "bold magenta",
    "AS": "bold yellow",
    "ATTACKER": "bold red",
    "ADMIN": "bold blue",
    "DEMO": "bold white",
}


def _tag(entity: str) -> str:
    base = entity.split(":")[0]
    return f"[{ENTITY_STYLE.get(base, 'bold')}]\\[{escape(entity)}][/]"


def fmt_value(value: object) -> str:
    if isinstance(value, bytes):
        return short_hex(value)
    return str(value)


def fmt_fields(fields: Mapping[str, object]) -> str:
    return ", ".join(f"{k}={escape(fmt_value(v))}" for k, v in fields.items())


def info(entity: str, text: str) -> None:
    console.print(f"{_tag(entity)} {text}")


def sent(entity: str, name: str, peer: str, fields: Mapping[str, object]) -> None:
    console.print(f"{_tag(entity)} [green]→ {name}[/] to {peer}: {fmt_fields(fields)}")


def received(entity: str, name: str, peer: str, fields: Mapping[str, object]) -> None:
    console.print(f"{_tag(entity)} [blue]← {name}[/] from {peer}: {fmt_fields(fields)}")


def ok(entity: str, text: str) -> None:
    console.print(f"{_tag(entity)} [bold green]✔ {escape(text)}[/]")


def reject(entity: str, reason: str) -> None:
    console.print(f"{_tag(entity)} [bold red]REJECT: {escape(reason)}[/]")


def warn(entity: str, text: str) -> None:
    console.print(f"{_tag(entity)} [yellow]{escape(text)}[/]")


def rule(title: str) -> None:
    console.rule(f"[bold]{escape(title)}[/]")
