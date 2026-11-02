"""Dolev–Yao attacker sitting between the Smart Device and the Door Lock.

The SD connects to the proxy (:9200) instead of the door; the proxy reads the
ID_DL in M1, connects to that door and relays frames in both directions,
applying the selected mode:

    pass     relay unchanged
    record   relay unchanged and save every frame (to memory and optionally --out FILE)
    tamper   flip a bit / bump a value in field --field of message --msg
    drop     swallow message --msg and cut both connections
    forge    never contact the door; answer M1 with a forged M4 (attacker posing as DL + AS)
    replay   (CLI only) re-send the SD→DL frames from a --capture file straight to the door

    python -m attacks.attacker_proxy --mode drop --msg M4
    python -m attacks.attacker_proxy --mode tamper --msg M1 --field C1
    python -m attacks.attacker_proxy --mode record --out logs/capture.jsonl
    python -m attacks.attacker_proxy --mode replay --capture logs/capture.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from admin.register_door import door_address
from common import console, net
from common.config import Config, load_config
from common.encoding import b64d, b64e, short_hex

NAME = "ATTACKER"
Frame = dict[str, Any]
MODES = ("pass", "record", "tamper", "drop", "forge")


def flip(value: Any) -> Any:
    """Minimal modification of a field: flip one bit of bytes, +1 for ints, append to strings."""
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        try:
            raw = bytearray(b64d(value))
        except ValueError:
            return value + "X"
        if not raw:
            return b64e(b"\x01")
        raw[len(raw) // 2] ^= 0x01
        return b64e(bytes(raw))
    raise TypeError(f"cannot tamper with {type(value).__name__}")


def describe(frame: Frame) -> str:
    parts = []
    for k, v in frame.items():
        if k == "type" or isinstance(v, dict):
            continue
        if isinstance(v, str):
            try:
                parts.append(f"{k}={short_hex(b64d(v), 6)}")
                continue
            except ValueError:
                pass
        parts.append(f"{k}={v}")
    return ", ".join(parts)


class AttackerProxy:
    def __init__(
        self,
        cfg: Config,
        mode: str = "pass",
        msg: str | None = None,
        field: str | None = None,
        out: Path | None = None,
        forge: Callable[[Frame], Frame] | None = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.cfg = cfg
        self.mode = mode
        self.msg = msg
        self.field = field
        self.out = out
        self.forge = forge
        self.captured: list[tuple[str, Frame]] = []
        self.actions: list[str] = []

    # ------------------------------------------------------------------ interception
    def _capture(self, direction: str, frame: Frame) -> None:
        self.captured.append((direction, copy.deepcopy(frame)))
        if self.out:
            self.out.parent.mkdir(parents=True, exist_ok=True)
            with self.out.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"dir": direction, "frame": frame}) + "\n")
        console.info(NAME, f"[dim]intercepted {frame.get('type')} {direction}: {describe(frame)}[/]")

    def _apply(self, direction: str, frame: Frame) -> Frame | None:
        """Return the frame to forward, or None to drop it and cut the connection."""
        self._capture(direction, frame)
        if frame.get("type") != self.msg:
            return frame
        if self.mode == "drop":
            self.actions.append(f"dropped {self.msg}")
            console.warn(NAME, f"✂ DROPPED {self.msg} ({direction}) and cut the connection")
            return None
        if self.mode == "tamper":
            assert self.field is not None
            forged = copy.deepcopy(frame)
            forged[self.field] = flip(forged[self.field])
            self.actions.append(f"tampered {self.msg}.{self.field}")
            console.warn(
                NAME, f"✎ TAMPERED {self.msg}.{self.field}: {frame[self.field]!s:.24} → {forged[self.field]!s:.24}"
            )
            return forged
        return frame

    async def _pump(self, direction: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            frame = await net.recv_frame(reader, timeout=60)
            out = self._apply(direction, frame)
            if out is None:
                return
            await net.send_frame(writer, out)

    async def _handle(self, sd_reader: asyncio.StreamReader, sd_writer: asyncio.StreamWriter) -> None:
        dl_writer: asyncio.StreamWriter | None = None
        try:
            first = await net.recv_frame(sd_reader, self.cfg.io_timeout_s)
            if self.mode == "forge" and self.forge and first.get("type") == "M1":
                self._capture("SD->DL", first)
                fake = self.forge(first)
                self.actions.append("forged M4")
                console.warn(NAME, f"⚑ answering M1 with FORGED {fake['type']}: {describe(fake)}")
                await net.send_frame(sd_writer, fake)
                await asyncio.sleep(0.5)
                return
            out = self._apply("SD->DL", first)
            if out is None:
                return
            host, port = door_address(self.cfg, str(first.get("ID_DL")))
            dl_reader, dl_writer = await asyncio.open_connection(host, port)
            await net.send_frame(dl_writer, out)
            tasks = [
                asyncio.create_task(self._pump("SD->DL", sd_reader, dl_writer)),
                asyncio.create_task(self._pump("DL->SD", dl_reader, sd_writer)),
            ]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except (net.ConnectionClosed, TimeoutError, OSError, ValueError) as exc:
            console.info(NAME, f"[dim]connection ended ({type(exc).__name__})[/]")
        finally:
            await net.close(sd_writer)
            if dl_writer is not None:
                await net.close(dl_writer)

    async def start(self, port: int | None = None) -> asyncio.Server:
        return await asyncio.start_server(self._handle, self.cfg.host, self.cfg.proxy_port if port is None else port)

    def frames(self, msg_type: str, direction: str | None = None) -> list[Frame]:
        return [f for d, f in self.captured if f.get("type") == msg_type and (direction is None or d == direction)]


# ---------------------------------------------------------------------- attacker as a client


async def exchange(host: str, port: int, frames: list[Frame], timeout: float = 3.0) -> list[Frame]:
    """Send frames one by one to (host, port), collecting one reply after each (stop when closed)."""
    replies: list[Frame] = []
    reader, writer = await asyncio.open_connection(host, port)
    try:
        for frame in frames:
            await net.send_frame(writer, frame)
            console.info(NAME, f"→ injected {frame.get('type')} to :{port}: {describe(frame)}")
            try:
                reply = await net.recv_frame(reader, timeout)
            except (net.ConnectionClosed, TimeoutError):
                break
            replies.append(reply)
            console.info(NAME, f"← got {reply.get('type')}: {reply.get('reason') or describe(reply)}")
    finally:
        await net.close(writer)
    return replies


async def replay_capture(cfg: Config, capture: Path) -> list[Frame]:
    rows = [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines() if line.strip()]
    sd_frames = [r["frame"] for r in rows if r["dir"] == "SD->DL"]
    if not sd_frames or sd_frames[0].get("type") != "M1":
        raise ValueError("capture has no SD→DL M1")
    host, port = door_address(cfg, sd_frames[0]["ID_DL"])
    return await exchange(host, port, sd_frames)


async def _amain(args: argparse.Namespace) -> None:
    cfg = load_config()
    if args.mode == "replay":
        await replay_capture(cfg, Path(args.capture))
        return
    proxy = AttackerProxy(cfg, args.mode, args.msg, args.field, Path(args.out) if args.out else None)
    srv = await proxy.start(port=args.port)
    console.ok(NAME, f"proxy listening on {cfg.host}:{srv.sockets[0].getsockname()[1]} (mode={args.mode})")
    async with srv:
        await srv.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=(*MODES[:-1], "replay"), default="pass")
    ap.add_argument("--msg", help="message type to act on (M1..M5)")
    ap.add_argument("--field", help="field to tamper with")
    ap.add_argument("--out", help="record frames to this JSONL file")
    ap.add_argument("--capture", help="capture file for --mode replay")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()
    if args.mode in ("tamper", "drop") and not args.msg:
        ap.error("--msg is required for tamper/drop")
    if args.mode == "tamper" and not args.field:
        ap.error("--field is required for tamper")
    if args.mode == "replay" and not args.capture:
        ap.error("--capture is required for replay")
    try:
        asyncio.run(_amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
