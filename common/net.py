"""asyncio framing: each message is a 4-byte big-endian length followed by UTF-8 JSON."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from common.messages import Message, ProtocolError, parse

MAX_FRAME = 64 * 1024


class ConnectionClosed(Exception):
    """Peer closed the connection before a full frame arrived."""


async def send_frame(writer: asyncio.StreamWriter, obj: dict[str, Any]) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ProtocolError("frame too large")
    writer.write(len(body).to_bytes(4, "big") + body)
    await writer.drain()


async def recv_frame(reader: asyncio.StreamReader, timeout: float) -> dict[str, Any]:
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout)
        n = int.from_bytes(header, "big")
        if n > MAX_FRAME:
            raise ProtocolError(f"frame too large ({n} bytes)")
        body = await asyncio.wait_for(reader.readexactly(n), timeout)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionClosed("connection closed by peer") from exc
    except ConnectionError as exc:
        raise ConnectionClosed(str(exc)) from exc
    try:
        obj = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ProtocolError("frame is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("frame is not a JSON object")
    return obj


async def send(writer: asyncio.StreamWriter, msg: Message) -> None:
    await send_frame(writer, msg.to_wire())


async def recv(reader: asyncio.StreamReader, timeout: float) -> Message:
    return parse(await recv_frame(reader, timeout))


async def close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
