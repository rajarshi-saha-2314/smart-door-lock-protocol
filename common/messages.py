"""Protocol messages M1..M5 plus REJECT and SESSION, with (de)serialization.

Wire format: a JSON object ``{"type": "M1", <field>: <value>, ...}`` where bytes
fields are base64 strings. ``encode()`` gives the canonical length-prefixed bytes
used inside MACs (Tag2) and the audit-log transcript hash.
"""

from __future__ import annotations

import dataclasses
import typing
from dataclasses import dataclass
from typing import Any, ClassVar

from common.encoding import b64d, b64e, cat


class ProtocolError(ValueError):
    """Malformed or unexpected message."""


@dataclass
class Message:
    TYPE: ClassVar[str] = ""

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.TYPE}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Message):
                out[f.name] = value.to_wire()
            elif isinstance(value, bytes):
                out[f.name] = b64e(value)
            else:
                out[f.name] = value
        return out

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> typing.Self:
        if d.get("type") != cls.TYPE:
            raise ProtocolError(f"expected {cls.TYPE}, got {d.get('type')!r}")
        hints = typing.get_type_hints(cls)
        kwargs: dict[str, Any] = {}
        for f in dataclasses.fields(cls):
            tp = hints[f.name]
            optional = type(None) in typing.get_args(tp)
            base = next((a for a in typing.get_args(tp) if a is not type(None)), tp)
            if f.name not in d or d[f.name] is None:
                if optional:
                    kwargs[f.name] = None
                    continue
                raise ProtocolError(f"{cls.TYPE}: missing field {f.name}")
            raw = d[f.name]
            try:
                if isinstance(base, type) and issubclass(base, Message):
                    kwargs[f.name] = base.from_wire(raw)
                elif base is bytes:
                    kwargs[f.name] = b64d(raw)
                elif base is int:
                    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
                        raise ProtocolError("not a non-negative integer")
                    kwargs[f.name] = raw
                elif base is str:
                    if not isinstance(raw, str):
                        raise ProtocolError("not a string")
                    kwargs[f.name] = raw
                else:  # pragma: no cover - schema error
                    raise TypeError(f"unsupported field type {base}")
            except (ValueError, TypeError, AttributeError) as exc:
                raise ProtocolError(f"{cls.TYPE}: bad field {f.name}: {exc}") from exc
        return cls(**kwargs)

    def fields_for_log(self) -> dict[str, object]:
        return {f.name: getattr(self, f.name) for f in dataclasses.fields(self) if getattr(self, f.name) is not None}


@dataclass
class M1(Message):
    """SD → DL: {TID, T1, ID_DL, E, C1}"""

    TYPE: ClassVar[str] = "M1"
    TID: bytes
    T1: int
    ID_DL: str
    E: bytes
    C1: bytes

    def encode(self) -> bytes:
        return cat(self.TID, self.T1, self.ID_DL, self.E, self.C1)


@dataclass
class M2(Message):
    """DL → AS: {M1, N2, T2, Tag2}"""

    TYPE: ClassVar[str] = "M2"
    M1: M1
    N2: bytes
    T2: int
    Tag2: bytes

    def encode(self) -> bytes:
        return cat(self.M1.encode(), self.N2, self.T2, self.Tag2)

    def fields_for_log(self) -> dict[str, object]:
        return {"M1.TID": self.M1.TID, "N2": self.N2, "T2": self.T2, "Tag2": self.Tag2}


@dataclass
class M3(Message):
    """AS → DL: {T3, C_DL, C_U}"""

    TYPE: ClassVar[str] = "M3"
    T3: int
    C_DL: bytes
    C_U: bytes


@dataclass
class M4(Message):
    """DL → SD: {C_U, T3, T4, Auth_DL}. On DENY only {C_U, T3}."""

    TYPE: ClassVar[str] = "M4"
    C_U: bytes
    T3: int
    T4: int | None = None
    Auth_DL: bytes | None = None


@dataclass
class M5(Message):
    """SD → DL: {T5, Auth_U}"""

    TYPE: ClassVar[str] = "M5"
    T5: int
    Auth_U: bytes


@dataclass
class Reject(Message):
    """Unauthenticated error notice (informational only — never trusted)."""

    TYPE: ClassVar[str] = "REJECT"
    reason: str


@dataclass
class Session(Message):
    """Post-handshake SD↔DL traffic: Enc_SK(command; aad = "SESSION" ‖ ID_DL ‖ TID ‖ seq ‖ sender)."""

    TYPE: ClassVar[str] = "SESSION"
    seq: int
    ct: bytes


MESSAGE_TYPES: dict[str, type[Message]] = {cls.TYPE: cls for cls in (M1, M2, M3, M4, M5, Reject, Session)}


def parse(d: dict[str, Any]) -> Message:
    if not isinstance(d, dict) or not isinstance(d.get("type"), str):
        raise ProtocolError("message must be a JSON object with a 'type'")
    cls = MESSAGE_TYPES.get(d["type"])
    if cls is None:
        raise ProtocolError(f"unknown message type {d['type']!r}")
    return cls.from_wire(d)
