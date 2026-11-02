"""Smart Device (SD) — the user's phone/smartcard client.

    python -m entities.user_device --id stu01 --door CSE-101 [--password ...] [--via-proxy]
                                   [--lock] [--new-password NEWPW] [--json]

Exit code: 0 = door unlocked, 2 = authenticated but DENY by policy, 1 = any failure.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from admin.register_door import door_address
from common import console, net
from common import crypto_utils as cu
from common.clock import Clock, SystemClock, is_fresh
from common.config import Config, load_config
from common.encoding import cat, split, to_int, to_str
from common.keystore import load_card, save_card
from common.messages import M1, M4, M5, ProtocolError, Reject, Session
from common.protocol import (
    ALLOW,
    aad_C1,
    aad_C_U,
    aad_session,
    compute_Auth_DL,
    compute_Auth_U,
    compute_B,
    compute_RPW,
    derive_k1,
    derive_k_u,
    derive_SK,
    fuzzy_verifier,
    recover_A,
)

NAME = "SD"


@dataclass
class LoginResult:
    status: str  # UNLOCKED | DENIED | REJECTED | ERROR
    reason: str
    TID_used: bytes | None = None
    TID_new: bytes | None = None
    SK: bytes | None = None
    session_replies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "UNLOCKED"

    def to_json(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "TID_used": self.TID_used.hex() if self.TID_used else None,
            "TID_new": self.TID_new.hex() if self.TID_new else None,
            "session_replies": self.session_replies,
        }


class SmartDevice:
    def __init__(self, cfg: Config, card_path: Path, clock: Clock | None = None) -> None:
        self.cfg = cfg
        self.card_path = card_path
        self.card = load_card(card_path)
        self.clock: Clock = clock or SystemClock()
        self.ID_U: str | None = None
        self._A: bytes | None = None
        self.online_verified = False  # set once the AS has proven itself in this session

    # ------------------------------------------------------------------ Step 1: local login
    def local_login(self, ID_U: str, PW_U: str) -> bool:
        RPW = compute_RPW(PW_U, self.card.r)
        V_star = fuzzy_verifier(ID_U, RPW, self.card.n0)
        if not cu.ct_eq(V_star.to_bytes(4, "big"), self.card.V.to_bytes(4, "big")):
            console.reject(NAME, "local login failed: fuzzy verifier V mismatch (wrong ID or password)")
            return False
        self.ID_U = ID_U
        self._A = recover_A(self.card.B, ID_U, RPW)
        console.ok(NAME, "local login: V matches; A recovered from B")
        return True

    # ------------------------------------------------------------------ Steps 2 – 7
    async def login(self, ID_DL: str, host: str, port: int, commands: tuple[str, ...] = ()) -> LoginResult:
        if self._A is None or self.ID_U is None:
            raise RuntimeError("local_login() must succeed first")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), self.cfg.io_timeout_s)
        except (OSError, TimeoutError) as exc:
            return self._fail("ERROR", f"cannot reach door at {host}:{port}: {exc}")
        try:
            return await self._run(reader, writer, ID_DL, commands)
        except (ProtocolError, net.ConnectionClosed, TimeoutError, OSError) as exc:
            reason = f"no valid reply ({type(exc).__name__}: {exc}) — keeping TID {self.card.TID.hex()[:8]}…"
            return self._fail("ERROR", reason)
        finally:
            await net.close(writer)

    def _fail(self, status: str, reason: str, **kw: object) -> LoginResult:
        console.reject(NAME, reason)
        return LoginResult(status, reason, **kw)  # type: ignore[arg-type]

    async def _run(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ID_DL: str, commands: tuple[str, ...]
    ) -> LoginResult:
        assert self._A is not None
        A, ΔT = self._A, self.cfg.delta_t_ms
        m1, N1 = self.build_M1(ID_DL)
        TID = m1.TID
        await net.send(writer, m1)
        console.sent(NAME, "M1", f"DL {ID_DL}", m1.fields_for_log())

        reply = await net.recv(reader, self.cfg.io_timeout_s)
        if isinstance(reply, Reject):
            return self._fail("REJECTED", reply.reason, TID_used=TID)
        if not isinstance(reply, M4):
            return self._fail("ERROR", f"expected M4, got {reply.TYPE}", TID_used=TID)
        m4 = reply
        console.received(NAME, "M4", f"DL {ID_DL}", m4.fields_for_log())

        # Step 6.1: authenticate the AS by decrypting C_U
        k_u = derive_k_u(A, N1, m4.T3)
        try:
            f = split(cu.Dec(k_u, m4.C_U, aad_C_U(TID, ID_DL)), expected=5)
            decision, N2, N3, TID_new, T3 = to_str(f[0]), f[1], f[2], f[3], to_int(f[4])
        except (cu.IntegrityError, ValueError):
            return self._fail("REJECTED", "C_U failed AES-GCM verification → AS NOT authenticated", TID_used=TID)
        if T3 != m4.T3:
            return self._fail("REJECTED", "T3 inside C_U does not match M4", TID_used=TID)
        fresh, delta = is_fresh(self.clock, T3, ΔT)
        if not fresh:
            return self._fail("REJECTED", f"stale timestamp T3 (Δ={delta / 1000:.1f}s)", TID_used=TID)
        self.online_verified = True
        console.ok(NAME, f"C_U decrypted → AS authenticated; decision={decision}")

        if decision != ALLOW:
            self._update_TID(TID_new)
            return self._fail("DENIED", decision, TID_used=TID, TID_new=TID_new)

        # Step 6.2: compute SK and authenticate the door via Auth_DL
        SK = derive_SK(N1, N2, N3, ID_DL, TID, T3)
        if m4.T4 is None or m4.Auth_DL is None:
            return self._fail("REJECTED", "ALLOW without Auth_DL → door not authenticated", TID_used=TID)
        fresh, delta = is_fresh(self.clock, m4.T4, ΔT)
        if not fresh:
            return self._fail("REJECTED", f"stale timestamp T4 (Δ={delta / 1000:.1f}s)", TID_used=TID)
        if not cu.ct_eq(m4.Auth_DL, compute_Auth_DL(SK, ID_DL, TID, m4.T4)):
            return self._fail("REJECTED", "Auth_DL invalid → door lock NOT authenticated", TID_used=TID)
        console.ok(NAME, f"Auth_DL valid → door {ID_DL} authenticated; SK established")

        # Step 6.3: adopt the new pseudonym
        self._update_TID(TID_new)

        # Step 6.4: key confirmation M5
        T5 = self.clock.now_ms()
        m5 = M5(T5=T5, Auth_U=compute_Auth_U(SK, TID, T5))
        await net.send(writer, m5)
        console.sent(NAME, "M5", f"DL {ID_DL}", m5.fields_for_log())

        # Step 7: door confirms over the Enc_SK channel
        result = LoginResult("UNLOCKED", "", TID_used=TID, TID_new=TID_new, SK=SK)
        seq_in = 0
        msg = await net.recv(reader, self.cfg.io_timeout_s)
        if isinstance(msg, Reject):
            return self._fail("REJECTED", msg.reason, TID_used=TID, TID_new=TID_new)
        result.session_replies.append(self._open_session(msg, SK, ID_DL, TID, seq_in))
        seq_in += 1
        for seq_out, cmd in enumerate(commands):
            ct = cu.Enc(SK, cmd.encode(), aad_session(ID_DL, TID, seq_out, "SD"))
            await net.send(writer, Session(seq=seq_out, ct=ct))
            console.sent(NAME, "SESSION", f"DL {ID_DL}", {"seq": seq_out, "cmd": cmd, "ct": ct})
            msg = await net.recv(reader, self.cfg.io_timeout_s)
            result.session_replies.append(self._open_session(msg, SK, ID_DL, TID, seq_in))
            seq_in += 1
        result.reason = result.session_replies[0]
        console.ok(NAME, f"door says (Enc_SK): {result.reason}")
        return result

    def build_M1(self, ID_DL: str) -> tuple[M1, bytes]:
        """Step 2: M1 = {TID, T1, ID_DL, E, C1} with ephemeral ECDH (D1). Returns (M1, N1)."""
        if self._A is None or self.ID_U is None:
            raise RuntimeError("local_login() must succeed first")
        TID, N1, T1 = self.card.TID, cu.rand(16), self.clock.now_ms()
        e, E = cu.ecdh_keygen()
        Z = cu.ecdh(e, self.card.Q_AS)
        k1 = derive_k1(self._A, Z, TID, T1, E)
        C1 = cu.Enc(k1, cat(N1, self.ID_U), aad_C1(TID, T1, ID_DL, E))
        return M1(TID=TID, T1=T1, ID_DL=ID_DL, E=E, C1=C1), N1

    def _open_session(self, msg: object, SK: bytes, ID_DL: str, TID: bytes, seq: int) -> str:
        if not isinstance(msg, Session) or msg.seq != seq:
            raise ProtocolError("expected an Enc_SK session message")
        try:
            return cu.Dec(SK, msg.ct, aad_session(ID_DL, TID, seq, "DL")).decode()
        except cu.IntegrityError as exc:
            raise ProtocolError("session message failed Enc_SK verification") from exc

    def _update_TID(self, TID_new: bytes) -> None:
        self.card.TID = TID_new
        save_card(self.card_path, self.card)
        console.info(NAME, f"card TID ← TID_new {TID_new.hex()[:8]}…")

    # ------------------------------------------------------------------ Phase 4: password change
    def change_password(self, new_PW: str) -> None:
        """Only after the AS has authenticated us in this session (avoids fuzzy-verifier false accepts)."""
        if not self.online_verified or self._A is None or self.ID_U is None:
            raise PermissionError("password change requires a successful online login in this session")
        r_new = cu.rand(16)
        RPW_new = compute_RPW(new_PW, r_new)
        self.card.B = compute_B(self._A, self.ID_U, RPW_new)
        self.card.V = fuzzy_verifier(self.ID_U, RPW_new, self.card.n0)
        self.card.r = r_new
        save_card(self.card_path, self.card)
        console.ok(NAME, "password changed: new r, B, V written to card (A unchanged, AS not involved)")


async def _amain(args: argparse.Namespace) -> int:
    cfg = load_config()
    card_path = Path(args.card) if args.card else cfg.card_path(args.ID_U)
    if not card_path.exists():
        console.reject(NAME, f"no card at {card_path}")
        return 1
    sd = SmartDevice(cfg, card_path)
    PW_U = args.password if args.password is not None else getpass.getpass(f"Password for {args.ID_U}: ")
    if not sd.local_login(args.ID_U, PW_U):
        return 1

    if args.via_proxy:
        host, port = cfg.host, cfg.proxy_port
    else:
        host, port = door_address(cfg, args.door)
    host, port = args.host or host, args.port or port
    commands = ("LOCK",) if args.lock else ()
    result = await sd.login(args.door, host, port, commands)

    if args.new_password:
        try:
            sd.change_password(args.new_password)
        except PermissionError as exc:
            console.reject(NAME, str(exc))
    if args.json:
        print("RESULT " + json.dumps(result.to_json()), flush=True)
    return {"UNLOCKED": 0, "DENIED": 2}.get(result.status, 1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True, dest="ID_U")
    ap.add_argument("--door", required=True, help="ID_DL of the door to open")
    ap.add_argument("--password", help="omit to be prompted")
    ap.add_argument("--card", help="card file (default cards/<ID>.json)")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--via-proxy", action="store_true", help="connect through the attacker proxy (:9200)")
    ap.add_argument("--lock", action="store_true", help="after unlocking, send LOCK over the Enc_SK channel")
    ap.add_argument("--new-password", help="change password after a successful online login")
    ap.add_argument("--json", action="store_true", help="print a machine-readable RESULT line")
    sys.exit(asyncio.run(_amain(ap.parse_args())))


if __name__ == "__main__":
    main()
