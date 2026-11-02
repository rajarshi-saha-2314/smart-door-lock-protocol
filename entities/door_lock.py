"""Door Lock (DL) — relays to the AS, verifies the AS and the user, actuates the (simulated) lock.

python -m entities.door_lock --door CSE-101 [--port 9100] [--as-host 127.0.0.1 --as-port 9000]
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass

from common import console, net
from common import crypto_utils as cu
from common.clock import Clock, SystemClock, is_fresh
from common.config import Config, load_config
from common.encoding import split, to_int, to_str
from common.keystore import DoorConfig, load_door_config
from common.messages import M1, M2, M3, M4, M5, Message, ProtocolError, Reject, Session
from common.protocol import (
    ALLOW,
    aad_C_DL,
    aad_session,
    compute_Auth_DL,
    compute_Auth_U,
    compute_Tag2,
)


@dataclass
class DoorEvent:
    kind: str  # UNLOCKED | LOCKED | DENIED | REJECTED
    detail: str


@dataclass
class _SessionState:
    TID: bytes
    SK: bytes
    role: str
    seq_in: int = 0
    seq_out: int = 0


class DoorLock:
    def __init__(
        self,
        cfg: Config,
        door: DoorConfig,
        clock: Clock | None = None,
        as_host: str | None = None,
        as_port: int | None = None,
    ) -> None:
        self.cfg = cfg
        self.door = door
        self.ID_DL = door.ID_DL
        self.K_DL = door.K_DL
        self.clock: Clock = clock or SystemClock()
        self.as_host = as_host or door.as_host
        self.as_port = door.as_port if as_port is None else as_port
        self.name = f"DL:{self.ID_DL}"
        self.unlocked = False
        self.events: list[DoorEvent] = []
        self._relock_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ actuator (simulated)
    def _event(self, kind: str, detail: str) -> None:
        self.events.append(DoorEvent(kind, detail))

    def _unlock(self, role: str) -> None:
        self.unlocked = True
        self._event("UNLOCKED", role)
        console.console.print(
            f"[bold green on black] 🔓 UNLOCKED {self.ID_DL} for {self.cfg.unlock_seconds} s [/] (role={role})"
        )
        if self._relock_task:
            self._relock_task.cancel()
        self._relock_task = asyncio.create_task(self._relock_later())

    async def _relock_later(self) -> None:
        await asyncio.sleep(self.cfg.unlock_seconds)
        self._lock("auto-relock")

    def _lock(self, why: str) -> None:
        if self.unlocked:
            self.unlocked = False
            self._event("LOCKED", why)
            console.info(self.name, f"🔒 LOCKED ({why})")

    # ------------------------------------------------------------------ helpers
    async def _reject_sd(self, writer: asyncio.StreamWriter, reason: str, kind: str = "REJECTED") -> None:
        console.reject(self.name, reason)
        self._event(kind, reason)
        try:
            await net.send(writer, Reject(reason))
        except (ConnectionError, OSError):
            pass

    async def _ask_as(self, m2: M2) -> Message:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.as_host, self.as_port), self.cfg.io_timeout_s
        )
        try:
            await net.send(writer, m2)
            console.sent(self.name, "M2", "AS", m2.fields_for_log())
            return await net.recv(reader, self.cfg.io_timeout_s)
        finally:
            await net.close(writer)

    # ------------------------------------------------------------------ protocol
    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._run_protocol(reader, writer)
        except (ProtocolError, net.ConnectionClosed, TimeoutError, OSError) as exc:
            await self._reject_sd(writer, f"session aborted: {type(exc).__name__}: {exc}")
        finally:
            await net.close(writer)

    async def _run_protocol(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ΔT = self.cfg.delta_t_ms
        m1 = await net.recv(reader, self.cfg.io_timeout_s)
        if not isinstance(m1, M1):
            return await self._reject_sd(writer, f"expected M1 to start a session, got {m1.TYPE}")
        console.received(self.name, "M1", "SD", m1.fields_for_log())

        # Step 3: check M1, build M2
        if m1.ID_DL != self.ID_DL:
            return await self._reject_sd(writer, f"M1 addressed to {m1.ID_DL}, this door is {self.ID_DL}")
        fresh, delta = is_fresh(self.clock, m1.T1, ΔT)
        if not fresh:
            return await self._reject_sd(writer, f"stale timestamp T1 (Δ={delta / 1000:.1f}s)")
        N2, T2 = cu.rand(16), self.clock.now_ms()
        Tag2 = compute_Tag2(self.K_DL, m1.encode(), N2, T2, self.ID_DL)
        reply = await self._ask_as(M2(M1=m1, N2=N2, T2=T2, Tag2=Tag2))

        if isinstance(reply, Reject):
            return await self._reject_sd(writer, f"AS rejected: {reply.reason}")
        if not isinstance(reply, M3):
            return await self._reject_sd(writer, f"unexpected reply from AS: {reply.TYPE}")
        m3 = reply
        console.received(self.name, "M3", "AS", m3.fields_for_log())

        # Step 5: authenticate the AS by decrypting C_DL with K_DL
        try:
            fields = split(cu.Dec(self.K_DL, m3.C_DL, aad_C_DL(self.ID_DL, m1.TID, N2)), expected=4)
            decision, SK, role, T3_inner = to_str(fields[0]), fields[1], to_str(fields[2]), to_int(fields[3])
        except (cu.IntegrityError, ValueError):
            return await self._reject_sd(writer, "C_DL failed AES-GCM verification → AS not authenticated")
        if T3_inner != m3.T3:
            return await self._reject_sd(writer, "T3 in C_DL does not match T3 in M3")
        fresh, delta = is_fresh(self.clock, m3.T3, ΔT)
        if not fresh:
            return await self._reject_sd(writer, f"stale timestamp T3 (Δ={delta / 1000:.1f}s)")
        console.ok(self.name, f"C_DL decrypted → AS authenticated; decision={decision}")

        if decision != ALLOW:
            self._event("DENIED", decision)
            console.warn(self.name, f"stays LOCKED ({decision}); forwarding C_U only")
            m4 = M4(C_U=m3.C_U, T3=m3.T3)
            await net.send(writer, m4)
            console.sent(self.name, "M4", "SD", m4.fields_for_log())
            return None

        T4 = self.clock.now_ms()
        m4 = M4(C_U=m3.C_U, T3=m3.T3, T4=T4, Auth_DL=compute_Auth_DL(SK, self.ID_DL, m1.TID, T4))
        await net.send(writer, m4)
        console.sent(self.name, "M4", "SD", m4.fields_for_log())

        # Step 7: key confirmation from the user
        m5 = await net.recv(reader, self.cfg.io_timeout_s)
        if not isinstance(m5, M5):
            return await self._reject_sd(writer, f"expected M5, got {m5.TYPE}")
        console.received(self.name, "M5", "SD", m5.fields_for_log())
        fresh, delta = is_fresh(self.clock, m5.T5, ΔT)
        if not fresh:
            return await self._reject_sd(writer, f"stale timestamp T5 (Δ={delta / 1000:.1f}s)")
        if not cu.ct_eq(m5.Auth_U, compute_Auth_U(SK, m1.TID, m5.T5)):
            return await self._reject_sd(writer, "Auth_U invalid → user did not prove knowledge of SK")
        console.ok(self.name, "Auth_U valid → user holds SK (key confirmed)")

        self._unlock(role)
        state = _SessionState(TID=m1.TID, SK=SK, role=role)
        await self._send_session(writer, state, f"UNLOCKED {self.ID_DL} for {self.cfg.unlock_seconds} s")
        await self._session_loop(reader, writer, state)
        return None

    # ------------------------------------------------------------------ post-handshake traffic (Enc_SK)
    async def _send_session(self, writer: asyncio.StreamWriter, st: _SessionState, text: str) -> None:
        ct = cu.Enc(st.SK, text.encode(), aad_session(self.ID_DL, st.TID, st.seq_out, "DL"))
        await net.send(writer, Session(seq=st.seq_out, ct=ct))
        st.seq_out += 1

    async def _session_loop(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, st: _SessionState
    ) -> None:
        while True:
            try:
                msg = await net.recv(reader, self.cfg.io_timeout_s)
            except (net.ConnectionClosed, TimeoutError):
                return
            if not isinstance(msg, Session) or msg.seq != st.seq_in:
                return await self._reject_sd(writer, "bad session message (type or sequence)")
            try:
                cmd = cu.Dec(st.SK, msg.ct, aad_session(self.ID_DL, st.TID, msg.seq, "SD")).decode()
            except cu.IntegrityError:
                return await self._reject_sd(writer, "session message failed Enc_SK verification")
            st.seq_in += 1
            console.received(self.name, "SESSION", "SD", {"seq": msg.seq, "cmd (decrypted)": cmd})
            if cmd == "LOCK":
                self._lock("user request over Enc_SK channel")
                await self._send_session(writer, st, f"LOCKED {self.ID_DL}")
            else:
                await self._send_session(writer, st, f"unknown command {cmd!r}")

    async def start(self, host: str | None = None, port: int | None = None) -> asyncio.Server:
        return await asyncio.start_server(
            self._handle_conn, host or self.cfg.host, self.door.port if port is None else port
        )


async def _amain(args: argparse.Namespace) -> None:
    cfg = load_config()
    door = load_door_config(cfg, args.door)
    dl = DoorLock(cfg, door, as_host=args.as_host, as_port=args.as_port)
    srv = await dl.start(port=args.port)
    port = srv.sockets[0].getsockname()[1]
    console.ok(dl.name, f"door lock listening on {cfg.host}:{port}, AS at {dl.as_host}:{dl.as_port}")
    async with srv:
        await srv.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--door", required=True, help="ID_DL, e.g. CSE-101")
    ap.add_argument("--port", type=int, default=None, help="default: port from the door config")
    ap.add_argument("--as-host", default=None)
    ap.add_argument("--as-port", type=int, default=None)
    try:
        asyncio.run(_amain(ap.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
