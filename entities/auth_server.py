"""Authentication Server (AS) — verifies users and doors, enforces policy, keeps the signed log.

    python -m entities.auth_server [--port 9000] [--sim-time 2026-11-02T09:30]

--sim-time only shifts the clock used by the timetable policy; message timestamps
always use real time so that freshness checks between processes stay meaningful.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

from common import console, net
from common import crypto_utils as cu
from common.audit_log import AuditLog
from common.clock import Clock, SystemClock, is_fresh
from common.config import Config, load_config
from common.encoding import cat, split, to_str
from common.keystore import ASKeys, load_as_keys
from common.messages import M2, M3, ProtocolError, Reject
from common.protocol import (
    ALLOW,
    aad_C1,
    aad_C_DL,
    aad_C_U,
    compute_A,
    compute_K_DL,
    compute_Tag2,
    derive_k1,
    derive_k_u,
    derive_SK,
)
from db.store import Store, UserRow
from entities.access_policy import AccessPolicy

NAME = "AS"


class AuthServer:
    def __init__(
        self,
        cfg: Config,
        keys: ASKeys | None = None,
        clock: Clock | None = None,
        policy_clock: Clock | None = None,
    ) -> None:
        self.cfg = cfg
        self.keys = keys or load_as_keys(cfg)
        self.clock: Clock = clock or SystemClock()
        self.policy_clock: Clock = policy_clock or self.clock
        self.store = Store(cfg.db_path)
        self.policy = AccessPolicy.load(cfg.policy_path)
        self.audit = AuditLog(cfg.access_log_path, self.keys.sk_AS)
        # (TID, T1, h(C1)) → expiry (ms). Entries older than the freshness window can be
        # dropped because a replay of them would fail the timestamp check anyway.
        self.replay_cache: dict[tuple[bytes, int, bytes], int] = {}
        self.last_reject: str | None = None

    # ------------------------------------------------------------------ helpers
    def _reject(
        self,
        reason: str,
        *,
        ID_DL: str | None = None,
        user: UserRow | None = None,
        transcript_hash: bytes | None = None,
    ) -> Reject:
        console.reject(NAME, reason)
        self.last_reject = reason
        # Only log once the request is known to come from a registered door (Tag2 valid),
        # so outsiders cannot flood the signed log.
        if transcript_hash is not None and ID_DL is not None:
            self.audit.append(
                timestamp=self.clock.now_ms(),
                ID_U=user.ID_U if user else None,
                role=user.role if user else None,
                ID_DL=ID_DL,
                decision="REJECT",
                reason=reason,
                transcript_hash=transcript_hash,
            )
        return Reject(reason)

    def _purge_replay_cache(self, now: int) -> None:
        for key in [k for k, exp in self.replay_cache.items() if exp < now]:
            del self.replay_cache[key]

    # ------------------------------------------------------------------ Step 4
    def handle_M2(self, m2: M2) -> M3 | Reject:
        m1 = m2.M1
        TID, T1, ID_DL, E, C1 = m1.TID, m1.T1, m1.ID_DL, m1.E, m1.C1
        N2, T2, Tag2 = m2.N2, m2.T2, m2.Tag2
        ΔT = self.cfg.delta_t_ms

        # 4.1 freshness + replay cache lookup
        for name, T in (("T1", T1), ("T2", T2)):
            fresh, delta = is_fresh(self.clock, T, ΔT)
            if not fresh:
                return self._reject(f"stale timestamp {name} (Δ={delta / 1000:.1f}s > ΔT={ΔT / 1000:.0f}s)")
        now = self.clock.now_ms()
        self._purge_replay_cache(now)
        cache_key = (TID, T1, cu.h(C1))
        if cache_key in self.replay_cache:
            return self._reject("replay detected: (TID, T1, h(C1)) already seen")

        # 4.2 authenticate the door: K_DL = h(ID_DL ‖ x), verify Tag2
        if not self.store.get_door(ID_DL):
            return self._reject(f"unknown door {ID_DL}")
        K_DL = compute_K_DL(ID_DL, self.keys.x)
        if not cu.ct_eq(Tag2, compute_Tag2(K_DL, m1.encode(), N2, T2, ID_DL)):
            return self._reject(f"Tag2 invalid: M2 not from door lock {ID_DL} or M1/M2 modified")
        # record in the replay cache only now, so forged M2s cannot poison it (design note D4)
        self.replay_cache[cache_key] = now + 2 * ΔT
        transcript_hash = cu.h(cat(m1.encode(), m2.encode()))
        console.ok(NAME, f"T1, T2 fresh; Tag2 valid → door {ID_DL} authenticated")

        # 4.3 TID lookup (current or previous pseudonym)
        found = self.store.find_by_tid(TID)
        if found is None:
            return self._reject(
                "unknown TID (not a current or previous pseudonym)",
                ID_DL=ID_DL,
                transcript_hash=transcript_hash,
            )
        user, which = found
        if which == "old":
            console.warn(NAME, "TID matched TID_old → previous M4 was lost; resynchronising")
        log = {"ID_DL": ID_DL, "user": user, "transcript_hash": transcript_hash}

        # 4.4 account state
        if user.revoked:
            return self._reject(f"user {user.ID_U} is revoked", **log)
        if user.failed_attempts >= self.cfg.max_failed_attempts:
            return self._reject(f"account {user.ID_U} locked after {user.failed_attempts} failed attempts", **log)

        # 4.5 authenticate the user: Z = d_AS·E, A = h(ID_U ‖ x ‖ v), decrypt C1
        A = compute_A(user.ID_U, self.keys.x, user.card_version)
        try:
            Z = cu.ecdh(self.keys.d_AS, E)
            k1 = derive_k1(A, Z, TID, T1, E)
            N1, ID_U_bytes = split(cu.Dec(k1, C1, aad_C1(TID, T1, ID_DL, E)), expected=2)
        except (cu.IntegrityError, ValueError):
            n = self.store.increment_failed(user.ID_U)
            return self._reject(
                f"C1 failed AES-GCM verification (wrong A / tampered M1) — "
                f"failed_attempts={n}/{self.cfg.max_failed_attempts}",
                **log,
            )
        if not cu.ct_eq(ID_U_bytes, user.ID_U.encode("utf-8")):
            n = self.store.increment_failed(user.ID_U)
            return self._reject(f"decrypted ID_U does not own this TID — failed_attempts={n}", **log)
        ID_U = to_str(ID_U_bytes)
        console.ok(NAME, f"C1 decrypted → ID_U={ID_U} (role={user.role}) authenticated")

        # 4.6 authorization
        verdict = self.policy.evaluate(ID_U, user.role, user.class_id, ID_DL, self.policy_clock.now_dt())
        decision = ALLOW if verdict.decision == ALLOW else f"DENY: {verdict.reason}"
        (console.ok if verdict.decision == ALLOW else console.warn)(
            NAME, f"policy → {verdict.decision} ({verdict.reason})"
        )

        # 4.7 – 4.10 session key and the two ciphertexts
        N3, TID_new, T3 = cu.rand(16), cu.rand(16), self.clock.now_ms()
        SK = derive_SK(N1, N2, N3, ID_DL, TID, T3)
        C_DL = cu.Enc(K_DL, cat(decision, SK, user.role, T3), aad_C_DL(ID_DL, TID, N2))
        k_u = derive_k_u(A, N1, T3)
        C_U = cu.Enc(k_u, cat(decision, N2, N3, TID_new, T3), aad_C_U(TID, ID_DL))

        # 4.11 TID update with desync protection
        self.store.rotate_tid(ID_U, TID, TID_new)

        # 4.12 signed audit-log entry
        entry = self.audit.append(
            timestamp=T3,
            ID_U=ID_U,
            role=user.role,
            ID_DL=ID_DL,
            decision=verdict.decision,
            reason=verdict.reason,
            transcript_hash=transcript_hash,
        )
        console.info(NAME, f"audit log #{entry['seq']} signed; TID rotated (TID_old ← TID, TID_cur ← TID_new)")
        return M3(T3=T3, C_DL=C_DL, C_U=C_U)

    # ------------------------------------------------------------------ network
    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            msg = await net.recv(reader, self.cfg.io_timeout_s)
            if not isinstance(msg, M2):
                reply: M3 | Reject = self._reject(f"AS expects M2, got {msg.TYPE}")
            else:
                console.received(NAME, "M2", f"DL {msg.M1.ID_DL}", msg.fields_for_log())
                reply = self.handle_M2(msg)
            await net.send(writer, reply)
            if isinstance(reply, M3):
                console.sent(NAME, "M3", "DL", reply.fields_for_log())
        except (ProtocolError, net.ConnectionClosed, TimeoutError) as exc:
            console.reject(NAME, f"bad request: {exc}")
        finally:
            await net.close(writer)

    async def start(self, host: str | None = None, port: int | None = None) -> asyncio.Server:
        return await asyncio.start_server(
            self._handle_conn, host or self.cfg.host, self.cfg.as_port if port is None else port
        )


async def _amain(args: argparse.Namespace) -> None:
    cfg = load_config()
    policy_clock = SystemClock.starting_at(args.sim_time) if args.sim_time else None
    server = AuthServer(cfg, policy_clock=policy_clock)
    srv = await server.start(port=args.port)
    port = srv.sockets[0].getsockname()[1]
    console.ok(NAME, f"Authentication Server listening on {cfg.host}:{port} (ΔT={cfg.delta_t_ms / 1000:.0f}s)")
    if args.sim_time:
        console.info(NAME, f"policy clock simulated: starts at {args.sim_time:%a %Y-%m-%d %H:%M}")
    async with srv:
        await srv.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--sim-time", type=datetime.fromisoformat, help="e.g. 2026-11-02T09:30 (a Monday)")
    try:
        asyncio.run(_amain(ap.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
