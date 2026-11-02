# Secure User Authentication Protocol for a Classroom Smart Door Lock

**CS428: Design of Secure Protocol — NIT Warangal**
Rajarshi Saha (23CSB0A07), B.Tech CSE

This repository contains:

1. A **software simulation** of the protocol in Python. The Authentication Server, each Door Lock and the user's Smart Device run as separate processes and talk over TCP on localhost.
2. An **attacker proxy** and **nine attack scripts**. They show the protocol resisting replay, MITM tampering, user and server impersonation, a stolen smart device (offline and online guessing), desynchronization, a malicious insider, door-lock compromise and traceability.
3. A **ProVerif model** of the protocol (`formal/`).
4. A **performance analysis** (`benchmarks/results.md`).

---

## Quick start

Requires Python 3.11+.

```bash
pip install -r requirements.txt

make demo          # or, without make (e.g. Windows):  python tasks.py demo
make test          #                                   python tasks.py test
```

`make demo` (`run_demo.py`) does the following in one go:

1. Resets the system and registers 2 doors, 1 faculty member and 1 student offline.
2. Starts the AS and two door-lock processes.
3. Shows two allowed logins, a password change, a login **denied** by the timetable and a revoked user.
4. Runs every attack and verifies the signed audit log, including a tampered copy.
5. Prints a summary.

It takes about 1.5 minutes. `python run_demo.py --fast` skips the 32-second "replay after ΔT" case.

Other targets: `make attacks` (setup plus attacks only), `make bench`, `make proverif`, `make lint`, `make clean`.
The Makefile only forwards to `tasks.py`, so `python tasks.py <target>` behaves identically.

### Running the entities by hand (one terminal each)

```bash
python -m admin.setup_system                       # Phase 0  (--force to reset everything)
python -m admin.register_door --door CSE-101       # Phase 1  → port 9100
python -m admin.register_door --door CSE-102       #          → port 9101
python -m admin.register_user --id F-1001 --role faculty                    # Phase 2 (prompts for password)
python -m admin.register_user --id 23CSB0A07 --role student --class CSE-4A

python -m entities.auth_server --sim-time 2026-11-02T09:30   # terminal 1 (AS :9000; --sim-time is optional)
python -m entities.door_lock --door CSE-101                  # terminal 2
python -m entities.door_lock --door CSE-102                  # terminal 3
python -m entities.user_device --id 23CSB0A07 --door CSE-101 [--lock] [--new-password NEW]

python -m attacks.attacker_proxy --mode drop --msg M4        # attacker proxy on :9200 ...
python -m entities.user_device --id 23CSB0A07 --door CSE-101 --via-proxy   # ... and route through it
python -m admin.revoke_user --id 23CSB0A07 [--undo | --reset-lockout]      # Phase 5
python -m admin.register_user --id 23CSB0A07 --reissue                     # Phase 5 re-issue
python -m tools.verify_log                                                 # check the audit log
```

`--sim-time` changes only the clock the **access policy** uses, so the timetable can be demonstrated at any
hour. Message timestamps always use real time.

---

## 1. Entities and roles

| Symbol | Entity | Role | Code |
|---|---|---|---|
| U | User | Student, CR, faculty member or admin who wants to open a classroom door | — |
| SD | Smart Device | Phone or smartcard. Stores the card values and runs the client side | `entities/user_device.py` |
| DL | Door Lock | Controller on a classroom door. Relays to the AS, verifies the AS and the user, actuates the lock | `entities/door_lock.py` |
| AS | Authentication Server | Department server. Registration authority, verifies users and doors, enforces policy, keeps the signed log | `entities/auth_server.py` |
| — | Admin office | Offline secure channel for registration, revocation and re-issue (a local CLI, never the network) | `admin/` |

## 2. Authentication parameters

| Who | Factors / long-term values | Where stored |
|---|---|---|
| User | `ID_U` + password `PW_U` (something you know) + smart device holding `{B, V, TID, n0, pk_AS, Q_AS, r}` (something you have) | user's memory / `cards/<ID>.json` |
| Door lock | identity `ID_DL` + pre-shared key `K_DL = h(ID_DL ‖ x)` | `keys/doors/<ID_DL>.json` |
| AS | master secret `x`, ECDSA key `sk_AS`, ECDH key `d_AS` | `keys/` |
| AS database | `ID_U, role, class, v, TID_cur, TID_old, revoked, failed_attempts`. **No** `PW_U`, `RPW`, `A` or `K_DL` | `db/door_lock.db` |

## 3. Assumptions and threat model

- Registration of users and doors is **offline** over a secure channel. It is simulated by the `admin/` CLIs, which write directly to the DB and the card and config files.
- Login messages travel over an **insecure public channel** (TCP on localhost) controlled by a **Dolev–Yao** attacker, who can eavesdrop, intercept, replay, modify, drop, delay and inject.
- The attacker may also **steal a smart device** and read everything on it, but does not know the password. They may be an **insider** who can read the AS DB, but not `x`. They may **compromise one door lock** and learn its `K_DL`.
- The AS is trusted. Clocks are loosely synchronized, with freshness window `ΔT = 30 s` (`SDL_DELTA_T_MS`).

---

## 4. The protocol

Notation: `h` = SHA-256, `HMAC` = HMAC-SHA256, `KDF` = HKDF-SHA256, `Enc/Dec` = AES-256-GCM with a random
12-byte nonce and associated data. `‖` is length-prefixed concatenation (4-byte big-endian length per field), which
makes `cat("ab","c") ≠ cat("a","bc")`. All formulas live in one module, [common/protocol.py](common/protocol.py), and
code variable names follow the notation (`N1`, `TID`, `C_U`, `Auth_DL`, …).

Sequence diagrams for every phase are in [diagrams/](diagrams/) (Mermaid; render with mermaid.live or the VS Code
Mermaid extension).

| Phase | Summary |
|---|---|
| 0 Setup | AS generates `x`, an ECDSA key pair `(sk_AS, pk_AS)` and an ECDH key pair `(d_AS, Q_AS)` |
| 1 Door registration | `K_DL = h(ID_DL ‖ x)` installed in the door |
| 2 User registration | SD: `RPW = h(PW‖r)`. AS: `A = h(ID_U‖x‖v)`, `B = A ⊕ h(ID_U‖RPW)`, `V = int(h(h(ID_U‖RPW))) mod n0`, random `TID` |
| 3 Login | M1 SD→DL `{TID, T1, ID_DL, E, C1}` · M2 DL→AS `{M1, N2, T2, Tag2}` · M3 AS→DL `{T3, C_DL, C_U}` · M4 DL→SD `{C_U, T3, T4, Auth_DL}` · M5 SD→DL `{T5, Auth_U}` · then `Enc_SK` session traffic |
| 4 Password change | Only after a successful online login in the same session. New `r', B', V'`; the AS is not involved |
| 5 Revocation / re-issue | `revoked = 1`. Re-issue: new `TID`, new `r`, `v ← v+1` |

Desynchronization: if M4 is lost, the SD keeps the old `TID`. The AS still accepts it as `TID_old` and issues a
fresh `TID_new` ([diagram](diagrams/desync_recovery.mmd), `attacks/desync_attack.py`, `tests/test_desync.py`).

### Design changes (approved during the project)

| # | Change | Why |
|---|---|---|
| **D1** | M1 carries an ephemeral ECDH share `E = e·G`. `k1 = KDF(A ‖ Z, "M1" ‖ TID ‖ T1 ‖ E)` with `Z = e·Q_AS = d_AS·E`, and `E` is added to C1's associated data. The card also stores `Q_AS` | **Stolen device + one recorded login → offline password recovery.** In the original design, a guessed password gives a candidate `A`, and trying to decrypt a recorded `C1` confirms it exactly (the GCM tag only verifies for the right `A`). That defeats the fuzzy verifier. With D1, checking a guess needs `Z`, which requires `d_AS` or `e`. `attacks/stolen_card.py` shows both cases: original design → password found, D1 → no candidate confirmed |
| **D2** | `A = h(ID_U ‖ x ‖ v)` with a per-user card-issue counter `v`, stored in the DB and incremented on re-issue | With a fixed `A`, an old card plus the password still worked after re-issue: every `M1` shows a valid `TID` in the clear, which the AS accepts as `TID_old`. Now the old card's `A` is dead (`tests/test_login_failures.py::test_reissued_card_kills_old_card_even_with_password`) |
| **D3** | `Auth_U = HMAC(SK, "U-CONFIRM" ‖ TID ‖ T5)`, using `TID` instead of `TID_new` | As written, the spec cannot be implemented: the door must verify `Auth_U`, but `TID_new` exists only inside `C_U`, which the door cannot read. Using `TID` keeps the next pseudonym hidden from the door |

### Implementation notes (no design change)

- **Replay cache ordering (D4).** `(TID, T1, h(C1))` is checked at Step 4.1 but **inserted only after `Tag2` verifies**. Otherwise anyone could send a bogus M2 straight to the AS, poison the cache and block a genuine login.
- **DENY with a reason.** On DENY, the `decision` field inside `C_DL` and `C_U` is the string `"DENY: <reason>"`, so the user sees why.
- **Rejections.** Each entity prints a precise reason, and the AS also sends it in an unauthenticated `REJECT` message so the demo is easy to follow. A production deployment would send a generic error.
- **Audit log.** The AS logs `ALLOW`, `DENY` and `REJECT`. A `REJECT` is logged only after `Tag2` verifies, so outsiders cannot flood the log.
- **Post-handshake traffic.** The door's "UNLOCKED" confirmation and the optional `LOCK` command travel as `Enc_SK(cmd; aad = "SESSION" ‖ ID_DL ‖ TID ‖ seq ‖ sender)` with sequence numbers.

---

## 5. Security services

| Service | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM (`C1`, `C_DL`, `C_U`, session traffic under `SK`). `ID_U` is never sent in the clear |
| Integrity | GCM tags + HMAC (`Tag2`, `Auth_DL`, `Auth_U`). All MAC/verifier comparisons are constant time (`hmac.compare_digest`) |
| Authentication | Mutual: SD↔AS via `A` (+ `Z`, D1). DL↔AS via `K_DL`. SD↔DL via key confirmation on `SK` (`Auth_DL`, `Auth_U`) |
| Authorization | AS role and timetable policy per door ([db/policy.json](db/policy.json), [entities/access_policy.py](entities/access_policy.py)) |
| Non-repudiation | ECDSA-signed, hash-chained audit log at the AS (`logs/access_log.jsonl`, checked by `tools/verify_log.py`) |
| User anonymity / untraceability | `TID` rotates every session. `ID_U` only travels inside `C1` |
| Freshness | Timestamps (`ΔT`), nonces `N1, N2, N3`, and the `(TID, T1, h(C1))` replay cache |
| Offline-guessing resistance | Fuzzy verifier `V` (≈ 1/n0 of guesses pass) + D1 (transcripts give no verifier) + lockout after 5 online failures |

### Access-control policy

| Role | Doors | Time |
|---|---|---|
| admin | any | any |
| faculty | any | 07:00–21:00 |
| cr | rooms where their class is timetabled | scheduled slot ± 15 min |
| student | rooms where their class is timetabled | scheduled slot |

The seed timetable (`db/policy.json`) covers rooms `CSE-101`, `CSE-102` and `LAB-3` for classes `CSE-4A` and `CSE-4B`. For example, CSE-4A is in CSE-101 on Monday 09:00–10:00.

### Signed audit log

Each line of `logs/access_log.jsonl` has the fields `seq, timestamp, ID_U, role, ID_DL, decision, reason, transcript_hash = h(M1 ‖ M2), prev_hash, signature`.
- `prev_hash` is the SHA-256 of the previous line, forming a hash chain.
- `signature` is ECDSA-P256 with `sk_AS` over the canonical JSON of all the other fields.
- `python -m tools.verify_log` reports the first line whose signature, chain link or sequence number is wrong.

---

## 6. Security testing (attack demonstrations)

All scripts expect the AS and doors to be running (`make attacks` starts everything). Each prints
`ATTACK: <name> → RESULT: BLOCKED (<reason>)`, and the reason comes from the rejecting entity's actual response.
The victim's smart device always runs as a **separate process**, and the attacker only touches the network.

| Script | Scenario | Blocked by |
|---|---|---|
| `replay_attack.py` | Record a genuine login via the proxy, then replay M1+M5, M5 alone, M1 with a refreshed `T1`, and (with `--wait`) M1 after ΔT | Replay cache. DL expects M1 first. `T1` bound into `k1`/aad. Timestamp window |
| `mitm_tamper.py` | Flip a bit in `M1.C1`, `M1.T1`, `M1.E`, `M4.C_U`, `M4.Auth_DL`, `M5.Auth_U`; then a genuine login via the proxy in `pass` mode | GCM / HMAC checks at AS, SD and DL. The genuine user still logs in afterwards |
| `impersonate_user.py` | Forge M1 from the victim's `ID_U`, an observed `TID` and the public `Q_AS`, without `A` | `C1` fails AES-GCM at the AS |
| `impersonate_server.py` | (a) Proxy answers M1 with a forged M4. (b) A real door's AS traffic is redirected to a rogue AS that returns a forged M3 with `ALLOW` | SD: `C_U` fails → AS not authenticated. DL: `C_DL` fails → stays locked |
| `stolen_card.py` | Read the card, run a 10,840-word dictionary against `V`, try the candidates against a recorded M1, then online; then re-issue the card and use the old card **with** the right password | ≈ 1/n0 of guesses pass `V`, and the transcript confirms none (D1; the original design would reveal the password, shown as a counterfactual). Lockout after 5. D2 |
| `desync_attack.py` | Drop M4 twice, then log in normally | `TID_old` accepted, fresh `TID_new` issued |
| `insider_attack.py` | Dump the users table and forge M1 with `TID_cur` and a guessed `x` | DB holds no `PW`/`RPW`/`A`. `A` needs `x` |
| `door_compromise.py` | Leak `K_DL(CSE-101)`, pose as door CSE-102 to the AS, try to derive other door keys | `Tag2` fails for CSE-102. Keys are independent hashes of `x` |
| `traceability.py` | Record two logins by the same user and compare every field on the wire | Fresh `TID`, `E`, `C1` each session. `ID_U` never appears |

Last full run of `make demo` from a clean copy: **24 / 24 attack checks blocked** (23 with `--fast`), including the
audit-log tamper check, and `verify_log` reports the real log intact.

`attacker_proxy.py` modes: `pass`, `record`, `tamper --msg M --field F`, `drop --msg M`, `forge` (library only),
and `replay --capture FILE`.

---

## 7. Formal verification (ProVerif)

Files: [formal/door_lock.pv](formal/door_lock.pv) (main model),
[formal/guessing_stolen_card.pv](formal/guessing_stolen_card.pv) and
[formal/guessing_stolen_card_original.pv](formal/guessing_stolen_card_original.pv) (offline guessing with a stolen device, for the
protocol as built and for the original spec). Run with `make proverif` (`formal/run_proverif.sh`), which writes
[formal/results.txt](formal/results.txt).

Modelling choices:
- AES-GCM is modelled as AEAD `aenc/adec` with associated data. `h`, HMAC and HKDF are one-way functions.
- The XOR mask on `B` uses `mask/unmask` with the two equations `unmask(mask(a,k),k) = a` and `mask(unmask(b,k),k) = b`, so unmasking with a wrong key yields garbage instead of failing, as real XOR does.
- ECDH uses the standard `exp` commutation equation, and timestamps are fresh nonces.
- Registration goes over private channels.
- The attacker additionally controls one **registered user** `IDE` (knows their password and card) and one **compromised door** `IDDLE` (knows its `K_DL`).
- TID rotation is not modelled. The AS creates `TID_new` but does not add it to its table, because re-inserting it makes ProVerif's saturation diverge, and no query depends on it. Untraceability is shown by `attacks/traceability.py` instead.

ProVerif 2.05 results, all three models together in about 1 minute (full output in [formal/results.txt](formal/results.txt)):

| Query (spec name) | ProVerif query | Result |
|---|---|---|
| Secrecy of `SK` (user side) | `attacker(secretU)`: a private name the user sends under `SK` (`SK` is a let-bound term, so it cannot be queried directly) | ✅ true |
| Secrecy of `SK` (door side) | `event(DoorAuthUser(IDDL,sk)) && attacker(sk) ==> event(ServerResponds(IDE,IDDL,n1,sk))`: the attacker knows a door session's key only if the AS ran that session for the attacker's own account | ✅ true |
| Secrecy of `x`, `PW_U`, `A`, honest `K_DL`, `d_AS` | `attacker(xAS)`, `attacker(PW)`, `attacker(hA(IDU,xAS,v1))`, `attacker(h2(IDDL,xAS))`, `attacker(dAS)` | ✅ all true |
| UserAuthenticated ⇐ UserStarts (at the AS) | `event(ASAuthUser(IDU,IDDL,n1)) ==> event(UserStarts(IDU,IDDL,n1))` | ✅ true |
| UserAuthenticated (at the door) | `inj-event(DoorAuthUser(IDDL,sk)) ==> inj-event(UserConfirms(IDDL,sk)) \|\| event(ServerResponds(IDE,IDDL,n1,sk))` | ✅ true |
| ServerAuthenticated (by the user) | `inj-event(UserAuthServer(IDU,d,n1,sk)) ==> inj-event(ServerResponds(IDU,d,n1,sk))` | ✅ true |
| ServerAuthenticated (by the door) | `inj-event(DoorAuthServer(IDDL,n2,sk)) ==> inj-event(ServerSendsKey(IDDL,n2,sk))` | ✅ true |
| DoorAuthenticated (by the AS) | `event(ASAuthDoor(IDDL,n2)) ==> event(DoorSendsM2(IDDL,n2))` | ✅ true |
| UserAcceptsKey ⇐ DoorSendsKey | `inj-event(UserAcceptsKey(IDDL,sk)) ==> inj-event(DoorSendsKey(IDDL,sk))` | ✅ true |
| `weaksecret PW_U`, stolen device, **as built** | `guessing_stolen_card.pv` | ✅ true |
| `weaksecret PW_U`, stolen device, **original spec** | `guessing_stolen_card_original.pv` | ❌ false, as expected: in ProVerif's trace the attacker turns a password guess into a candidate `A` and tests whether the recorded `C1` decrypts. This is the attack that motivated D1 |

How the door-side queries are stated: a door cannot know which user it is serving. So a completed door session is
either the honest user's, or one the AS knowingly ran for the attacker's **own** registered account. A first version
of these two queries omitted the second case. ProVerif then reported "attacks" in which the attacker simply logged in
as `IDE`, and those traces never involve the honest user. The first version of the guessing models also lacked the
second XOR equation, which produced a spurious `weaksecret` failure. Both were corrected in the model only; the
protocol did not change.

The two AS-side correspondences are non-injective on purpose. Injectivity at the AS comes from the timestamp
window and the replay cache, which need state that a stateless symbolic model cannot express. Injective agreement is
proved where a fresh nonce of the verifier is involved (door ↔ user via `SK`, user ↔ AS via `N1`, door ↔ AS via `N2`).
The fuzzy verifier's `mod n0` cannot be expressed symbolically, so `V` is not given to the attacker in the guessing
models. Its ≈ 1/n0 false-accept behaviour is shown empirically by `stolen_card.py`.

---

## 8. Performance

`make bench` times every primitive (1000 runs, `benchmarks/primitive_timing.csv`). It then writes
[benchmarks/results.md](benchmarks/results.md) with the per-entity computation cost (symbolic and ms), the per-message
communication cost in bits, and a comparison table whose rows for other schemes are left as `TODO`.

| Entity | Computation (one successful login) |
|---|---|
| SD | 4T_h + 1T_xor + 2T_hmac + 2T_kdf + 1T_enc + 2T_dec + 2T_ecm |
| DL | 3T_hmac + 1T_enc + 1T_dec |
| AS | 4T_h + 1T_hmac + 2T_kdf + 2T_enc + 1T_dec + 1T_ecm (+ 1T_h + 1T_sig for the audit log) |

Communication cost: M1 1032 + M2 1448 + M3 1208 + M4 968 + M5 288 = **4944 bits**, of which 2288 bits cross the SD↔DL link.
D1 adds 3 EC scalar multiplications and 264 bits (`E`).

---

## 9. Known limitations

- **Lockout is a DoS lever.** Anyone who has seen a user's `TID` can send 5 bad M1s and lock the account until an admin runs `revoke_user --reset-lockout` or re-issues the card. This is inherent to any lockout counter.
- **Forced desync links sessions.** If the attacker keeps dropping M4, the user reuses the same `TID` and those sessions are linkable.
- **Non-repudiation relies on a trusted AS.** Users hold no signing keys, and the AS can compute `A`, so the signed log proves what the AS recorded, not what the user signed.
- **Log truncation.** Deleting the newest lines of the log is not detectable from the chain alone. Periodically anchoring the latest `prev_hash` elsewhere (printed report, second server) closes this gap.
- **Compromised door scope.** A compromised door can act as *that* door and read `SK` for sessions at *that* door. It learns nothing about `A`, `x` or other doors.
- **Simulation only.** No hardware is involved. Policy times use the AS host's local time zone.

## 10. Project structure

```
common/      crypto_utils (only place crypto is called), protocol formulas, encoding, messages, net framing,
             clock, config, keystore, audit_log, console
entities/    auth_server, door_lock, user_device, access_policy
admin/       setup_system, register_door, register_user (+ --reissue), revoke_user   — offline CLIs
db/          schema.sql, policy.json, store.py
attacks/     attacker_proxy, harness, 9 attack scripts
tools/       verify_log.py
tests/       pytest suite (crypto, registration + policy, login success/failures, password change, desync, audit log)
formal/      ProVerif models, run script, results
benchmarks/  primitive_timing.py, cost_analysis.py, results.md
diagrams/    Mermaid sources: architecture + each phase + desync
run_demo.py  tasks.py  Makefile
```

Runtime state in `keys/`, `cards/`, `logs/`, `db/*.db` and `doors.json` is git-ignored. `SDL_DATA_DIR` redirects
all of it, which the tests use to work in a temporary directory.
