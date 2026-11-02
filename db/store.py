"""SQLite access layer for the Authentication Server.

Every call reads the database afresh, so rows written by the offline admin CLIs
(registration, revocation) are visible to a running AS immediately.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


@dataclass(frozen=True)
class UserRow:
    ID_U: str
    role: str
    class_id: str | None
    card_version: int
    TID_cur: bytes
    TID_old: bytes | None
    revoked: bool
    failed_attempts: int


def _row_to_user(row: sqlite3.Row) -> UserRow:
    return UserRow(
        ID_U=row["ID_U"],
        role=row["role"],
        class_id=row["class_id"],
        card_version=row["card_version"],
        TID_cur=bytes.fromhex(row["TID_cur"]),
        TID_old=bytes.fromhex(row["TID_old"]) if row["TID_old"] else None,
        revoked=bool(row["revoked"]),
        failed_attempts=row["failed_attempts"],
    )


class Store:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:  # commits on success, rolls back on exception
                yield conn
        finally:
            conn.close()

    def init_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    # ------------------------------------------------------------ doors
    def add_door(self, ID_DL: str, port: int) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO doors (ID_DL, port, registered_ms) VALUES (?, ?, ?)",
                (ID_DL, port, int(time.time() * 1000)),
            )

    def get_door(self, ID_DL: str) -> dict[str, object] | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM doors WHERE ID_DL = ?", (ID_DL,)).fetchone()
        return dict(row) if row else None

    def list_doors(self) -> list[dict[str, object]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM doors ORDER BY port")]

    # ------------------------------------------------------------ users
    def add_user(self, ID_U: str, role: str, class_id: str | None, TID: bytes) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO users (ID_U, role, class_id, card_version, TID_cur) VALUES (?, ?, ?, 1, ?)",
                (ID_U, role, class_id, TID.hex()),
            )

    def get_user(self, ID_U: str) -> UserRow | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE ID_U = ?", (ID_U,)).fetchone()
        return _row_to_user(row) if row else None

    def list_users(self) -> list[UserRow]:
        with self._conn() as c:
            return [_row_to_user(r) for r in c.execute("SELECT * FROM users ORDER BY ID_U")]

    def raw_rows(self) -> list[dict[str, object]]:
        """Exactly what an insider with read access sees."""
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM users ORDER BY ID_U")]

    def find_by_tid(self, TID: bytes) -> tuple[UserRow, str] | None:
        """Look TID up as TID_cur or TID_old. Returns (row, "cur" | "old")."""
        hx = TID.hex()
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE TID_cur = ? OR TID_old = ?", (hx, hx)).fetchone()
        if not row:
            return None
        user = _row_to_user(row)
        return user, ("cur" if user.TID_cur == TID else "old")

    def rotate_tid(self, ID_U: str, TID_used: bytes, TID_new: bytes) -> None:
        """Step 4.11: TID_old ← TID (just used), TID_cur ← TID_new, failed_attempts ← 0."""
        with self._conn() as c:
            # clear TID_old first so the UNIQUE constraint cannot trip when TID_used == TID_old
            c.execute("UPDATE users SET TID_old = NULL WHERE ID_U = ?", (ID_U,))
            c.execute(
                "UPDATE users SET TID_old = ?, TID_cur = ?, failed_attempts = 0 WHERE ID_U = ?",
                (TID_used.hex(), TID_new.hex(), ID_U),
            )

    def increment_failed(self, ID_U: str) -> int:
        with self._conn() as c:
            c.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE ID_U = ?", (ID_U,))
            row = c.execute("SELECT failed_attempts FROM users WHERE ID_U = ?", (ID_U,)).fetchone()
        return int(row["failed_attempts"])

    def reset_failed(self, ID_U: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET failed_attempts = 0 WHERE ID_U = ?", (ID_U,))

    def set_revoked(self, ID_U: str, revoked: bool) -> bool:
        with self._conn() as c:
            cur = c.execute("UPDATE users SET revoked = ? WHERE ID_U = ?", (int(revoked), ID_U))
        return cur.rowcount == 1

    def reissue(self, ID_U: str, TID_new: bytes) -> int:
        """Phase 5 re-issue: v ← v+1, fresh TID, old TID forgotten, un-revoke, clear lockout."""
        with self._conn() as c:
            c.execute(
                "UPDATE users SET card_version = card_version + 1, TID_cur = ?, TID_old = NULL, "
                "revoked = 0, failed_attempts = 0 WHERE ID_U = ?",
                (TID_new.hex(), ID_U),
            )
            row = c.execute("SELECT card_version FROM users WHERE ID_U = ?", (ID_U,)).fetchone()
        return int(row["card_version"])
