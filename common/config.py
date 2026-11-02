"""Ports, protocol parameters and filesystem paths.

Runtime state (keys/, cards/, logs/, db/*.db) lives under ``data_dir``, which
defaults to the repository root and can be redirected with ``SDL_DATA_DIR``
(the tests use a temporary directory).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Config:
    data_dir: Path = REPO_ROOT
    host: str = "127.0.0.1"
    as_port: int = 9000
    dl_base_port: int = 9100
    proxy_port: int = 9200
    delta_t_ms: int = 30_000  # freshness window ΔT
    n0: int = 256  # fuzzy-verifier modulus
    max_failed_attempts: int = 5
    io_timeout_s: float = 5.0  # how long an entity waits for the next message
    unlock_seconds: int = 5
    policy_path: Path = field(default=REPO_ROOT / "db" / "policy.json")

    # ------------------------------------------------------------- paths
    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def master_key_path(self) -> Path:
        return self.keys_dir / "as_master_x.bin"

    @property
    def sign_sk_path(self) -> Path:
        return self.keys_dir / "as_sign_sk.pem"

    @property
    def sign_pk_path(self) -> Path:
        return self.keys_dir / "as_sign_pk.pem"

    @property
    def dh_sk_path(self) -> Path:
        return self.keys_dir / "as_dh_sk.pem"

    @property
    def dh_pk_path(self) -> Path:
        return self.keys_dir / "as_dh_pk.pem"

    @property
    def doors_dir(self) -> Path:
        """Per-door config files {ID_DL, K_DL, pk_AS, port} (secret — installed in the lock)."""
        return self.keys_dir / "doors"

    def door_config_path(self, ID_DL: str) -> Path:
        return self.doors_dir / f"{ID_DL}.json"

    @property
    def door_directory_path(self) -> Path:
        """Public map ID_DL → {host, port} so devices know where each door listens (no secrets)."""
        return self.data_dir / "doors.json"

    @property
    def cards_dir(self) -> Path:
        return self.data_dir / "cards"

    def card_path(self, ID_U: str) -> Path:
        return self.cards_dir / f"{ID_U}.json"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def access_log_path(self) -> Path:
        return self.logs_dir / "access_log.jsonl"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "db" / "door_lock.db"


def load_config(**overrides: object) -> Config:
    """Build a Config from defaults, ``SDL_*`` environment variables, then overrides."""
    env: dict[str, object] = {}
    if v := os.environ.get("SDL_DATA_DIR"):
        env["data_dir"] = Path(v)
    if v := os.environ.get("SDL_DELTA_T_MS"):
        env["delta_t_ms"] = int(v)
    if v := os.environ.get("SDL_AS_PORT"):
        env["as_port"] = int(v)
    if v := os.environ.get("SDL_POLICY"):
        env["policy_path"] = Path(v)
    cfg = replace(Config(), **env)  # type: ignore[arg-type]
    return replace(cfg, **overrides)  # type: ignore[arg-type]
