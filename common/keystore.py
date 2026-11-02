"""Loading and saving of key material, door configs and smart-device card files."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common import crypto_utils as cu
from common.config import Config
from common.encoding import b64d, b64e


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def write_json(path: Path, obj: dict[str, Any]) -> None:
    write_atomic(path, (json.dumps(obj, indent=2) + "\n").encode("utf-8"))


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- AS keys


@dataclass(frozen=True)
class ASKeys:
    x: bytes  # master secret — never leaves the AS
    sk_AS: cu.PrivateKey  # ECDSA signing key (audit log)
    d_AS: cu.PrivateKey  # static ECDH key (D1)

    @property
    def pk_AS(self) -> cu.PublicKey:
        return self.sk_AS.public_key()

    @property
    def Q_AS(self) -> bytes:
        return cu.point_bytes(self.d_AS.public_key())


def load_as_keys(cfg: Config) -> ASKeys:
    if not cfg.master_key_path.exists():
        raise FileNotFoundError(f"AS keys not found in {cfg.keys_dir} — run `python -m admin.setup_system` first")
    return ASKeys(
        x=cfg.master_key_path.read_bytes(),
        sk_AS=cu.load_private_key_pem(cfg.sign_sk_path.read_bytes()),
        d_AS=cu.load_private_key_pem(cfg.dh_sk_path.read_bytes()),
    )


def load_pk_AS(cfg: Config) -> cu.PublicKey:
    return cu.load_public_key_pem(cfg.sign_pk_path.read_bytes())


# ---------------------------------------------------------------- door config


@dataclass(frozen=True)
class DoorConfig:
    ID_DL: str
    K_DL: bytes
    pk_AS_pem: str
    port: int
    as_host: str
    as_port: int

    def to_json(self) -> dict[str, Any]:
        return {
            "ID_DL": self.ID_DL,
            "K_DL": b64e(self.K_DL),
            "pk_AS": self.pk_AS_pem,
            "port": self.port,
            "as_host": self.as_host,
            "as_port": self.as_port,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> DoorConfig:
        return cls(d["ID_DL"], b64d(d["K_DL"]), d["pk_AS"], d["port"], d["as_host"], d["as_port"])


def load_door_config(cfg: Config, ID_DL: str) -> DoorConfig:
    path = cfg.door_config_path(ID_DL)
    if not path.exists():
        raise FileNotFoundError(f"door {ID_DL} is not registered ({path} missing)")
    return DoorConfig.from_json(read_json(path))


# ---------------------------------------------------------------- smart-device card


@dataclass
class Card:
    B: bytes
    V: int
    TID: bytes
    n0: int
    pk_AS_pem: str
    Q_AS: bytes
    r: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "B": b64e(self.B),
            "V": self.V,
            "TID": b64e(self.TID),
            "n0": self.n0,
            "pk_AS": self.pk_AS_pem,
            "Q_AS": b64e(self.Q_AS),
            "r": b64e(self.r),
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Card:
        return cls(
            B=b64d(d["B"]),
            V=int(d["V"]),
            TID=b64d(d["TID"]),
            n0=int(d["n0"]),
            pk_AS_pem=d["pk_AS"],
            Q_AS=b64d(d["Q_AS"]),
            r=b64d(d["r"]),
        )


def load_card(path: Path) -> Card:
    return Card.from_json(read_json(path))


def save_card(path: Path, card: Card) -> None:
    write_json(path, card.to_json())
