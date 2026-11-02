"""Phase 1 — Door lock registration (offline, at the department office).

The AS computes K_DL = h(ID_DL ‖ x) and installs {ID_DL, K_DL, pk_AS} (plus network
settings) into the door's config file. Nothing goes over the network.

    python -m admin.register_door --door CSE-101 [--port 9100]
"""

from __future__ import annotations

import argparse
import os

from common import console
from common import crypto_utils as cu
from common.config import Config, load_config
from common.keystore import DoorConfig, load_as_keys, read_json, write_json
from common.protocol import compute_K_DL
from db.store import Store
from entities.access_policy import AccessPolicy


def register_door(cfg: Config, ID_DL: str, port: int | None = None) -> DoorConfig:
    keys = load_as_keys(cfg)
    store = Store(cfg.db_path)
    if store.get_door(ID_DL):
        raise ValueError(f"door {ID_DL} is already registered")
    if port is None:
        port = cfg.dl_base_port + len(store.list_doors())

    K_DL = compute_K_DL(ID_DL, keys.x)
    door = DoorConfig(
        ID_DL=ID_DL,
        K_DL=K_DL,
        pk_AS_pem=cu.public_key_to_pem(keys.pk_AS).decode("ascii"),
        port=port,
        as_host=cfg.host,
        as_port=cfg.as_port,
    )
    path = cfg.door_config_path(ID_DL)
    write_json(path, door.to_json())
    os.chmod(path, 0o600)
    store.add_door(ID_DL, port)

    directory = read_json(cfg.door_directory_path) if cfg.door_directory_path.exists() else {}
    directory[ID_DL] = {"host": cfg.host, "port": port}
    write_json(cfg.door_directory_path, directory)
    return door


def door_address(cfg: Config, ID_DL: str) -> tuple[str, int]:
    """Where door ID_DL listens, from the public door directory."""
    if not cfg.door_directory_path.exists():
        raise FileNotFoundError("no doors registered yet")
    entry = read_json(cfg.door_directory_path).get(ID_DL)
    if entry is None:
        raise FileNotFoundError(f"door {ID_DL} not in {cfg.door_directory_path}")
    return entry["host"], int(entry["port"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--door", required=True, help="door identity ID_DL, e.g. CSE-101")
    ap.add_argument("--port", type=int, help="TCP port the door lock listens on (default: 9100 + n)")
    args = ap.parse_args()
    cfg = load_config()
    if args.door not in AccessPolicy.load(cfg.policy_path).rooms:
        console.warn("ADMIN", f"{args.door} is not listed in {cfg.policy_path}; every login there is DENY")
    try:
        door = register_door(cfg, args.door, args.port)
    except (ValueError, FileNotFoundError) as exc:
        console.reject("ADMIN", str(exc))
        raise SystemExit(1) from exc
    console.ok("ADMIN", f"door {door.ID_DL} registered on port {door.port}")
    console.info("ADMIN", f"installed {{ID_DL, K_DL, pk_AS}} → {cfg.door_config_path(door.ID_DL)}")


if __name__ == "__main__":
    main()
