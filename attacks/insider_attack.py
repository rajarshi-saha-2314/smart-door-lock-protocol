"""Malicious insider with read access to the AS database (but not to x).

python -m attacks.insider_attack
"""

from __future__ import annotations

from rich.table import Table

from attacks.attacker_proxy import exchange
from attacks.harness import Verdicts, banner, cfg, door, fresh_victim, run
from attacks.impersonate_user import forge_M1
from common import console
from common import crypto_utils as cu
from common.encoding import cat
from common.keystore import load_card
from db.store import Store

VICTIM, PW = "victim-insider", "Insider#Victim1"


async def attack(v: Verdicts) -> None:
    banner("Malicious insider", "dump the AS user table and try to log in as a user from it")
    fresh_victim(VICTIM, PW)
    rows = Store(cfg.db_path).raw_rows()
    table = Table(title="users table as seen by the insider", show_lines=False)
    for col in rows[0]:
        table.add_column(col)
    for r in rows:
        table.add_row(*[(str(x)[:10] + "…") if isinstance(x, str) and len(x) > 12 else str(x) for x in r.values()])
    console.console.print(table)

    db_bytes = cfg.db_path.read_bytes()
    leaked = PW.encode() in db_bytes
    sensitive_cols = {"PW_U", "password", "RPW", "A", "B", "x", "K_DL"} & set(rows[0])
    console.info(
        "ATTACKER",
        f"columns: {list(rows[0])}; password-related columns: {sorted(sensitive_cols) or 'none'}; "
        f"victim password bytes in DB file: {leaked}",
    )

    victim = next(r for r in rows if r["ID_U"] == VICTIM)
    TID = bytes.fromhex(str(victim["TID_cur"]))
    x_guess = cu.rand(32)
    A_guess = cu.h(cat(VICTIM, x_guess, int(victim["card_version"])))  # A = h(ID_U ‖ x ‖ v), x unknown
    console.info("ATTACKER", "forging M1 with TID_cur from the DB and A = h(ID_U ‖ x' ‖ v) for a guessed x'")
    host, port = door("CSE-101")
    replies = await exchange(
        host, port, [forge_M1(TID, VICTIM, "CSE-101", load_card(cfg.card_path(VICTIM)).Q_AS, A_guess).to_wire()]
    )
    reason = replies[0].get("reason", "closed") if replies else "closed"
    rejected = bool(replies) and replies[0]["type"] == "REJECT"
    v.add(
        "insider reads AS database",
        rejected and not leaked and not sensitive_cols,
        f"DB has no PW/RPW/A; forging with DB data → {reason}",
    )


if __name__ == "__main__":
    run(attack)
