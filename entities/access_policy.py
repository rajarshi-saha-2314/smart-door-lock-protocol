"""Role + timetable authorization policy (Section 5), evaluated by the AS at Step 4.6."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from pathlib import Path

from common.protocol import ALLOW, DENY

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _hm(text: str) -> time:
    hh, mm = text.split(":")
    return time(int(hh), int(mm))


@dataclass(frozen=True)
class Decision:
    decision: str  # ALLOW | DENY
    reason: str


class AccessPolicy:
    def __init__(self, data: dict) -> None:
        self.rooms: list[str] = data["rooms"]
        self.roles: dict[str, dict] = data["roles"]
        self.timetable: list[dict] = data["timetable"]

    @classmethod
    def load(cls, path: Path) -> AccessPolicy:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def class_rooms(self, class_id: str | None) -> set[str]:
        return {s["room"] for s in self.timetable if s["class"] == class_id}

    def evaluate(self, ID_U: str, role: str, class_id: str | None, ID_DL: str, now: datetime) -> Decision:
        if ID_DL not in self.rooms:
            return Decision(DENY, f"{ID_DL} is not a room in the access policy")
        rule = self.roles.get(role)
        if rule is None:
            return Decision(DENY, f"unknown role {role!r}")

        if rule["doors"] == "class" and ID_DL not in self.class_rooms(class_id):
            return Decision(DENY, f"{role} {ID_U} ({class_id}) has no class in {ID_DL}")

        hours = rule["hours"]
        if hours == "any":
            return Decision(ALLOW, f"{role}: any door, any time")
        if isinstance(hours, dict):
            start, end = _hm(hours["start"]), _hm(hours["end"])
            if start <= now.time() <= end:
                return Decision(ALLOW, f"{role}: within {hours['start']}-{hours['end']}")
            return Decision(DENY, f"{role}: {now:%a %H:%M} is outside {hours['start']}-{hours['end']}")
        if hours == "timetable":
            grace = timedelta(minutes=int(rule.get("grace_minutes", 0)))
            day = DAYS[now.weekday()]
            for slot in self.timetable:
                if slot["class"] != class_id or slot["room"] != ID_DL or slot["day"] != day:
                    continue
                start = datetime.combine(now.date(), _hm(slot["start"])) - grace
                end = datetime.combine(now.date(), _hm(slot["end"])) + grace
                if start <= now <= end:
                    g = f" ±{rule.get('grace_minutes', 0)}min" if grace else ""
                    return Decision(ALLOW, f"{role}: {class_id} slot {day} {slot['start']}-{slot['end']}{g} in {ID_DL}")
            return Decision(DENY, f"{role}: {now:%a %H:%M} is outside {class_id}'s timetable for {ID_DL}")
        return Decision(DENY, f"malformed policy for role {role!r}")
