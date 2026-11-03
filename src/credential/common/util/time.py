from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class TimeWrapper:
    time: datetime
    time_str: str = ""

    @classmethod
    def new(cls, t: datetime) -> TimeWrapper:
        return cls(time=t)

    @classmethod
    def parse(cls, time_str: str) -> TimeWrapper:
        tw = cls(time=datetime.now(timezone.utc))
        tw._parse(time_str)
        return tw

    def _parse(self, time_str: str) -> None:
        try:
            t = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except ValueError:
            t = datetime.fromisoformat(time_str + "+00:00")
        self.time = t
        self.time_str = time_str

    def format_to_string(self) -> str:
        if self.time_str:
            return self.time_str
        return self.time.isoformat().replace("+00:00", "Z")

    def to_json(self) -> str:
        return json.dumps(self.format_to_string())
