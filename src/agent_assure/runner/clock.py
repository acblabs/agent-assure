from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class DeterministicClock:
    base_time: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

    def at_index(self, index: int) -> datetime:
        if index < 0:
            raise ValueError("clock index must be non-negative")
        return self.base_time + timedelta(seconds=index)

    def iso_at_index(self, index: int) -> str:
        return self.at_index(index).isoformat().replace("+00:00", "Z")
