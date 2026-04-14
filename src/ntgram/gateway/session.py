from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SessionState:
    auth_key_id: int
    session_id: int
    user_id: int | None = None
    pts: int = 0
    qts: int = 0
    seq: int = 0
    pending: dict[int, Any] = field(default_factory=dict)

    def touch_pts(self) -> int:
        self.pts += 1
        return self.pts
