from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

MAX_SEEN_MSG_IDS = 8192


@dataclass(slots=True)
class ReplayWindow:
    """Bounded replay-protection window for inbound encrypted messages."""

    last_msg_id: int = 0
    seen_msg_ids: set[int] = field(default_factory=set)
    seen_msg_id_order: deque[int] = field(default_factory=deque)

    def touch(self, msg_id: int) -> bool:
        """Return True if msg_id is fresh, False on replay/old."""
        if msg_id in self.seen_msg_ids:
            return False
        if self.last_msg_id and msg_id <= self.last_msg_id:
            return False
        self.seen_msg_ids.add(msg_id)
        self.seen_msg_id_order.append(msg_id)
        while len(self.seen_msg_id_order) > MAX_SEEN_MSG_IDS:
            old = self.seen_msg_id_order.popleft()
            self.seen_msg_ids.discard(old)
        self.last_msg_id = msg_id
        return True
