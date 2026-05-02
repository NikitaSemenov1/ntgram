from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from ntgram.gateway.mtproto.session_store import AuthSession

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PushSlot:
    user_id: int
    auth_key_id: int
    session_id: int
    queue: asyncio.Queue[dict] = field(default_factory=asyncio.Queue)
    session: AuthSession | None = None
    # Subscriber task created by _ensure_push_slot 
    # cancelled on disconnect
    task: asyncio.Task | None = None


class PushRegistry:
    """Maps user_id -> list of active `PushSlot` (one per TCP connection)."""

    def __init__(self) -> None:
        self._by_user: dict[int, list[PushSlot]] = {}

    def register(self, slot: PushSlot) -> None:
        slots = self._by_user.setdefault(slot.user_id, [])
        if slot not in slots:
            slots.append(slot)
        logger.debug(
            "push slot registered: user=%d auth_key=%d",
            slot.user_id, slot.auth_key_id,
        )

    def unregister(self, slot: PushSlot) -> None:
        slots = self._by_user.get(slot.user_id)
        if slots is not None:
            try:
                slots.remove(slot)
            except ValueError:
                pass
            if not slots:
                del self._by_user[slot.user_id]
        logger.debug(
            "push slot unregistered: user=%d auth_key=%d",
            slot.user_id, slot.auth_key_id,
        )

    def get_connections(self, user_id: int) -> list[PushSlot]:
        """Return all active slots for a user (may be empty)."""
        return list(self._by_user.get(user_id, ()))
