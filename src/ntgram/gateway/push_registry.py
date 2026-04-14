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


class PushRegistry:
    """Maps user_id -> set of active PushSlots (one per TCP connection)."""

    def __init__(self) -> None:
        self._by_user: dict[int, set[PushSlot]] = {}

    def register(self, slot: PushSlot) -> None:
        self._by_user.setdefault(slot.user_id, set()).add(slot)
        logger.debug(
            "push slot registered: user=%d auth_key=%d",
            slot.user_id, slot.auth_key_id,
        )

    def unregister(self, slot: PushSlot) -> None:
        slots = self._by_user.get(slot.user_id)
        if slots is not None:
            slots.discard(slot)
            if not slots:
                del self._by_user[slot.user_id]
        logger.debug(
            "push slot unregistered: user=%d auth_key=%d",
            slot.user_id, slot.auth_key_id,
        )

    def get_slots(self, user_id: int) -> set[PushSlot]:
        return self._by_user.get(user_id, set())

    async def push_to_user(
        self, user_id: int, update: dict,
        *, exclude_auth_key_id: int = 0,
    ) -> int:
        """Push update to all connections of a user.

        Returns count of slots notified.
        """
        slots = self._by_user.get(user_id, set())
        count = 0
        for slot in slots:
            if slot.auth_key_id == exclude_auth_key_id:
                continue
            try:
                slot.queue.put_nowait(update)
                count += 1
            except asyncio.QueueFull:
                logger.warning(
                    "push queue full for user=%d auth_key=%d, dropping",
                    user_id, slot.auth_key_id,
                )
        return count
