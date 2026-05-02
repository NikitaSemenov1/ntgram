from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class MessageParticipant:
    """One row in `NewMessageEvent.participants`."""

    user_id: int
    user_message_box_id: int
    pts: int
    dialog_id: int
    peer_id: int
    is_group: bool


@dataclass(slots=True, frozen=True)
class NewMessageEvent:
    """A new message that needs to be fanned out to other participants."""

    actor_user_id: int
    actor_auth_key_id: int
    from_user_id: int
    text: str
    date: int
    participants: tuple[MessageParticipant, ...]


@dataclass(slots=True, frozen=True)
class ReadOutboxReceipt:
    """One row in `ReadOutboxEvent.receipts`."""

    sender_user_id: int
    sender_dialog_id: int
    max_outbox_id: int
    pts: int


@dataclass(slots=True, frozen=True)
class ReadOutboxEvent:
    """Read receipts for the actor's outbox in another user's dialog."""

    actor_user_id: int
    receipts: tuple[ReadOutboxReceipt, ...]


@dataclass(slots=True, frozen=True)
class PresenceEvent:
    """Online/offline transition for a user."""

    user_id: int
    online: bool


FanoutEvent = NewMessageEvent | ReadOutboxEvent | PresenceEvent


@dataclass(slots=True, frozen=True)
class RouteOutcome:
    """Bridge call result split into TL payload and optional fanout event."""

    tl_payload: dict[str, Any]
    fanout: FanoutEvent | None = None

    @classmethod
    def tl_only(cls, tl_payload: dict[str, Any]) -> RouteOutcome:
        """Convenience for handlers that have no side-effects."""
        return cls(tl_payload=tl_payload, fanout=None)
