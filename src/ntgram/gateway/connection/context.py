from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ntgram.gateway.push_registry import PushSlot


@dataclass(slots=True)
class ConnectionContext:
    """Mutable per-connection state."""

    peer: object
    handshake_session_id: int
    transport_encrypt: Callable[[bytes], bytes] | None = None
    transport_decrypt: Callable[[bytes], bytes] | None = None
    current_auth_key_id: int = 0
    current_session_id: int = 0
    current_user_id: int | None = None
    push_slot: PushSlot | None = None
