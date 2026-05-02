from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class MtprotoSessionCounters:
    """Inbound/outbound content-message counters for one MTProto session_id."""

    inbound_content_count: int = 0
    outbound_content_count: int = 0


@dataclass(slots=True)
class SessionCounterStore:
    """Per-session-id counter map with validation/issuance helpers."""

    auth_key_id: int = 0
    counters: dict[int, MtprotoSessionCounters] = field(default_factory=dict)

    def for_session(self, session_id: int) -> MtprotoSessionCounters:
        if session_id not in self.counters:
            self.counters[session_id] = MtprotoSessionCounters()
        return self.counters[session_id]

    def forget_session(self, session_id: int) -> None:
        self.counters.pop(session_id, None)

    def validate_inbound(
        self, session_id: int, seq_no: int, *, content_related: bool,
    ) -> int | None:
        """Return MTProto bad_msg_notification code or None when valid."""
        c = self.for_session(session_id)
        expected = c.inbound_content_count * 2 + (1 if content_related else 0)

        if content_related and (seq_no & 1) == 0:
            logger.warning(
                "bad seq_no parity (content must be odd): "
                "auth_key_id=%s session_id=%s seq_no=%s",
                self.auth_key_id, session_id, seq_no,
            )
            return 35
        if not content_related and (seq_no & 1) == 1:
            logger.warning(
                "bad seq_no parity (non-content must be even): "
                "auth_key_id=%s session_id=%s seq_no=%s",
                self.auth_key_id, session_id, seq_no,
            )
            return 34

        if content_related:
            if seq_no < expected:
                logger.warning(
                    "content seq too low: auth_key_id=%s session_id=%s "
                    "seq_no=%s expected_min=%s",
                    self.auth_key_id, session_id, seq_no, expected,
                )
                return 32
            c.inbound_content_count = (seq_no + 1) // 2
            return None

        if seq_no < expected:
            logger.warning(
                "non-content seq too low: auth_key_id=%s session_id=%s "
                "seq_no=%s expected_min=%s",
                self.auth_key_id, session_id, seq_no, expected,
            )
            return 32
        return None

    def next_outbound(self, session_id: int, *, content_related: bool) -> int:
        """Generate and advance the outbound seq_no for session_id."""
        c = self.for_session(session_id)
        seq_no = c.outbound_content_count * 2 + (1 if content_related else 0)
        if content_related:
            c.outbound_content_count += 1
        return seq_no
