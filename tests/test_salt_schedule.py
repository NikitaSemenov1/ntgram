from __future__ import annotations

import logging
from unittest.mock import patch

from ntgram.gateway.mtproto.salt_schedule import (
    PREVIOUS_SALTS_LIMIT,
    SERVER_SALT_GRACE_WINDOW_SEC,
    SERVER_SALT_INTERVAL_SEC,
    SaltSchedule,
)


def test_rotate_logs_random_fallback_when_no_future_candidates(
    caplog,
) -> None:
    """When the window expires and no scheduled future salt fits ``now``,
    rotation falls back to a random salt and emits a diagnostic INFO log."""
    schedule = SaltSchedule(server_salt=0x1111, server_salt_valid_until=100)
    with caplog.at_level(logging.INFO, logger="ntgram.gateway.mtproto.salt_schedule"):
        rotated = schedule.rotate_if_needed(now=200)
    assert rotated is True
    assert schedule.server_salt != 0x1111
    record = next(r for r in caplog.records if "server salt rotated" in r.message)
    assert "source=random_fallback" in record.getMessage()
    assert "previous_salt=4369" in record.getMessage()  # 0x1111
    assert f"new_salt={schedule.server_salt}" in record.getMessage()


def test_rotate_logs_scheduled_future_salt_promotion(caplog) -> None:
    """When a registered future salt covers ``now``, rotation promotes it
    instead of generating a random value, with a corresponding INFO log."""
    schedule = SaltSchedule(server_salt=0x2222, server_salt_valid_until=100)
    schedule.accepted_future_salts[0xCAFE] = (150, 150 + SERVER_SALT_INTERVAL_SEC)
    with caplog.at_level(logging.INFO, logger="ntgram.gateway.mtproto.salt_schedule"):
        rotated = schedule.rotate_if_needed(now=200)
    assert rotated is True
    assert schedule.server_salt == 0xCAFE
    record = next(r for r in caplog.records if "server salt rotated" in r.message)
    assert "source=scheduled_future_salt" in record.getMessage()
    assert "new_salt=51966" in record.getMessage()  # 0xCAFE


def test_rotate_no_op_does_not_log(caplog) -> None:
    """Rotation must be silent when the current salt's window is still valid."""
    schedule = SaltSchedule(server_salt=0x3333, server_salt_valid_until=10_000)
    with caplog.at_level(logging.INFO, logger="ntgram.gateway.mtproto.salt_schedule"):
        rotated = schedule.rotate_if_needed(now=500)
    assert rotated is False
    assert schedule.server_salt == 0x3333
    assert not any("server salt rotated" in r.message for r in caplog.records)


def test_previous_salt_accepted_during_grace_window() -> None:
    """A salt that was current immediately before rotation must still be
    accepted for ``SERVER_SALT_GRACE_WINDOW_SEC`` seconds (REQ-SALT-08)."""
    prev_salt = 0xAA55
    schedule = SaltSchedule(server_salt=prev_salt, server_salt_valid_until=100)
    now = 200
    with patch("time.time", return_value=now):
        schedule.rotate_if_needed(now=now)
    assert prev_salt in schedule.previous_salts
    assert schedule.previous_salts[prev_salt] == now + SERVER_SALT_GRACE_WINDOW_SEC
    # Inside grace window, the prev salt is still accepted by validate-path.
    with patch("time.time", return_value=now + 100):
        assert schedule.is_accepted(prev_salt) is True
    # And the brand-new current salt is accepted too.
    with patch("time.time", return_value=now + 100):
        assert schedule.is_accepted(schedule.server_salt) is True


def test_previous_salt_rejected_after_grace_window() -> None:
    """Once the grace window expires the prev salt must no longer be accepted
    and is lazily evicted from ``previous_salts`` to avoid unbounded growth."""
    prev_salt = 0xBEEF
    schedule = SaltSchedule(server_salt=prev_salt, server_salt_valid_until=100)
    rotate_at = 200
    with patch("time.time", return_value=rotate_at):
        schedule.rotate_if_needed(now=rotate_at)
    assert prev_salt in schedule.previous_salts
    way_after = rotate_at + SERVER_SALT_GRACE_WINDOW_SEC + 1
    with patch("time.time", return_value=way_after):
        assert schedule.is_accepted(prev_salt) is False
    # Lazy GC: the expired entry is dropped on the failed check.
    assert prev_salt not in schedule.previous_salts


def test_previous_salts_bounded_to_limit() -> None:
    """When more rotations happen within one grace window than the limit, the
    oldest entries are evicted to keep ``previous_salts`` bounded."""
    schedule = SaltSchedule(server_salt=1, server_salt_valid_until=100)
    # All rotations happen at the same ``now`` so every prev salt is still in
    # the grace window when the next rotation pushes a new one in. This
    # forces the size-based eviction loop instead of the time-based one.
    rotate_at = 200
    for _ in range(PREVIOUS_SALTS_LIMIT + 2):
        schedule.server_salt_valid_until = rotate_at - 1
        with patch("time.time", return_value=rotate_at):
            schedule.rotate_if_needed(now=rotate_at)
    assert len(schedule.previous_salts) == PREVIOUS_SALTS_LIMIT


def test_rotate_does_not_record_zero_previous_salt() -> None:
    """A freshly-constructed schedule with ``server_salt=0`` (no handshake yet)
    must not populate ``previous_salts`` with the placeholder zero on rotate."""
    schedule = SaltSchedule(server_salt=0, server_salt_valid_until=100)
    with patch("time.time", return_value=200):
        schedule.rotate_if_needed(now=200)
    assert 0 not in schedule.previous_salts
    assert schedule.previous_salts == {}


def test_rotate_log_includes_previous_salts_kept_count(caplog) -> None:
    """The diagnostic INFO log must surface how many prev salts are now kept,
    so operators can confirm the grace ring is populated."""
    schedule = SaltSchedule(server_salt=0xCAFEBABE, server_salt_valid_until=100)
    with caplog.at_level(logging.INFO, logger="ntgram.gateway.mtproto.salt_schedule"):
        with patch("time.time", return_value=200):
            schedule.rotate_if_needed(now=200)
    record = next(r for r in caplog.records if "server salt rotated" in r.message)
    assert "previous_salts_kept=1" in record.getMessage()
