from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass

import pytest

from ntgram.gateway.connection.context import ConnectionContext
from ntgram.gateway.connection.frame_decoder import FrameDecoder
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    encode_encrypted_message,
)
from ntgram.gateway.mtproto.session_store import (
    AuthSession,
    AuthSessionRepository,
    SessionStore,
)
from ntgram.gateway.transport.abridged import AbridgedFrame
from ntgram.tl.codec import encode_tl_object


@dataclass
class _RecordingRepository(AuthSessionRepository):
    """In-memory repository that records every ``save`` call."""

    _store: dict[int, AuthSession]
    saves: int

    def __init__(self) -> None:
        self._store = {}
        self.saves = 0

    def load(self, auth_key_id: int) -> AuthSession | None:
        return self._store.get(auth_key_id)

    def save(self, session: AuthSession) -> None:
        self._store[session.auth_key_id] = session
        self.saves += 1


def _valid_msg_id() -> int:
    base = (int(time.time()) << 32) | 123456
    return base - (base % 4)


class _NullWriter:
    """Minimal stand-in for ``asyncio.StreamWriter``; never actually written."""

    def write(self, _data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass


def _make_session(store: SessionStore) -> AuthSession:
    auth_key = secrets.token_bytes(256)
    return store.complete_handshake(
        session_id=1,
        auth_key=auth_key,
        new_nonce=12345,
        server_nonce=67890,
    )


def test_mark_server_salt_clean_is_called_on_validate_failure() -> None:
    """When ``decode_encrypted_message`` raises ``bad_server_salt`` after
    rotating the salt schedule, the frame decoder must still persist the
    rotated state (otherwise the new salt is lost on gateway restart)."""
    repo = _RecordingRepository()
    store = SessionStore(repository=repo)
    session = _make_session(store)

    # Encode a real client envelope with the *current* salt, then twist the
    # session so the decode-side validate definitely raises bad_server_salt
    # AND triggers ``rotate_if_needed`` inside ``is_accepted``.
    msg_id = _valid_msg_id()
    payload = encode_encrypted_message(
        session, 0xABCD_1234, msg_id, 1, b"payload!",
    )
    session.salt.server_salt = (session.salt.server_salt ^ 0xFFFF_FFFF_FFFF_FFFF)
    session.salt.server_salt_valid_until = int(time.time()) - 1
    session.salt.server_salt_dirty = False
    saves_before_decode = repo.saves

    decoder = FrameDecoder(store)
    ctx = ConnectionContext(peer=("127.0.0.1", 1234), handshake_session_id=1)
    frame = AbridgedFrame(payload=payload, quick_ack_requested=False)
    writer = _NullWriter()

    with pytest.raises(EncryptedLayerError) as excinfo:
        asyncio.run(
            decoder.decode(ctx=ctx, frame=frame, writer=writer),
        )
    assert excinfo.value.error_code in (48, 16, 17, 18)

    # ``decode_encrypted_message`` rotated salt internally; the finally block
    # in ``FrameDecoder`` must have persisted that mutation.
    assert repo.saves > saves_before_decode, (
        "rotated salt was not persisted on validate-failure; "
        "the next gateway restart would resurrect a stale valid_until"
    )
    # And the session.salt is no longer dirty after the persist.
    assert session.salt.server_salt_dirty is False


def test_mark_server_salt_clean_no_op_when_not_dirty() -> None:
    """When validate fails without any salt mutation (replay path), we must
    NOT redundantly persist; ``mark_server_salt_clean`` is gated by the
    ``server_salt_dirty`` flag, so saves stay at the post-handshake baseline."""
    repo = _RecordingRepository()
    store = SessionStore(repository=repo)
    session = _make_session(store)
    saves_after_handshake = repo.saves

    # First send a normal envelope with the current salt — this succeeds and
    # leaves the salt schedule clean (no rotation, dirty=False). Inner TL has
    # to be a real construct so ``decode_tl_request`` does not raise itself.
    inner_tl = encode_tl_object("ping", {"ping_id": 7})
    msg_id = _valid_msg_id()
    payload = encode_encrypted_message(
        session, 0xABCD_1234, msg_id, 1, inner_tl,
    )
    decoder = FrameDecoder(store)
    ctx = ConnectionContext(peer=("127.0.0.1", 1234), handshake_session_id=1)
    writer = _NullWriter()
    asyncio.run(
        decoder.decode(
            ctx=ctx,
            frame=AbridgedFrame(payload=payload, quick_ack_requested=False),
            writer=writer,
        ),
    )
    saves_after_first_decode = repo.saves

    # Replay the very same envelope — validate raises code 16 (replay) without
    # rotating the salt schedule.
    with pytest.raises(EncryptedLayerError) as excinfo:
        asyncio.run(
            decoder.decode(
                ctx=ctx,
                frame=AbridgedFrame(payload=payload, quick_ack_requested=False),
                writer=writer,
            ),
        )
    assert excinfo.value.error_code == 16
    # Replay path didn't touch the salt schedule, so no extra save fired.
    assert repo.saves == saves_after_first_decode
    # And we never regress below the post-handshake baseline either.
    assert repo.saves >= saves_after_handshake
