from __future__ import annotations

import time

import pytest

from ntgram.gateway.mtproto.encrypted_layer import EncryptedLayerError, decode_encrypted_message, encode_encrypted_message
from ntgram.gateway.mtproto.session_store import SessionStore


def _valid_msg_id() -> int:
    base = (int(time.time()) << 32) | 123456
    return base - (base % 4)


def _make_session(store, session_id, new_nonce, server_nonce):
    import secrets
    auth_key = secrets.token_bytes(256)
    return store.complete_handshake(
        session_id=session_id,
        auth_key=auth_key,
        new_nonce=new_nonce,
        server_nonce=server_nonce,
    )


def test_encrypted_message_roundtrip() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=101, new_nonce=1111, server_nonce=2222)
    data = b"\x01\x02\x03\x04" * 8
    msg_id = _valid_msg_id()
    encoded = encode_encrypted_message(session, session.session_id, msg_id, 1, data)
    decoded_session_id, decoded_msg_id, decoded_seq_no, decoded_data = decode_encrypted_message(session, encoded)
    assert decoded_session_id == session.session_id
    assert decoded_msg_id == msg_id
    assert decoded_seq_no == 1
    assert decoded_data == data


def test_encrypted_message_replay_is_rejected() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=102, new_nonce=3333, server_nonce=4444)
    msg_id = _valid_msg_id()
    encoded = encode_encrypted_message(session, session.session_id, msg_id, 1, b"payload")
    decode_encrypted_message(session, encoded)
    with pytest.raises(EncryptedLayerError):
        decode_encrypted_message(session, encoded)
