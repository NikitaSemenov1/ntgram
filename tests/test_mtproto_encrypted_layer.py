from __future__ import annotations

import time

import pytest

from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    decode_bind_temp_auth_key_inner_message,
    decode_encrypted_message,
    encode_bind_temp_auth_key_inner_message,
    encode_encrypted_message,
)
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.tl.codec import encode_tl_object


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
    client_session_id = 555
    encoded = encode_encrypted_message(session, client_session_id, msg_id, 1, data)
    decoded_session_id, decoded_msg_id, decoded_seq_no, decoded_data = decode_encrypted_message(session, encoded)
    assert decoded_session_id == client_session_id
    assert session.session_id == client_session_id
    assert decoded_msg_id == msg_id
    assert decoded_seq_no == 1
    assert decoded_data == data


def test_encrypted_message_replay_is_rejected() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=102, new_nonce=3333, server_nonce=4444)
    msg_id = _valid_msg_id()
    encoded = encode_encrypted_message(session, 777, msg_id, 1, b"payload!")
    decode_encrypted_message(session, encoded)
    with pytest.raises(EncryptedLayerError):
        decode_encrypted_message(session, encoded)


def test_bad_server_salt_includes_plaintext_session_id() -> None:
    """bad_server_salt must carry inbound session_id for correct encrypted error reply."""
    store = SessionStore()
    session = _make_session(store, session_id=104, new_nonce=7777, server_nonce=8888)
    msg_id = _valid_msg_id()
    client_mtproto_session = 0xABCDEF0123456789
    encoded = encode_encrypted_message(
        session, client_mtproto_session, msg_id, 1, b"payload!",
    )
    session.server_salt ^= 0xFFFFFFFFFFFFFFFF
    with pytest.raises(EncryptedLayerError) as excinfo:
        decode_encrypted_message(session, encoded)
    err = excinfo.value
    assert err.error_code == 48
    assert err.context_session_id == client_mtproto_session


def test_decode_accepts_future_salt_registered_via_get_future_salts() -> None:
    """Inbound header salt may match a previously issued future_salt window."""
    store = SessionStore()
    session = _make_session(store, session_id=105, new_nonce=1212, server_nonce=3434)
    msg_id = _valid_msg_id()
    client_mtproto_session = 999
    salt_used = session.server_salt
    encoded = encode_encrypted_message(
        session, client_mtproto_session, msg_id, 1, b"future-salt-body",
    )
    session.server_salt ^= 0xFFFFFFFFFFFFFFFF
    now = int(time.time())
    session.register_future_salt_entries([(now - 10, now + 3600, salt_used)])
    sid, mid, seq, body = decode_encrypted_message(session, encoded)
    assert sid == client_mtproto_session
    assert mid == msg_id
    assert body == b"future-salt-body"


def test_bind_temp_auth_key_inner_message_roundtrip() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=103, new_nonce=5555, server_nonce=6666)
    msg_id = _valid_msg_id()
    body = encode_tl_object(
        "bind_auth_key_inner",
        {
            "nonce": 1,
            "temp_auth_key_id": 2,
            "perm_auth_key_id": session.auth_key_id,
            "temp_session_id": 3,
            "expires_at": int(time.time()) + 60,
        },
    )

    encoded = encode_bind_temp_auth_key_inner_message(
        session,
        msg_id=msg_id,
        message_data=body,
        random_bytes=b"\x11" * 16,
    )
    decoded_msg_id, decoded_seq_no, decoded_body = (
        decode_bind_temp_auth_key_inner_message(
            session,
            encoded,
            expected_msg_id=msg_id,
        )
    )

    assert decoded_msg_id == msg_id
    assert decoded_seq_no == 0
    assert decoded_body == body
