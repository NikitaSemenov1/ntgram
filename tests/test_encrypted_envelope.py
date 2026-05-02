from __future__ import annotations

import secrets
import time

import pytest

from ntgram.gateway.mtproto.encrypted_layer import (
    DecodedEnvelope,
    EncryptedLayerError,
    commit_envelope_to_session,
    decode_encrypted_message_pure,
    encode_encrypted_message,
    validate_envelope_against_session,
)
from ntgram.gateway.mtproto.session_store import SessionStore


def _valid_msg_id() -> int:
    base = (int(time.time()) << 32) | 123456
    return base - (base % 4)


def _make_session(store: SessionStore, *, session_id: int) -> object:
    auth_key = secrets.token_bytes(256)
    return store.complete_handshake(
        session_id=session_id,
        auth_key=auth_key,
        new_nonce=0xDEAD,
        server_nonce=0xBEEF,
    )


def test_decode_pure_returns_envelope_for_valid_payload() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=201)
    payload = b"\x01\x02\x03\x04" * 4
    msg_id = _valid_msg_id()
    client_session_id = 0xAA_BB_CC_DD_EE_FF
    encoded = encode_encrypted_message(session, client_session_id, msg_id, 1, payload)

    envelope = decode_encrypted_message_pure(session.auth_key, encoded)

    assert isinstance(envelope, DecodedEnvelope)
    assert envelope.auth_key_id == session.auth_key_id
    assert envelope.server_salt == session.server_salt
    assert envelope.session_id == client_session_id
    assert envelope.msg_id == msg_id
    assert envelope.seq_no == 1
    assert envelope.message_data == payload
    assert 12 <= envelope.padding_len <= 1024


def test_decode_pure_rejects_msg_key_mismatch() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=202)
    msg_id = _valid_msg_id()
    encoded = encode_encrypted_message(session, 777, msg_id, 1, b"payload!")
    tampered = bytearray(encoded)
    tampered[8] ^= 0xFF

    with pytest.raises(EncryptedLayerError, match="msg_key mismatch"):
        decode_encrypted_message_pure(session.auth_key, bytes(tampered))


def test_validate_rejects_unknown_server_salt_with_code_48() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=203)
    msg_id = _valid_msg_id()
    client_session_id = 0xABCD_EF01_2345_6789
    encoded = encode_encrypted_message(session, client_session_id, msg_id, 1, b"payload!")
    envelope = decode_encrypted_message_pure(session.auth_key, encoded)

    session.server_salt ^= 0xFFFF_FFFF_FFFF_FFFF

    with pytest.raises(EncryptedLayerError) as excinfo:
        validate_envelope_against_session(session, envelope)

    err = excinfo.value
    assert err.error_code == 48
    assert err.bad_msg_id == msg_id
    assert err.context_session_id == client_session_id


def test_commit_detects_replay_with_code_16() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=204)
    msg_id = _valid_msg_id()
    encoded = encode_encrypted_message(session, 555, msg_id, 1, b"replay!!")
    envelope = decode_encrypted_message_pure(session.auth_key, encoded)

    validate_envelope_against_session(session, envelope)
    commit_envelope_to_session(session, envelope)

    with pytest.raises(EncryptedLayerError) as excinfo:
        commit_envelope_to_session(session, envelope)

    err = excinfo.value
    assert err.error_code == 16
    assert err.bad_msg_id == msg_id


def test_commit_binds_new_mtproto_session() -> None:
    store = SessionStore()
    session = _make_session(store, session_id=205)

    msg_id = _valid_msg_id()
    new_mtproto_session_id = 0xCAFE_BABE_DEAD_BEEF
    encoded = encode_encrypted_message(
        session, new_mtproto_session_id, msg_id, 1, b"new-bind",
    )
    envelope = decode_encrypted_message_pure(session.auth_key, encoded)

    validate_envelope_against_session(session, envelope)
    commit_envelope_to_session(session, envelope)

    assert session.session_id == new_mtproto_session_id
    assert new_mtproto_session_id in session.known_session_ids
