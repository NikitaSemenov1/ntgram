"""Full auth key exchange integration test.

Simulates the client side of the MTProto handshake:
  1. req_pq_multi -> resPQ (receive pq, fingerprints)
  2. PQ factorization (client), build p_q_inner_data_dc, RSA_PAD encrypt
  3. req_DH_params -> server_DH_params_ok (receive encrypted_answer)
  4. Decrypt server_DH_inner_data, get g, dh_prime, g_a
  5. Generate client DH pair (b, g_b), encrypt client_DH_inner_data
  6. set_client_DH_params -> dh_gen_ok
  7. Verify auth_key derivation matches
"""
from __future__ import annotations

import hashlib
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ntgram.gateway.mtproto.auth_handshake import AuthHandshakeProcessor
from ntgram.gateway.mtproto.dh_params import DH_PRIME
from ntgram.gateway.mtproto.encrypted_layer import (
    _aes_ige_encrypt_blockwise,
)
from ntgram.gateway.mtproto.rsa_keys import load_rsa_keypair
from ntgram.gateway.mtproto.rsa_pad import rsa_pad_encrypt
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.mtproto.tmp_aes import compute_tmp_aes_key_iv, tmp_aes_decrypt
from ntgram.tl.codec import encode_tl_object
from ntgram.tl.models import TlRequest
from ntgram.tl.serializer import _Reader, deserialize_from_reader
from ntgram.tl.registry import default_schema_registry


def _write_rsa_pair(tmp_path) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(private_path), str(public_path)


def _int_to_tl_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def test_full_dh_handshake(tmp_path) -> None:
    """Full end-to-end auth key exchange with real RSA + DH crypto."""
    sessions = SessionStore()
    private_path, public_path = _write_rsa_pair(tmp_path)
    rsa_keys = load_rsa_keypair(private_path, public_path)
    processor = AuthHandshakeProcessor(sessions, rsa_keys)
    registry = default_schema_registry()
    session_id = 9001

    # ---- Step 1: req_pq_multi ----
    client_nonce = secrets.randbits(128)

    req_pq = TlRequest(
        constructor_id=0,
        constructor="req_pq_multi",
        req_msg_id=1,
        auth_key_id=0,
        session_id=session_id,
        payload={"nonce": client_nonce},
    )
    res = processor.handle(req_pq)
    assert res.handled
    assert res.response is not None
    result = res.response.result
    assert result["constructor"] == "resPQ"
    assert result["nonce"] == client_nonce

    server_nonce = result["server_nonce"]
    pq_bytes = result["pq"]
    fingerprints = result["server_public_key_fingerprints"]
    assert rsa_keys.fingerprint in fingerprints

    pq = int.from_bytes(pq_bytes, "big")
    # Simple factorization for small pq
    p = 0
    for i in range(2, int(pq ** 0.5) + 1):
        if pq % i == 0:
            p = i
            break
    assert p > 0
    q = pq // p
    if p > q:
        p, q = q, p

    # ---- Step 2: Build p_q_inner_data_dc and RSA_PAD encrypt ----
    new_nonce = secrets.randbits(256)

    inner_data = encode_tl_object("p_q_inner_data_dc", {
        "pq": pq_bytes,
        "p": _int_to_tl_bytes(p),
        "q": _int_to_tl_bytes(q),
        "nonce": client_nonce,
        "server_nonce": server_nonce,
        "new_nonce": new_nonce,
        "dc": 1,
    })
    assert len(inner_data) <= 144

    encrypted_data = rsa_pad_encrypt(inner_data, rsa_keys.public_key)
    assert len(encrypted_data) == 256

    # ---- Step 3: req_DH_params ----
    req_dh = TlRequest(
        constructor_id=0,
        constructor="req_DH_params",
        req_msg_id=2,
        auth_key_id=0,
        session_id=session_id,
        payload={
            "nonce": client_nonce,
            "server_nonce": server_nonce,
            "p": _int_to_tl_bytes(p),
            "q": _int_to_tl_bytes(q),
            "public_key_fingerprint": rsa_keys.fingerprint,
            "encrypted_data": encrypted_data,
        },
    )
    res2 = processor.handle(req_dh)
    assert res2.handled
    assert res2.response is not None
    assert res2.response.error_code is None, f"error: {res2.response.error_message}"
    result2 = res2.response.result
    assert result2["constructor"] == "server_DH_params_ok"

    # Decrypt server_DH_inner_data
    encrypted_answer = result2["encrypted_answer"]
    decrypted = tmp_aes_decrypt(encrypted_answer, server_nonce, new_nonce)

    sha1_prefix = decrypted[:20]
    inner_payload = decrypted[20:]

    reader = _Reader(inner_payload)
    name, dh_fields = deserialize_from_reader(reader, registry)
    assert name == "server_DH_inner_data"

    consumed = inner_payload[:reader.offset]
    assert hashlib.sha1(consumed).digest() == sha1_prefix

    g = dh_fields["g"]
    dh_prime = int.from_bytes(dh_fields["dh_prime"], "big")
    g_a = int.from_bytes(dh_fields["g_a"], "big")
    assert dh_prime == DH_PRIME
    assert g == 3
    assert 1 < g_a < dh_prime - 1

    # ---- Step 4: Client generates b, computes g_b ----
    b = secrets.randbelow(dh_prime - 2) + 2
    g_b = pow(g, b, dh_prime)

    client_dh_inner = encode_tl_object("client_DH_inner_data", {
        "nonce": client_nonce,
        "server_nonce": server_nonce,
        "retry_id": 0,
        "g_b": g_b.to_bytes(256, "big"),
    })

    sha1_client = hashlib.sha1(client_dh_inner).digest()
    data_with_hash = sha1_client + client_dh_inner
    pad_len = (16 - (len(data_with_hash) % 16)) % 16
    if pad_len:
        data_with_hash += os.urandom(pad_len)

    tmp_key, tmp_iv = compute_tmp_aes_key_iv(server_nonce, new_nonce)
    client_encrypted = _aes_ige_encrypt_blockwise(data_with_hash, tmp_key, tmp_iv)

    # ---- Step 5: set_client_DH_params ----
    set_dh = TlRequest(
        constructor_id=0,
        constructor="set_client_DH_params",
        req_msg_id=3,
        auth_key_id=0,
        session_id=session_id,
        payload={
            "nonce": client_nonce,
            "server_nonce": server_nonce,
            "encrypted_data": client_encrypted,
        },
    )
    res3 = processor.handle(set_dh)
    assert res3.handled
    assert res3.response is not None
    result3 = res3.response.result
    assert result3["constructor"] == "dh_gen_ok", f"got {result3}"

    # ---- Step 6: Verify auth_key matches ----
    client_auth_key = pow(g_a, b, dh_prime).to_bytes(256, "big")
    server_auth_key_id = SessionStore.make_auth_key_id(client_auth_key)

    session = sessions.get_session(server_auth_key_id)
    assert session is not None, "session not found by auth_key_id"
    assert session.auth_key == client_auth_key

    # Verify new_nonce_hash1
    auth_key_aux_hash = SessionStore.make_auth_key_aux_hash(client_auth_key)
    nn_bytes = new_nonce.to_bytes(32, "little")
    expected_nnh1_data = nn_bytes + bytes([1]) + auth_key_aux_hash.to_bytes(8, "little")
    expected_nnh1 = int.from_bytes(hashlib.sha1(expected_nnh1_data).digest()[-16:], "little")
    assert result3["new_nonce_hash1"] == expected_nnh1


def test_handshake_invalid_order(tmp_path) -> None:
    """set_client_DH_params without prior steps -> error."""
    sessions = SessionStore()
    private_path, public_path = _write_rsa_pair(tmp_path)
    processor = AuthHandshakeProcessor(sessions, load_rsa_keypair(private_path, public_path))

    bad = processor.handle(
        TlRequest(
            constructor_id=0,
            constructor="set_client_DH_params",
            req_msg_id=7,
            auth_key_id=0,
            session_id=42,
            payload={"nonce": 0, "server_nonce": 0, "encrypted_data": b""},
        )
    )
    assert bad.handled
    assert bad.response is not None
    assert bad.response.error_code == 400


def test_unhandled_constructor(tmp_path) -> None:
    """Non-handshake constructor returns handled=False."""
    sessions = SessionStore()
    private_path, public_path = _write_rsa_pair(tmp_path)
    processor = AuthHandshakeProcessor(sessions, load_rsa_keypair(private_path, public_path))

    result = processor.handle(
        TlRequest(
            constructor_id=0,
            constructor="ping",
            req_msg_id=1,
            auth_key_id=0,
            session_id=1,
            payload={"ping_id": 0},
        )
    )
    assert not result.handled
