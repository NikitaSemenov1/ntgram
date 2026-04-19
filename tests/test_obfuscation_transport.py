from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ntgram.gateway.transport.obfuscation import (
    INIT_PAYLOAD_LEN,
    OBFUSCATED_ABRIDGED_PROTOCOL_ID,
    ObfuscationProtocolError,
    parse_obfuscation_init,
)


def _make_plain_init_payload() -> bytes:
    payload = bytearray(range(1, INIT_PAYLOAD_LEN + 1))
    payload[0:4] = b"\x01\x02\x03\x04"
    payload[4:8] = b"\x10\x11\x12\x13"
    payload[56:60] = OBFUSCATED_ABRIDGED_PROTOCOL_ID
    payload[60:64] = b"\x01\x00\x00\x00"
    return bytes(payload)


def _make_obfuscated_wire_init(plain_init_payload: bytes) -> tuple[bytes, object]:
    encryptor = Cipher(
        algorithms.AES(plain_init_payload[8:40]),
        modes.CTR(plain_init_payload[40:56]),
    ).encryptor()
    encrypted_init = encryptor.update(plain_init_payload)
    final_init = bytearray(plain_init_payload)
    final_init[56:64] = encrypted_init[56:64]
    return bytes(final_init), encryptor


def test_parse_obfuscation_init_derives_stream_ciphers() -> None:
    plain_init = _make_plain_init_payload()
    wire_init, client_encryptor = _make_obfuscated_wire_init(plain_init)

    session = parse_obfuscation_init(wire_init)
    inbound_plaintext = b"\x11\x22\x33\x44" * 8
    inbound_ciphertext = client_encryptor.update(inbound_plaintext)
    assert session.decrypt(inbound_ciphertext) == inbound_plaintext

    reversed_plain = plain_init[::-1]
    client_decryptor = Cipher(
        algorithms.AES(reversed_plain[8:40]),
        modes.CTR(reversed_plain[40:56]),
    ).decryptor()
    outbound_plaintext = b"\xaa\xbb\xcc\xdd" * 6
    outbound_ciphertext = session.encrypt(outbound_plaintext)
    assert client_decryptor.update(outbound_ciphertext) == outbound_plaintext


def test_parse_obfuscation_init_rejects_short_payload() -> None:
    with pytest.raises(ObfuscationProtocolError):
        parse_obfuscation_init(b"\x00" * (INIT_PAYLOAD_LEN - 1))


def test_parse_obfuscation_init_rejects_forbidden_plain_prefix() -> None:
    plain_init = _make_plain_init_payload()
    forbidden_init = b"HEAD" + plain_init[4:]
    wire_init, _ = _make_obfuscated_wire_init(forbidden_init)
    with pytest.raises(ObfuscationProtocolError):
        parse_obfuscation_init(wire_init)
