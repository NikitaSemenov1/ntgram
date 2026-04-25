from __future__ import annotations

import hashlib
import struct
from asyncio import StreamReader, StreamWriter
from collections.abc import Callable
from dataclasses import dataclass

ABRIDGED_MARKER = 0xEF
ABRIDGED_EXTENDED_LEN_MARKER = 0x7F
ABRIDGED_QUICK_ACK_MARKER = 0xFF
MAX_ABRIDGED_WORDS = 1 << 20
TRANSPORT_ERROR_BAD_PACKET = 404
TRANSPORT_ERROR_BAD_LENGTH = 429
TRANSPORT_ERROR_INVALID_STATE = 444


class AbridgedProtocolError(ValueError):
    """Raised when abridged transport framing is invalid."""


@dataclass(slots=True, frozen=True)
class AbridgedFrame:
    payload: bytes
    quick_ack_requested: bool


async def read_abridged_marker(
    reader: StreamReader,
    decrypt: Callable[[bytes], bytes] | None = None,
) -> int:
    marker = await reader.readexactly(1)
    if decrypt is not None:
        marker = decrypt(marker)
    value = marker[0]
    if value != ABRIDGED_MARKER:
        raise AbridgedProtocolError(f"invalid abridged marker: {value:#x}")
    return value


async def read_abridged_packet(
    reader: StreamReader,
    decrypt: Callable[[bytes], bytes] | None = None,
) -> AbridgedFrame:
    length_byte = await reader.readexactly(1)
    if decrypt is not None:
        length_byte = decrypt(length_byte)
    first = length_byte[0]
    quick_ack_requested = False
    if first == ABRIDGED_EXTENDED_LEN_MARKER:
        raw = await reader.readexactly(3)
        if decrypt is not None:
            raw = decrypt(raw)
        word_len = int.from_bytes(raw, "little")
    elif first == ABRIDGED_QUICK_ACK_MARKER:
        quick_ack_requested = True
        raw = await reader.readexactly(3)
        if decrypt is not None:
            raw = decrypt(raw)
        word_len = int.from_bytes(raw, "little")
    else:
        quick_ack_requested = (first & 0x80) != 0
        word_len = first & 0x7F

    if word_len <= 0 or word_len > MAX_ABRIDGED_WORDS:
        raise AbridgedProtocolError(f"invalid abridged length: {word_len}")

    payload = await reader.readexactly(word_len * 4)
    if decrypt is not None:
        payload = decrypt(payload)
    return AbridgedFrame(payload=payload, quick_ack_requested=quick_ack_requested)


def encode_abridged_packet(payload: bytes, quick_ack_requested: bool = False) -> bytes:
    if len(payload) % 4 != 0:
        raise AbridgedProtocolError("payload must be 4-byte aligned for abridged framing")

    words = len(payload) // 4
    if words <= 0 or words > MAX_ABRIDGED_WORDS:
        raise AbridgedProtocolError(f"payload words out of range: {words}")
    if words < ABRIDGED_EXTENDED_LEN_MARKER:
        header = words + (0x80 if quick_ack_requested else 0)
        return bytes([header]) + payload
    marker = ABRIDGED_QUICK_ACK_MARKER if quick_ack_requested else ABRIDGED_EXTENDED_LEN_MARKER
    return bytes([marker]) + struct.pack("<I", words)[:3] + payload


def compute_quick_ack_token(payload: bytes, auth_key: bytes | None = None, x: int = 0) -> int:
    """Compute quick-ack token for standalone 4-byte response.

    MTProto quick ack uses the first 32 bits of the same SHA-256 input family as
    msg_key, then sets the MSB of the resulting little-endian uint32.
    """
    if auth_key is not None:
        if len(payload) < 24:
            raise AbridgedProtocolError("encrypted payload too short for quick ack")
        digest = hashlib.sha256(auth_key[88 + x : 88 + x + 32] + payload[24:]).digest()
    else:
        # Compatibility fallback for tests/non-encrypted callers.
        digest = hashlib.sha256(payload).digest()
    token = int.from_bytes(digest[:4], "little")
    return token | 0x80000000


def encode_abridged_quick_ack_token(token: int) -> bytes:
    # Abridged transport uses byte-swapped token on wire.
    return struct.pack(">I", token | 0x80000000)


def encode_transport_error(code: int) -> bytes:
    if code <= 0:
        raise AbridgedProtocolError("transport error code must be positive")
    return struct.pack("<i", -code)


async def write_abridged_packet(
    writer: StreamWriter,
    payload: bytes,
    encrypt: Callable[[bytes], bytes] | None = None,
) -> None:
    frame = encode_abridged_packet(payload)
    if encrypt is not None:
        frame = encrypt(frame)
    writer.write(frame)
    await writer.drain()


async def write_abridged_quick_ack(
    writer: StreamWriter,
    token: int,
    encrypt: Callable[[bytes], bytes] | None = None,
) -> None:
    frame = encode_abridged_quick_ack_token(token)
    if encrypt is not None:
        frame = encrypt(frame)
    writer.write(frame)
    await writer.drain()


async def write_transport_error(
    writer: StreamWriter,
    code: int,
    encrypt: Callable[[bytes], bytes] | None = None,
) -> None:
    frame = encode_transport_error(code)
    if encrypt is not None:
        frame = encrypt(frame)
    writer.write(frame)
    await writer.drain()
