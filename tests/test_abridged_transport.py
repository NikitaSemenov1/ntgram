from __future__ import annotations

import asyncio

import pytest

from ntgram.gateway.transport.abridged import (
    ABRIDGED_QUICK_ACK_MARKER,
    compute_quick_ack_token,
    encode_abridged_packet,
    encode_abridged_quick_ack_token,
    encode_transport_error,
)
from ntgram.gateway.transport.abridged import read_abridged_marker, read_abridged_packet
from ntgram.gateway.transport.abridged import AbridgedProtocolError


def test_abridged_short_frame() -> None:
    payload = b"\x00\x00\x00\x00" * 2
    frame = encode_abridged_packet(payload)
    assert frame[0] == 2
    assert frame[1:] == payload


def test_abridged_long_frame() -> None:
    payload = b"\x00\x00\x00\x00" * 200
    frame = encode_abridged_packet(payload)
    assert frame[0] == 0x7F
    assert int.from_bytes(frame[1:4], "little") == 200
    assert frame[4:] == payload


def test_abridged_boundary_126_words() -> None:
    payload = b"\x00\x00\x00\x00" * 126
    frame = encode_abridged_packet(payload)
    assert frame[0] == 126
    assert frame[1:] == payload


def test_abridged_boundary_127_words() -> None:
    payload = b"\x00\x00\x00\x00" * 127
    frame = encode_abridged_packet(payload)
    assert frame[0] == 0x7F
    assert int.from_bytes(frame[1:4], "little") == 127
    assert frame[4:] == payload


@pytest.mark.asyncio
async def test_abridged_marker_and_packet_read() -> None:
    reader = asyncio.StreamReader()
    payload = b"\x01\x00\x00\x00" * 2
    reader.feed_data(bytes([0xEF]) + bytes([2]) + payload)
    reader.feed_eof()
    assert await read_abridged_marker(reader) == 0xEF
    frame = await read_abridged_packet(reader)
    assert frame.payload == payload
    assert frame.quick_ack_requested is False


@pytest.mark.asyncio
async def test_abridged_quick_ack_header_is_decoded() -> None:
    reader = asyncio.StreamReader()
    payload = b"\x01\x00\x00\x00" * 3
    reader.feed_data(bytes([0x80 + 3]) + payload)
    reader.feed_eof()
    frame = await read_abridged_packet(reader)
    assert frame.quick_ack_requested is True
    assert frame.payload == payload


@pytest.mark.asyncio
async def test_abridged_extended_quick_ack_header_is_decoded() -> None:
    reader = asyncio.StreamReader()
    payload = b"\x00\x00\x00\x00" * 200
    reader.feed_data(bytes([ABRIDGED_QUICK_ACK_MARKER]) + (200).to_bytes(3, "little") + payload)
    reader.feed_eof()
    frame = await read_abridged_packet(reader)
    assert frame.quick_ack_requested is True
    assert frame.payload == payload


def test_quick_ack_token_encoding() -> None:
    payload = b"\x01\x02\x03\x04" * 4
    token = compute_quick_ack_token(payload)
    encoded = encode_abridged_quick_ack_token(token)
    assert len(encoded) == 4
    assert (int.from_bytes(encoded, "big") & 0x80000000) != 0


def test_transport_error_encoding() -> None:
    encoded = encode_transport_error(404)
    assert int.from_bytes(encoded, "little", signed=True) == -404


def test_transport_error_encoding_rejects_non_positive() -> None:
    with pytest.raises(AbridgedProtocolError):
        encode_transport_error(0)
