from __future__ import annotations

from ntgram.errors import RpcFailure


def assert_meta_ok(meta: object) -> None:
    if getattr(meta, "ok", False):
        return
    err = getattr(meta, "error", None)
    code = getattr(err, "code", 500)
    msg = getattr(err, "message", "INTERNAL_SERVER_ERROR")
    raise RpcFailure(code, msg)


def int64_from_tl_long(value: object) -> int:
    """Convert a TL long (unsigned 64-bit on the wire) to protobuf signed int64."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 0
    v &= (1 << 64) - 1
    if v >= 1 << 63:
        return v - (1 << 64)
    return v


def phone_from_payload(payload: dict) -> str:
    """Extract the phone number from a TL API payload."""
    phone = payload.get("phone_number") or payload.get("phone")
    if not isinstance(phone, str) or not phone:
        raise RpcFailure(400, "PHONE_NUMBER_INVALID")
    return phone
