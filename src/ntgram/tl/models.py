from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class TlRequest:
    constructor_id: int
    constructor: str
    req_msg_id: int
    auth_key_id: int
    session_id: int
    message_id: int | None = None
    seq_no: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class TlResponse:
    req_msg_id: int
    result: dict[str, Any]
    error_code: int | None = None
    error_message: str | None = None


@dataclass(slots=True, frozen=True)
class TlPayloadEntry:
    key: str
    value: Any


@dataclass(slots=True, frozen=True)
class TlObject:
    constructor_id: int
    constructor: str
    payload: dict[str, Any] = field(default_factory=dict)
