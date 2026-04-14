from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class RpcFailure(Exception):
    code: int
    message: str

    def __str__(self) -> str:
        return f"{self.code}:{self.message}"


INTERNAL_SERVER_ERROR = RpcFailure(500, "INTERNAL_SERVER_ERROR")
METHOD_NOT_SUPPORTED = RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")
AUTH_KEY_INVALID = RpcFailure(401, "AUTH_KEY_INVALID")
