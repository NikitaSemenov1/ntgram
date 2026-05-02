from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from ntgram.tl.models import TlRequest, TlResponse

if TYPE_CHECKING:
    from ntgram.gateway.handlers.context import RouterContext


RpcHandler = Callable[["RouterContext", TlRequest], Awaitable[TlResponse]]


class HandlerRegistry:
    """In-memory dict[str, RpcHandler] with explicit registration."""

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        self._handlers: dict[str, RpcHandler] = {}

    def register(self, constructor: str, handler: RpcHandler) -> None:
        """Bind constructor to handler; refuses duplicate keys."""
        if constructor in self._handlers:
            raise ValueError(
                f"handler for {constructor!r} already registered",
            )
        self._handlers[constructor] = handler

    def register_all(self, mapping: dict[str, RpcHandler]) -> None:
        """Bulk-register a constructor-to-handler mapping."""
        for constructor, handler in mapping.items():
            self.register(constructor, handler)

    def lookup(self, constructor: str) -> RpcHandler | None:
        """Return the handler for constructor or None if absent."""
        return self._handlers.get(constructor)

    def __contains__(self, constructor: str) -> bool:
        return constructor in self._handlers
