from __future__ import annotations

from ntgram.gateway.handlers.grpc import GRPC_ROUTE_HANDLERS
from ntgram.tl.registry import default_schema_registry

_SCHEMA = default_schema_registry()

CONSTRUCTOR_ID_TO_NAME: dict[int, str] = {
    _SCHEMA.methods_by_name[name].id: name
    for name in GRPC_ROUTE_HANDLERS
    if name in _SCHEMA.methods_by_name
}

__all__ = ["CONSTRUCTOR_ID_TO_NAME"]
