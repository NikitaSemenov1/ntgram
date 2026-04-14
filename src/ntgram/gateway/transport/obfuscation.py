from __future__ import annotations


class ObfuscationProtocolError(RuntimeError):
    """Compatibility stub kept after transport obfuscation removal."""


def parse_obfuscation_init(init_payload: bytes) -> None:
    del init_payload
    raise ObfuscationProtocolError("transport obfuscation was removed; use abridged transport only")
