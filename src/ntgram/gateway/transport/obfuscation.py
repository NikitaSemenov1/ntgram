from __future__ import annotations


class ObfuscationProtocolError(RuntimeError):
    """Obfuscation protocol error."""


def parse_obfuscation_init(init_payload: bytes) -> None:
    del init_payload
    raise ObfuscationProtocolError("Obfuscation protocol is not supported")
