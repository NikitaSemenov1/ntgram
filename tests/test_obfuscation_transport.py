from __future__ import annotations

import pytest

from ntgram.gateway.transport.obfuscation import ObfuscationProtocolError, parse_obfuscation_init


def test_parse_obfuscation_init_removed() -> None:
    with pytest.raises(ObfuscationProtocolError):
        parse_obfuscation_init(b"\x00" * 64)
