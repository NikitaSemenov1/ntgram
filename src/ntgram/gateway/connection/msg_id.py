from __future__ import annotations

import secrets
import time


class MsgIdGenerator:
    @staticmethod
    def server() -> int:
        """msg_id for unencrypted handshake replies (parity 1)."""
        value = (int(time.time()) << 32) | secrets.randbits(30)
        value -= value % 4
        return value + 1

    @staticmethod
    def encrypted_response() -> int:
        """msg_id for encrypted RPC responses (parity 1)."""
        value = (int(time.time()) << 32) | secrets.randbits(30)
        return value - (value % 4) + 1

    @staticmethod
    def server_push() -> int:
        """msg_id for server-initiated pushes (parity 3)."""
        value = (int(time.time()) << 32) | secrets.randbits(30)
        return value - (value % 4) + 3
