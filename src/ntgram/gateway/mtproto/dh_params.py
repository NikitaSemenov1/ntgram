"""DH parameters for the MTProto auth key exchange.

Uses a well-known 2048-bit safe prime from Telegram's DH parameter set.
The prime p is such that (p-1)/2 is also prime (safe prime), and g is
a primitive root modulo p.
"""
from __future__ import annotations

import secrets

# 2048-bit safe prime used by Telegram servers.
# This is the same prime documented in Telegram's open-source server code.
DH_PRIME = int(
    "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
    "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37"
    "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64"
    "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4"
    "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754"
    "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4"
    "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F"
    "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B",
    16,
)

DH_PRIME_BYTES = DH_PRIME.to_bytes(256, "big")

# Generator g=3 is valid for this prime (Telegram uses g in {2,3,4,5,6,7}).
DH_G = 3
_DH_PUBLIC_LOWER_BOUND = 1 << (2048 - 64)


def is_dh_public_value_safe(value: int) -> bool:
    """Return whether g_a/g_b is in Telegram's recommended safe range."""
    return _DH_PUBLIC_LOWER_BOUND <= value <= DH_PRIME - _DH_PUBLIC_LOWER_BOUND


def generate_dh_pair() -> tuple[int, int]:
    """Generate a server-side DH keypair (secret a, public g_a).

    Returns (a, g_a) where g_a = pow(g, a, p).
    """
    while True:
        a = secrets.randbelow(DH_PRIME - 2) + 2
        g_a = pow(DH_G, a, DH_PRIME)
        if is_dh_public_value_safe(g_a):
            return a, g_a


def compute_auth_key(g_b: int, a: int) -> bytes:
    """Compute the shared auth_key from the client's g_b and server's secret a.

    Returns auth_key as 256 bytes (big-endian).
    """
    if not is_dh_public_value_safe(g_b):
        raise ValueError("g_b out of safe range")
    shared = pow(g_b, a, DH_PRIME)
    return shared.to_bytes(256, "big")
