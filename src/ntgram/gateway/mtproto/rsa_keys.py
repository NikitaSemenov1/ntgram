from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class RsaKeyError(ValueError):
    """Raised when RSA key files are invalid or mismatched."""


@dataclass(slots=True, frozen=True)
class RsaKeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    fingerprint: int


def _tl_serialize_bytes(value: bytes) -> bytes:
    length = len(value)
    if length <= 253:
        out = bytes([length]) + value
    else:
        out = bytes([254]) + length.to_bytes(4, "little")[:3] + value
    padding = (4 - (len(out) % 4)) % 4
    if padding:
        out += b"\x00" * padding
    return out


def _compute_mtproto_fingerprint(public_key: rsa.RSAPublicKey) -> int:
    public_numbers = public_key.public_numbers()
    n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")
    digest = hashes.Hash(hashes.SHA1())
    # MTProto fingerprint uses SHA1 over TL-serialized `bytes` n and e.
    digest.update(_tl_serialize_bytes(n_bytes) + _tl_serialize_bytes(e_bytes))
    sha1 = digest.finalize()
    return int.from_bytes(sha1[-8:], "little", signed=False)


def load_rsa_keypair(private_key_path: str, public_key_path: str) -> RsaKeyPair:
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    if not private_path.exists():
        raise RsaKeyError(f"private key not found: {private_path}")
    if not public_path.exists():
        raise RsaKeyError(f"public key not found: {public_path}")

    private_obj = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    public_obj = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(private_obj, rsa.RSAPrivateKey):
        raise RsaKeyError("private key must be RSA")
    if not isinstance(public_obj, rsa.RSAPublicKey):
        raise RsaKeyError("public key must be RSA")

    if private_obj.public_key().public_numbers() != public_obj.public_numbers():
        raise RsaKeyError("private/public RSA key mismatch")

    return RsaKeyPair(
        private_key=private_obj,
        public_key=public_obj,
        fingerprint=_compute_mtproto_fingerprint(public_obj),
    )

