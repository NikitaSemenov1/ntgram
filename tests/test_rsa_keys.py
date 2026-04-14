from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ntgram.gateway.mtproto.rsa_keys import RsaKeyError, load_rsa_keypair


def _write_pair(tmp_path: Path, *, suffix: str = "") -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_path = tmp_path / f"private{suffix}.pem"
    public_path = tmp_path / f"public{suffix}.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(private_path), str(public_path)


def test_load_rsa_keypair_success(tmp_path: Path) -> None:
    private_path, public_path = _write_pair(tmp_path)
    pair = load_rsa_keypair(private_path, public_path)
    assert pair.fingerprint > 0


def test_load_rsa_keypair_rejects_mismatch(tmp_path: Path) -> None:
    private_path, _ = _write_pair(tmp_path, suffix="_a")
    _, public_path = _write_pair(tmp_path, suffix="_b")
    with pytest.raises(RsaKeyError):
        load_rsa_keypair(private_path, public_path)
