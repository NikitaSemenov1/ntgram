from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate RSA keypair for MTProto handshake.")
    parser.add_argument("--output-dir", default="ntgram/keys", help="Directory for private.pem/public.pem")
    parser.add_argument("--force", action="store_true", help="Overwrite existing keys")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    private_path = output_dir / "private.pem"
    public_path = output_dir / "public.pem"
    if (private_path.exists() or public_path.exists()) and not args.force:
        print("Key files already exist. Use --force to overwrite.")
        return 1

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)
    public_key = private_key.public_key()

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
    print(f"Generated {private_path} and {public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
