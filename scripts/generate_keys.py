#!/usr/bin/env python3
"""
Generate a new RSA 2048-bit keypair for CloudForge Identity Service.

Usage:
    python scripts/generate_keys.py

Output:
    - private_key.pem  (keep secret, put into RSA_PRIVATE_KEY env var)
    - public_key.pem   (can be shared / used for verification)
"""

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def main():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    out_dir = Path(__file__).resolve().parent.parent
    private_path = out_dir / "private_key.pem"
    public_path = out_dir / "public_key.pem"

    private_path.write_bytes(pem_private)
    public_path.write_bytes(pem_public)

    print("✅ Generated keypair:")
    print(f"   Private: {private_path}")
    print(f"   Public : {public_path}")
    print()
    print("👉 Put the content of private_key.pem into the RSA_PRIVATE_KEY")
    print("   environment variable (or .env file).")
    print()
    print("⚠️  Never commit private_key.pem to git!")


if __name__ == "__main__":
    main()
