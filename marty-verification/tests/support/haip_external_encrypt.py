#!/usr/bin/env python3
"""Encrypt one HAIP response for a public JWK using Python cryptography."""

import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> None:
    recipient_jwk = json.load(sys.stdin)
    if recipient_jwk.get("kty") != "EC" or recipient_jwk.get("crv") != "P-256":
        raise ValueError("HAIP test recipient must be a public P-256 key")
    if "d" in recipient_jwk:
        raise ValueError("HAIP test recipient must not expose a private key")
    x = decode_b64url(recipient_jwk["x"])
    y = decode_b64url(recipient_jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("HAIP test recipient coordinates must be 32 bytes")
    recipient = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    ).public_key()

    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), recipient)
    algorithm_id = b"A256GCM"
    other_info = (
        len(algorithm_id).to_bytes(4, "big")
        + algorithm_id
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (256).to_bytes(4, "big")
    )
    cek = ConcatKDFHash(hashes.SHA256(), 32, other_info).derive(shared)
    numbers = ephemeral.public_key().public_numbers()
    epk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }
    header = {"alg": "ECDH-ES", "enc": "A256GCM", "epk": epk}
    protected = b64url(json.dumps(header, separators=(",", ":")).encode())
    iv = os.urandom(12)
    plaintext = b'{"vp_token":"external-fixture"}'
    encrypted = AESGCM(cek).encrypt(iv, plaintext, protected.encode())
    compact = ".".join(
        [protected, "", b64url(iv), b64url(encrypted[:-16]), b64url(encrypted[-16:])]
    )
    print(json.dumps({"compact_jwe": compact, "plaintext": plaintext.decode()}))


if __name__ == "__main__":
    main()
