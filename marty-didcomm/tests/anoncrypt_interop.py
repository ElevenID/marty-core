"""Independent fresh-key transport check; not demo or conformance qualification.

Requires Python cryptography. All recipient secrets are generated in memory;
only their public keys reach the Rust unit-test producer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives import constant_time, hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def wrapping_key(private: X25519PrivateKey, public: bytes, apv: bytes) -> bytes:
    other_info = field(b"ECDH-ES+A256KW") + field(b"") + field(apv) + (256).to_bytes(4, "big")
    return ConcatKDFHash(hashes.SHA256(), 32, other_info).derive(
        private.exchange(X25519PublicKey.from_public_bytes(public))
    )


def tag(key: bytes, aad: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA512())
    mac.update(aad + iv + ciphertext + (len(aad) * 8).to_bytes(8, "big"))
    return mac.finalize()[:32]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", default="1.95.0")
    args = parser.parse_args()
    private_keys = {f"did:example:bob#x25519-{i}": X25519PrivateKey.generate() for i in (1, 2)}
    environment = os.environ.copy()
    environment["MARTY_DIDCOMM_INTEROP_STDOUT"] = "1"
    environment["MARTY_DIDCOMM_INTEROP_PUBLIC_KEYS"] = json.dumps([
        encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        for key in private_keys.values()
    ])
    command = ["cargo", f"+{args.toolchain}", "test", "--locked", "-q", "-p", "marty-didcomm",
               "--no-default-features", "--features", "encrypted-envelope", "--lib",
               "public_recipient_anoncrypt_has_normative_protected_profile", "--", "--nocapture"]
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[2], env=environment,
                            capture_output=True, text=True, encoding="utf-8", check=False)
    if result.returncode:
        raise RuntimeError(result.stderr)
    lines = [line.removeprefix("DIDCOMM_INTEROP ") for line in result.stdout.splitlines()
             if line.startswith("DIDCOMM_INTEROP ")]
    assert len(lines) == 1, "expected exactly one fresh Rust envelope"
    envelope = json.loads(lines[0])
    header = json.loads(decode(envelope["protected"]))
    assert header["typ"] == "application/didcomm-encrypted+json"
    assert header["alg"] == "ECDH-ES+A256KW" and header["enc"] == "A256CBC-HS512"
    assert header["epk"]["kty"] == "OKP" and header["epk"]["crv"] == "X25519"
    assert "apu" not in header and "skid" not in header
    recipients = envelope["recipients"]
    assert len(recipients) == 2
    assert {recipient["header"]["kid"] for recipient in recipients} == set(private_keys)
    apv = hashlib.sha256(".".join(sorted(private_keys)).encode()).digest()
    assert decode(header["apv"]) == apv
    ephemeral = decode(header["epk"]["x"])
    aad, iv, ciphertext, expected_tag = envelope["protected"].encode(), decode(envelope["iv"]), decode(envelope["ciphertext"]), decode(envelope["tag"])
    assert len(ephemeral) == 32 and len(iv) == 16 and len(expected_tag) == 32
    for recipient in recipients:
        key = wrapping_key(private_keys[recipient["header"]["kid"]], ephemeral, apv)
        wrapped = decode(recipient["encrypted_key"])
        cek = aes_key_unwrap(key, wrapped)
        assert len(cek) == 64
        assert constant_time.bytes_eq(tag(cek[:32], aad, iv, ciphertext), expected_tag)
        decryptor = Cipher(algorithms.AES(cek[32:]), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        assert unpadder.update(padded) + unpadder.finalize() == b'{"id":"message-1","type":"test"}'
        changed_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        assert not constant_time.bytes_eq(tag(cek[:32], aad, iv, changed_ciphertext), expected_tag)
        assert not constant_time.bytes_eq(tag(cek[:32], aad + b"changed", iv, ciphertext), expected_tag)
        for wrong_key, corrupted in [(key, wrapped[:-1] + bytes([wrapped[-1] ^ 1])),
                                      (wrapping_key(X25519PrivateKey.generate(), ephemeral, apv), wrapped)]:
            try:
                aes_key_unwrap(wrong_key, corrupted)
            except InvalidUnwrap:
                pass
            else:
                raise AssertionError("corrupt wrapping key or wrong recipient was accepted")
    print("DIDComm interop PASS: 2 fresh recipients; altered AAD/ciphertext/wrapped keys and wrong recipients rejected")


if __name__ == "__main__":
    main()
