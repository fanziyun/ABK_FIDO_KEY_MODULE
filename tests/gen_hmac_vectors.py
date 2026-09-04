#!/usr/bin/env python3
"""Generate fixed hmac-secret golden vectors for the kernel selftest and tests.

Algorithm under test is the classic CTAP2 hmac-secret extension (the form
Windows Hello uses, matching fido2 0.8.1 client/ctap2 + extensions.py):

  Z           = SHA-256(x-coordinate of ECDH(P-256, authenticatorPriv, platformPub))
  saltEnc     = AES-256-CBC(key=Z, iv=0x00*16, salt1 || salt2)
  saltAuth    = HMAC-SHA-256(key=Z, saltEnc)[0:16]
  output1     = HMAC-SHA-256(key=credSecret, salt1)
  output2     = HMAC-SHA-256(key=credSecret, salt2)
  outputEnc   = AES-256-CBC(key=Z, iv=0x00*16, output1 || output2)

Run: python3 tests/gen_hmac_vectors.py
Writes: tests/hmac_vectors.json and prints C arrays for core.c.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def scalar(label: bytes) -> int:
    d = hashlib.sha256(label).digest()
    v = int.from_bytes(d, "big") % (N - 1) + 1
    return v


def pub_xy(priv: int) -> bytes:
    pub = ec.derive_private_key(priv, ec.SECP256R1()).public_key()
    nums = pub.public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def c_array(name: str, data: bytes, per_line: int = 12) -> str:
    hexes = ["0x%02x" % b for b in data]
    lines = []
    for i in range(0, len(hexes), per_line):
        lines.append("\t" + ", ".join(hexes[i:i + per_line]) + ",")
    return "static const u8 %s[%d] = {\n%s\n};\n" % (name, len(data), "\n".join(lines))


def main() -> int:
    cred_priv = scalar(b"ABK FIDO hmac selftest credential key")
    cred_pub = pub_xy(cred_priv)
    platform_priv = scalar(b"ABK FIDO hmac selftest platform key")
    platform_pub = pub_xy(platform_priv)

    # Z: SHA-256 of the ECDH shared x-coordinate. Authenticator side: the
    # credential's private key meets the platform's public key.
    cred_key = ec.derive_private_key(cred_priv, ec.SECP256R1())
    x = int.from_bytes(platform_pub[:32], "big")
    y = int.from_bytes(platform_pub[32:], "big")
    platform_pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    shared_x = cred_key.exchange(ec.ECDH(), platform_pub_key)
    z = hashlib.sha256(shared_x).digest()

    cred_secret = bytes(range(32))  # 00 01 02 ... 1f
    salt1 = bytes((0x11 + i) & 0xFF for i in range(32))
    salt2 = bytes((0x51 + i) & 0xFF for i in range(32))

    zero_iv = b"\x00" * 16

    def aes_cbc_enc(key: bytes, plain: bytes) -> bytes:
        enc = Cipher(algorithms.AES(key), modes.CBC(zero_iv)).encryptor()
        return enc.update(plain) + enc.finalize()

    def aes_cbc_dec(key: bytes, ciphertext: bytes) -> bytes:
        dec = Cipher(algorithms.AES(key), modes.CBC(zero_iv)).decryptor()
        return dec.update(ciphertext) + dec.finalize()

    salt_enc = aes_cbc_enc(z, salt1 + salt2)
    salt_auth = hmac.new(z, salt_enc, hashlib.sha256).digest()[:16]
    output1 = hmac.new(cred_secret, salt1, hashlib.sha256).digest()
    output2 = hmac.new(cred_secret, salt2, hashlib.sha256).digest()
    output_enc = aes_cbc_enc(z, output1 + output2)

    # Self-checks against the reference direction.
    assert aes_cbc_dec(z, salt_enc) == salt1 + salt2
    assert aes_cbc_dec(z, output_enc) == output1 + output2

    vectors = {
        "cred_priv": cred_priv.to_bytes(32, "big").hex(),
        "cred_pub": cred_pub.hex(),
        "platform_priv": platform_priv.to_bytes(32, "big").hex(),
        "platform_pub": platform_pub.hex(),
        "z": z.hex(),
        "cred_secret": cred_secret.hex(),
        "salt1": salt1.hex(),
        "salt2": salt2.hex(),
        "salt_enc": salt_enc.hex(),
        "salt_auth": salt_auth.hex(),
        "output1": output1.hex(),
        "output2": output2.hex(),
        "output_enc": output_enc.hex(),
    }
    out = Path(__file__).with_name("hmac_vectors.json")
    out.write_text(json.dumps(vectors, indent=2) + "\n")
    print("wrote", out)

    print("\n/* ---- embed in core.c hmac_selftest ---- */\n")
    print(c_array("abk_fido_selftest_cred_priv", cred_priv.to_bytes(32, "big")))
    print(c_array("abk_fido_selftest_platform_xy", platform_pub))
    print(c_array("abk_fido_selftest_cred_secret", cred_secret))
    print(c_array("abk_fido_selftest_salt_enc", salt_enc))
    print(c_array("abk_fido_selftest_salt_auth", salt_auth))
    print(c_array("abk_fido_selftest_want_z", z))
    print(c_array("abk_fido_selftest_want_output_enc", output_enc))
    print(c_array("abk_fido_selftest_want_output1", output1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
