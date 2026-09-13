"""Local (non-2PC) crypto/TLS helpers shared by the emulated provider S and
the agent's local verification steps.

Everything here is plain single-party cryptography -- the pieces a real party
can do on its own once it holds keys.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import curve

# ---------------- SHA-256 / HMAC / HKDF (RFC 8446 key schedule) --------------

def h256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac256(key: bytes, msg: bytes) -> bytes:
    return _hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes,
                      length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    return hkdf_expand(secret, info, length)


def derive_secret(secret: bytes, label: str, messages: bytes) -> bytes:
    return hkdf_expand_label(secret, label, h256(messages), 32)


# --------------------- ECDSA (secp256k1, minimal) ---------------------------

def ecdsa_sign(sk: int, msg_hash: bytes) -> bytes:
    """(r,s) 64-byte signature."""
    z = int.from_bytes(msg_hash, "big")
    k = secrets.randbelow(curve.N - 1) + 1
    x, _ = curve.point_mul(k)
    r = x % curve.N
    s = (pow(k, curve.N - 2, curve.N) * (z + r * sk)) % curve.N
    if s > curve.N // 2:
        s = curve.N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def ecdsa_verify(pk: curve.Point, msg_hash: bytes, sig: bytes) -> bool:
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (0 < r < curve.N and 0 < s < curve.N):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = pow(s, curve.N - 2, curve.N)
    u1, u2 = (z * w) % curve.N, (r * w) % curve.N
    x, _ = curve.point_add(curve.point_mul(u1), curve.point_mul(u2, pk))
    return (x % curve.N) == r


# --------------------- TLS 1.3 record layer --------------------------------

CT_APPDATA = 0x17          # inner content type for application data
CT_HANDSHAKE = 0x16
CT_ALERT = 0x15


def wrap_record(ct: int, payload: bytes) -> bytes:
    """TLSCiphertext: type(1) | version(2) | length(2) | payload."""
    return bytes([CT_APPDATA, 0x03, 0x03]) + len(payload).to_bytes(2, "big") \
        + payload


def tls_aead_encrypt(key: bytes, iv: bytes, seq: int, aad: bytes,
                     inner: bytes) -> bytes:
    nonce = bytes(a ^ b for a, b in
                  zip(iv, seq.to_bytes(12, "big")))
    return AESGCM(key).encrypt(nonce, inner, aad)


def tls_aead_decrypt(key: bytes, iv: bytes, seq: int, aad: bytes,
                     ct: bytes) -> Optional[bytes]:
    nonce = bytes(a ^ b for a, b in
                  zip(iv, seq.to_bytes(12, "big")))
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception:
        return None


def strip_inner_padding(inner: bytes) -> Tuple[bytes, int]:
    """Split inner plaintext into (content, content_type); zeros stripped."""
    i = len(inner) - 1
    while i >= 0 and inner[i] == 0:
        i -= 1
    if i < 0:
        raise ValueError("empty inner plaintext")
    return inner[:i], inner[i]
