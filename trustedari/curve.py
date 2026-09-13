"""Elliptic-curve helpers (secp256k1) used by the reproduced TrustedARI stack.

Used for the emulated TLS ECDHE key exchange, the ECtF primitive and the
Chou-Orlandi base OTs inside the IKNP extension.  Point arithmetic is provided
by py_ecc; this module adds (de)serialization and a few convenience wrappers.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional, Tuple

from py_ecc.secp256k1 import secp256k1 as _ec

# secp256k1 parameters
P = _ec.P          # field prime
N = _ec.N          # group order
G = (_ec.Gx, _ec.Gy)

Point = Tuple[int, int]


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def point_mul(s: int, pt: Point = G) -> Point:
    return _ec.multiply(pt, s % N)


def point_add(a: Point, b: Point) -> Point:
    return _ec.add(a, b)


def point_neg(a: Point) -> Point:
    return (a[0], (-a[1]) % P)


def point_sub(a: Point, b: Point) -> Point:
    return point_add(a, point_neg(b))


def ser_point(pt: Point) -> bytes:
    """SEC compressed encoding."""
    x, y = pt
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def deser_point(data: bytes) -> Point:
    assert len(data) == 33 and data[0] in (2, 3)
    x = int.from_bytes(data[1:], "big")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)  # P % 4 == 3
    if (y & 1) != (data[0] & 1):
        y = P - y
    return (x, y)


def hash_point(pt: Point, label: bytes = b"") -> bytes:
    return hashlib.sha256(label + ser_point(pt)).digest()


def point_to_field(pt: Point) -> int:
    """x-coordinate as a field element (the ECtF output value)."""
    return pt[0] % P
