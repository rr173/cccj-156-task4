"""Self-contained Ed25519 implementation (RFC 8032), pure Python stdlib.

The deployment environment has no third-party cryptography package, so the
small amount of asymmetric crypto the ceremony needs (device attestation
signatures, root signing keys, record-export signatures) is implemented here
on top of hashlib.sha512. Points are kept in extended twisted-edwards
coordinates (X, Y, Z, T); formulas are the standard ones from RFC 8032 /
RFC 7748 Appendix A.
"""

from __future__ import annotations

import hashlib

p = 2 ** 255 - 19
n = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


_By = 4 * pow(5, p - 2, p) % p
_Bx = _xrecover(_By)
B = (_Bx, _By, 1, _Bx * _By % p)
IDENT = (0, 1, 1, 0)


def _edwards_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % p
    Bb = ((Y1 + X1) * (Y2 + X2)) % p
    C = (T1 * 2 * d * T2) % p
    Dd = (Z1 * 2 * Z2) % p
    E = (Bb - A) % p
    F = (Dd - C) % p
    G = (Dd + C) % p
    H = (Bb + A) % p
    return (E * F, G * H, F * G, E * H)


def _point_equal(P, Q) -> bool:
    X1, Y1, Z1, _ = P
    X2, Y2, Z2, _ = Q
    return (X1 * Z2 - X2 * Z1) % p == 0 and (Y1 * Z2 - Y2 * Z1) % p == 0


def _scalarmult(P, e: int):
    Q = IDENT
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


def _encodepoint(P) -> bytes:
    X, Y, Z, _ = P
    zi = pow(Z, p - 2, p)
    x = X * zi % p
    y = Y * zi % p
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decodepoint(s: bytes):
    if len(s) != 32:
        raise ValueError("invalid point length")
    b = int.from_bytes(s, "little")
    sign = b >> 255
    y = b & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != sign:
        x = p - x
    P = (x, y, 1, x * y % p)
    if _point_equal(_scalarmult(P, n), IDENT) is False:
        raise ValueError("point not in prime-order subgroup")
    return P


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _secret_scalar(seed: bytes) -> int:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a % n


def public_from_secret(secret32: bytes) -> bytes:
    if len(secret32) != 32:
        raise ValueError("secret must be 32 bytes")
    a = _secret_scalar(secret32)
    A = _scalarmult(B, a)
    return _encodepoint(A)


def sign(secret32: bytes, msg: bytes) -> bytes:
    a = _secret_scalar(secret32)
    A = _encodepoint(_scalarmult(B, a))
    h = hashlib.sha512(secret32).digest()
    r = _hint(h[32:] + msg) % n
    R = _encodepoint(_scalarmult(B, r))
    S = (r + _hint(R + A + msg) * a) % n
    return R + S.to_bytes(32, "little")


def verify(public32: bytes, msg: bytes, sig64: bytes) -> bool:
    try:
        if len(public32) != 32 or len(sig64) != 64:
            return False
        A = _decodepoint(public32)
        R = _decodepoint(sig64[:32])
        S = int.from_bytes(sig64[32:], "little")
        if S >= n:
            return False
        h = _hint(sig64[:32] + public32 + msg) % n
        return _point_equal(_scalarmult(B, S), _edwards_add(R, _scalarmult(A, h)))
    except (ValueError, OverflowError):
        return False
