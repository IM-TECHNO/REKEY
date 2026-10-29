"""Shamir secret sharing over GF(2^8), applied byte by byte.

A share is `x || y_0 .. y_{n-1}` where x is in 1..255 and y_i is the value of the
i-th byte's polynomial at x. Field: AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
"""

import secrets

from rekey.crypto.errors import InvalidShares

_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x  # multiply by the generator 3
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[_LOG[a] - _LOG[b] + 255]


def _eval(coeffs: list[int], x: int) -> int:
    """Evaluate a polynomial (coeffs[0] is the constant term) at x using Horner's rule."""
    result = 0
    for c in reversed(coeffs):
        result = _mul(result, x) ^ c
    return result


def split(secret: bytes, threshold: int, shares: int) -> list[bytes]:
    if not secret:
        raise ValueError("secret must not be empty")
    if not 2 <= threshold <= shares <= 255:
        raise ValueError("need 2 <= threshold <= shares <= 255")

    out = [bytearray([x]) for x in range(1, shares + 1)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for share in out:
            share.append(_eval(coeffs, share[0]))
    return [bytes(s) for s in out]


def combine(parts: list[bytes]) -> bytes:
    if len(parts) < 2:
        raise InvalidShares("at least two shares are required")
    length = len(parts[0])
    if length < 2:
        raise InvalidShares("share too short")
    xs: list[int] = []
    for p in parts:
        if len(p) != length:
            raise InvalidShares("shares have different lengths")
        if p[0] == 0:
            raise InvalidShares("invalid share index")
        xs.append(p[0])
    if len(set(xs)) != len(xs):
        raise InvalidShares("duplicate shares")

    # Lagrange basis at x = 0; in GF(2^8) subtraction is XOR.
    basis: list[int] = []
    for i, xi in enumerate(xs):
        b = 1
        for j, xj in enumerate(xs):
            if i != j:
                b = _mul(b, _div(xj, xj ^ xi))
        basis.append(b)

    secret = bytearray()
    for k in range(1, length):
        acc = 0
        for p, b in zip(parts, basis, strict=True):
            acc ^= _mul(p[k], b)
        secret.append(acc)
    return bytes(secret)
