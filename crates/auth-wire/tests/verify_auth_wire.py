#!/usr/bin/env python3
"""Dependency-free independent Ed25519 verification of the auth-wire v2 goldens."""
import hashlib
import json
from pathlib import Path

Q = 2**255 - 19
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)
L = 2**252 + 27742317777372353535851937790883648493

def inv(x): return pow(x, Q - 2, Q)
def xrecover(y):
    x = pow((y*y - 1) * inv(D*y*y + 1), (Q + 3) // 8, Q)
    if (x*x - (y*y - 1) * inv(D*y*y + 1)) % Q: x = (x * I) % Q
    return Q - x if x & 1 else x

BY = (4 * inv(5)) % Q
B = (xrecover(BY), BY)

def add(p, q):
    x1, y1 = p; x2, y2 = q
    k = D*x1*x2*y1*y2
    return ((x1*y2 + x2*y1) * inv(1 + k) % Q,
            (y1*y2 + x1*x2) * inv(1 - k) % Q)

def mul(p, n):
    out = (0, 1)
    while n:
        if n & 1: out = add(out, p)
        p = add(p, p); n >>= 1
    return out

def decodepoint(raw):
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    x = xrecover(y)
    if x & 1 != raw[31] >> 7: x = Q - x
    p = (x, y)
    if mul(p, L) != (0, 1): raise ValueError("point is not in the prime subgroup")
    return p

def verify(public, signature, message):
    if len(public) != 32 or len(signature) != 64: return False
    rraw, sraw = signature[:32], signature[32:]
    s = int.from_bytes(sraw, "little")
    if s >= L: return False
    try: a, r = decodepoint(public), decodepoint(rraw)
    except ValueError: return False
    h = int.from_bytes(hashlib.sha512(rraw + public + message).digest(), "little") % L
    return mul(B, s) == add(r, mul(a, h))

def main():
    version = "v2"
    fixture = json.loads((Path(__file__).parent / f"fixtures/auth_wire_{version}.json").read_text())
    raw = {name: bytes.fromhex(value) for name, value in fixture.items()}

    request = raw["request"]
    # Final postcard field is proofs: 1, signer[32], signature Vec length 64, signature[64].
    proof_start = len(request) - (1 + 32 + 1 + 64)
    public = request[proof_start + 1:proof_start + 33]
    signature = request[-64:]
    unsigned = request[:proof_start] + b"\x00"
    assert request[0] == int(version[1:]), "version byte"
    assert verify(public, signature, f"commons/auth/request/{version}\0".encode() + unsigned)

    for name, domain, key_offset in [
        ("response", f"commons/auth/response/{version}\0".encode(), 49),
        ("session", f"commons/auth/session/{version}\0".encode(), None),
        ("stream", f"commons/auth/stream/{version}\0".encode(), None),
    ]:
        value = raw[name]
        public = value[key_offset:key_offset + 32] if key_offset is not None else value[-97:-65]
        signature = value[-64:]
        unsigned = value[:-65] + b"\x00"
        assert verify(public, signature, domain + unsigned), name
    print(f"auth-wire {version} Python Ed25519 verification passed")

if __name__ == "__main__": main()
