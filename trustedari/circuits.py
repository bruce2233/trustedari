"""2PC crypto circuits built on the PC engine (trustedari.twopc).

Byte convention: a secret-shared byte string is ``List[Bits]`` (each ``n=8``),
index 0 = first byte.  ``pack_bytes`` flattens a byte list into one ``Bits``
(little-endian byte order, matching ``Chan``/share_bytes).  Public bytes can be
turned into shares with ``pub_bytes`` (constant shares, no interaction).

Circuits
--------
* ``sha256`` / ``hmac_sha256`` / ``hkdf_extract`` / ``hkdf_expand_label`` /
  ``derive_secret`` -- the TLS 1.3 key schedule over shared secrets.
* ``ectf_x_add`` -- ECtF: shared x-coordinate of P_A + P_B (DHE sharing).
* ``aes128_enc`` -- AES-128 encrypt block; S-box via masked-open GF(2^8)
  inversion + affine transform (paper-standard "open one masked value" trick).
* ``ghash`` / ``gcm_encrypt`` / ``gcm_open`` -- AEAD for TLS records.

These circuits are gate-level honest: every nonlinear step goes through the
engine's AND/OT or an ``open`` so the same code runs under ``mode='ot'``
(slow but real) and ``mode='sim'`` (fast, deterministic-pad simulation used
for the standard primitives, exactly as the paper treats SHA/AES as given
2PC-friendly subcircuits).
"""
from __future__ import annotations

import hashlib
from typing import List, Optional, Sequence, Tuple

from .twopc import Arith, Bits, Fld, PC

# --------------------------------------------------------------------------
# byte plumbing
# --------------------------------------------------------------------------

def pub_bytes(pc: PC, data: bytes) -> List[Bits]:
    """Public (both parties know) byte string -> constant shares."""
    return [pc.const_bits(b, 8) for b in data]


def share_byte_list(pc: PC, owner: bool, data: bytes) -> List[Bits]:
    """One owner-side share_bytes then unpack to byte list (one message)."""
    return pc._unpack(pc.share_bytes(owner, data), [8] * len(data))


def pack_bytes(pc: PC, bs: Sequence[Bits]) -> Bits:
    return pc._pack(list(bs))


def be32(pc: PC, bs4: Sequence[Bits]) -> Bits:
    """4 bytes (MSB first) -> 32-bit word Bits."""
    assert len(bs4) == 4
    return pc.concat(pc.concat(pc.concat(bs4[0], bs4[1]), bs4[2]), bs4[3])


def to_be32_bytes(pc: PC, w: Bits) -> List[Bits]:
    """32-bit word -> [byte0(MSB) .. byte3]."""
    return [pc.slice(w, 24, 8), pc.slice(w, 16, 8),
            pc.slice(w, 8, 8), pc.slice(w, 0, 8)]


def open_bytes(pc: PC, bs: Sequence[Bits]) -> bytes:
    """Open a byte list to both parties (batched into one exchange)."""
    v = pc.open(pack_bytes(pc, bs))
    return v.to_bytes(len(bs), "little")


# --------------------------------------------------------------------------
# SHA-256
# --------------------------------------------------------------------------

_K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_H256 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def _sigma(pc: PC, x: Bits, r1: int, r2: int, s: int) -> Bits:
    return pc.xor(pc.xor(pc.rotr(x, r1), pc.rotr(x, r2)), pc.shr_bits(x, s))


def _big_sigma(pc: PC, x: Bits, r1: int, r2: int, r3: int) -> Bits:
    return pc.xor(pc.xor(pc.rotr(x, r1), pc.rotr(x, r2)), pc.rotr(x, r3))


def sha256_compress(pc: PC, state: List[Bits], block: List[Bits]) -> List[Bits]:
    """One compression: state = 8 words, block = 64 bytes.  Returns 8 words."""
    assert len(state) == 8 and len(block) == 64
    w = [be32(pc, block[4 * t:4 * t + 4]) for t in range(16)]
    for t in range(16, 64):
        s0 = _sigma(pc, w[t - 15], 7, 18, 3)
        s1 = _sigma(pc, w[t - 2], 17, 19, 10)
        w.append(pc.add(pc.add(w[t - 16], s0), pc.add(w[t - 7], s1)))

    a, b, c, d, e, f, g, h = state
    for t in range(64):
        big_s1 = _big_sigma(pc, e, 6, 11, 25)
        # Ch(e,f,g) = g ^ (e & (f ^ g))  -- one AND level
        ch = pc.xor(g, pc.and_bits(e, pc.xor(f, g)))
        kw = pc.add(pc.const_bits(_K256[t], 32), w[t])
        t1 = pc.add(pc.add(h, big_s1), pc.add(ch, kw))
        big_s0 = _big_sigma(pc, a, 2, 13, 22)
        # Maj(a,b,c) = (a&b) ^ (c & (a^b)) -- one AND level
        maj = pc.xor(pc.and_bits(a, b), pc.and_bits(c, pc.xor(a, b)))
        t2 = pc.add(big_s0, maj)
        h, g, f, e, d, c, b, a = \
            g, f, e, pc.add(d, t1), c, b, a, pc.add(t1, t2)

    return [pc.add(s, v) for s, v in zip(state, [a, b, c, d, e, f, g, h])]


def sha256_from_state(pc: PC, state: List[Bits],
                      msg: Sequence[Bits], pre_len: int = 0) -> List[Bits]:
    """SHA-256 finalize: pad `msg` and compress starting from `state`
    (8 words).  `pre_len` = number of bytes already compressed into `state`
    (the padding's length field covers the TOTAL message length).
    Used as the HMAC inner/outer finalization after precomputed pad-block
    states (the paper's ExpandOptm trick)."""
    L = len(msg)
    pad_len = (64 - ((pre_len + L + 8 + 1) % 64)) % 64
    padded = list(msg) + [pc.const_bits(0x80, 8)] + \
        [pc.const_bits(0, 8) for _ in range(pad_len)]
    bitlen = (pre_len + L) * 8
    for i in range(7, -1, -1):
        padded.append(pc.const_bits((bitlen >> (8 * i)) & 0xFF, 8))
    st = state
    for off in range(0, len(padded), 64):
        st = sha256_compress(pc, st, padded[off:off + 64])
    return st


def sha256_bytes(pc: PC, msg: Sequence[Bits]) -> List[Bits]:
    """SHA-256 over a shared/public byte list; returns 8 word shares."""
    state = [pc.const_bits(h, 32) for h in _H256]
    return sha256_from_state(pc, state, msg)


def sha256_digest_bytes(pc: PC, msg: Sequence[Bits]) -> List[Bits]:
    """SHA-256 digest as 32 byte-shares (MSB-first order)."""
    out: List[Bits] = []
    for w in sha256_bytes(pc, msg):
        out.extend(to_be32_bytes(pc, w))
    return out


# --------------------------------------------------------------------------
# HMAC-SHA256 / HKDF (TLS 1.3 key schedule)
# --------------------------------------------------------------------------

def hmac_sha256(pc: PC, key: Sequence[Bits], msg: Sequence[Bits]) -> List[Bits]:
    """HMAC-SHA256(key, msg) -> 32 byte-shares.  key <= 64 bytes."""
    assert len(key) <= 64
    k0 = list(key) + [pc.const_bits(0, 8) for _ in range(64 - len(key))]
    ipad = [pc.xor(b, pc.const_bits(0x36, 8)) for b in k0]
    opad = [pc.xor(b, pc.const_bits(0x5C, 8)) for b in k0]
    inner = sha256_digest_bytes(pc, ipad + list(msg))
    return sha256_digest_bytes(pc, opad + inner)


# -- ExpandOptm (paper, Subprotocols 1-2): precompute the two HMAC pad-block
# compression states once per shared secret and reuse across every expansion.

HmacPC = Tuple[List[Bits], List[Bits]]   # (iv1, iv2): state after pad blocks


def hmac_precompute_sh(pc: PC, key: Sequence[Bits]) -> HmacPC:
    """Shared HMAC key -> shared (IV1, IV2) = f_H(IV0, K^ipad / K^opad)."""
    assert len(key) <= 64
    k0 = list(key) + [pc.const_bits(0, 8) for _ in range(64 - len(key))]
    h0 = [pc.const_bits(h, 32) for h in _H256]
    ipad = [pc.xor(b, pc.const_bits(0x36, 8)) for b in k0]
    opad = [pc.xor(b, pc.const_bits(0x5C, 8)) for b in k0]
    return (sha256_compress(pc, h0, ipad), sha256_compress(pc, h0, opad))


def hmac_precompute_pub(pc: PC, key: bytes) -> HmacPC:
    """Public HMAC key -> (IV1, IV2) as constant shares (free: local)."""
    return hmac_precompute_sh(pc, pub_bytes(pc, key))


def hmac_from_pc(pc: PC, st: HmacPC, msg: Sequence[Bits]) -> List[Bits]:
    """HMAC-SHA256 with precomputed pad states -> 32 byte-shares."""
    iv1, iv2 = st
    inner = sha256_from_state(pc, iv1, msg, pre_len=64)
    inner_b: List[Bits] = []
    for w in inner:
        inner_b.extend(to_be32_bytes(pc, w))
    outer = sha256_from_state(pc, iv2, inner_b, pre_len=64)
    out: List[Bits] = []
    for w in outer:
        out.extend(to_be32_bytes(pc, w))
    return out


def expand_optm(pc: PC, st: HmacPC, label: str, context: bytes,
                length: int) -> List[Bits]:
    """HKDF.ExpandOptm(PC, label || context) -- TLS HKDF-Expand-Label with
    cached pad states."""
    assert 1 <= length <= 32
    full = b"tls13 " + label.encode()
    info = pub_bytes(
        pc,
        length.to_bytes(2, "big") + bytes([len(full)]) + full
        + bytes([len(context)]) + context)
    return hmac_from_pc(pc, st, info + [pc.const_bits(1, 8)])[:length]


def derive_tk_optm(pc: PC, st: HmacPC) -> Tuple[List[Bits], List[Bits]]:
    """DeriveTKOptm: (shared tk, public-to-be-opened iv) via two expansions."""
    tk = expand_optm(pc, st, "key", b"", 16)
    iv = expand_optm(pc, st, "iv", b"", 12)
    return tk, iv


def hkdf_extract(pc: PC, salt: Sequence[Bits], ikm: Sequence[Bits]) -> List[Bits]:
    """HKDF-Extract(salt, ikm) = HMAC(salt, ikm).  Zero salt -> 32 const bytes."""
    if len(salt) == 0:
        salt = pub_bytes(pc, b"\x00" * 32)
    return hmac_sha256(pc, salt, ikm)


def hkdf_expand(pc: PC, prk: Sequence[Bits], info: Sequence[Bits],
                length: int) -> List[Bits]:
    """HKDF-Expand; only lengths <= 32 (one T block) are needed for TLS keys."""
    assert 1 <= length <= 32
    t = hmac_sha256(pc, prk, list(info) + [pc.const_bits(1, 8)])
    return t[:length]


def hkdf_expand_label(pc: PC, secret: Sequence[Bits], label: str,
                      context: bytes, length: int) -> List[Bits]:
    """TLS 1.3 HKDF-Expand-Label(secret, label, context, length).

    context is always a *public* value in TLS (a transcript hash) so it is
    injected as constant shares -- matching the paper, where transcript data
    is public and only the secrets are shared.
    """
    full = b"tls13 " + label.encode()
    info = pub_bytes(
        pc,
        length.to_bytes(2, "big") + bytes([len(full)]) + full
        + bytes([len(context)]) + context)
    return hkdf_expand(pc, secret, info, length)


def derive_secret(pc: PC, secret: Sequence[Bits], label: str,
                  transcript_hash: bytes) -> List[Bits]:
    """Derive-Secret(secret, label, messages) with public transcript hash."""
    return hkdf_expand_label(pc, secret, label, transcript_hash, 32)


def sha256_public(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------
# ECtF -- shared x-coordinate of point sum (DHE)
# --------------------------------------------------------------------------

def ectf_x_add(pc: PC, my_pt: Tuple[int, int]) -> Fld:
    """Each party holds its own curve point P_i (secret locally, shared into
    the 2PC); returns additive shares of x(P_0 + P_1).

    Paper use: A and R pick r_A, r_R, set Z_i = r_i*G, CKS = Z_A + Z_R goes to
    S.  Each then computes ssk_i = r_i*Y (Y = server ephemeral) and ECtF turns
    x(ssk_A + ssk_B) = x((r_A+r_R)*Y) -- the real ECDHE secret -- into field
    shares: exactly the joint-DHE primitive of TrustedARI's handshake.
    """
    x1 = pc.share_field(pc.side == 0, my_pt[0] if pc.side == 0 else 0)
    y1 = pc.share_field(pc.side == 0, my_pt[1] if pc.side == 0 else 0)
    x2 = pc.share_field(pc.side == 1, my_pt[0] if pc.side == 1 else 0)
    y2 = pc.share_field(pc.side == 1, my_pt[1] if pc.side == 1 else 0)
    dx = pc.fsub(x2, x1)
    dy = pc.fsub(y2, y1)
    lam = pc.fmul(dy, pc.finv(dx))          # lambda = (y2-y1)/(x2-x1)
    x3 = pc.fsub(pc.fsub(pc.fmul(lam, lam), x1), x2)
    return x3


def fld_to_bits(pc: PC, f: Fld) -> Bits:
    """Additive F_p shares -> XOR-shared 256-bit integer (DHE -> HKDF ikm).

    s = (s0 + s1) mod p.  Compute the 257-bit sum, then conditionally
    subtract p (once) based on the carry-out OR an extra p-comparison.
    """
    from .curve import P as _P
    if pc.mode == "sim" and f.t is not None:
        mine = f.v
        peer = (f.t - mine) % _P
        op0 = mine if pc.side == 0 else peer
        op1 = peer if pc.side == 0 else mine
    else:
        op0 = f.v if pc.side == 0 else 0
        op1 = f.v if pc.side == 1 else 0
    b0 = Bits(op0 if pc.side == 0 else 0, 257,
              op0 if pc.mode == "sim" else None)
    b1 = Bits(op1 if pc.side == 1 else 0, 257,
              op1 if pc.mode == "sim" else None)
    full = pc.add(b0, b1)                    # 257-bit s0+s1
    low = pc.slice(full, 0, 256)
    carry = pc.slice(full, 256, 1)
    low257 = pc.concat(pc.const_bits(0, 1), low)
    d = pc.add(low257, pc.const_bits((1 << 256) - _P, 257))
    ge = pc.slice(d, 256, 1)                 # low >= P ?
    sel = pc.xor(carry, ge)
    subt = pc.add(low, pc.const_bits((1 << 256) - _P, 256))
    return pc.mux(sel, subt, low)


# --------------------------------------------------------------------------
# AES-128 (encrypt) + GHASH + GCM
# --------------------------------------------------------------------------

_AES_POLY = 0x11B


def _xtime8_local(pc: PC, a: Bits) -> Bits:
    """a * x in GF(2^8) -- a linear map, so each party applies it to its own
    share and to the sim truth:  xtime(a0) ^ xtime(a1) = xtime(a0^a1)."""
    def xt(v: int) -> int:
        return (((v << 1) & 0xFF) ^ (0x1B if v & 0x80 else 0))
    return Bits(xt(a.v), 8, xt(a.t) if a.t is not None else None)


def _gf8_mul_const(pc: PC, a: Bits, c: int) -> Bits:
    """shared byte * public GF(2^8) constant -- purely local (linear map)."""
    acc = pc.const_bits(0, 8)
    aa, cc = a, c
    while cc:
        if cc & 1:
            acc = pc.xor(acc, aa)
        aa = _xtime8_local(pc, aa)
        cc >>= 1
    return acc


def gf8_mul(pc: PC, a: Bits, b: Bits) -> Bits:
    """Shared GF(2^8) product -- one batched AND round (8 pairs of 8 bits)."""
    pairs = []
    ax = a
    for j in range(8):
        pairs.append((pc.rep_bit(pc.slice(b, j, 1), 8), ax))
        ax = _xtime8_local(pc, ax)
    terms = pc.and_pairs(pairs)
    acc = terms[0]
    for t in terms[1:]:
        acc = pc.xor(acc, t)
    return acc


def aes_sbox(pc: PC, b: Bits) -> Bits:
    """AES S-box via masked-open GF(2^8) inversion + affine map."""
    tinv = 0
    for _ in range(8):                    # degenerate mask (m=0): retry;
        r = pc.rand_bits(8)               # 8 zeros in a row => b=0 whp (2^-64)
        m = pc.open(gf8_mul(pc, b, r))
        if m:
            tinv = _gf8_inv_public(m)
            break
    s = _gf8_mul_const(pc, r, tinv)       # r * (b*r)^{-1} = b^{-1}
    # affine: y = s ^ rotl(s,1)^rotl(s,2)^rotl(s,3)^rotl(s,4) ^ 0x63
    y = s
    for k in range(1, 5):
        y = pc.xor(y, pc.rotl(s, k))
    return pc.xor(y, pc.const_bits(0x63, 8))


def _gf8_inv_public(x: int) -> int:
    """Plain GF(2^8) inverse used on the *opened* masked value."""
    if x == 0:
        return 0
    return _gf8_pow_public(x, 254)


def _gf8_mul_public(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= _AES_POLY
        b >>= 1
    return p


def _gf8_pow_public(a: int, e: int) -> int:
    r = 1
    while e:
        if e & 1:
            r = _gf8_mul_public(r, a)
        a = _gf8_mul_public(a, a)
        e >>= 1
    return r


def _shift_rows(st: List[Bits]) -> List[Bits]:
    """State is a flat 16-byte list, column-major like FIPS-197 input bytes."""
    out = [None] * 16
    for row in range(4):
        for col in range(4):
            out[col * 4 + row] = st[((col + row) % 4) * 4 + row]
    return out


def _mix_columns(pc: PC, st: List[Bits]) -> List[Bits]:
    out = []
    for c in range(4):
        s0, s1, s2, s3 = st[4 * c:4 * c + 4]
        out.append(pc.xor(pc.xor(_gf8_mul_const(pc, s0, 2),
                                 _gf8_mul_const(pc, s1, 3)),
                          pc.xor(s2, s3)))
        out.append(pc.xor(pc.xor(s0, _gf8_mul_const(pc, s1, 2)),
                          pc.xor(_gf8_mul_const(pc, s2, 3), s3)))
        out.append(pc.xor(pc.xor(s0, s1),
                          pc.xor(_gf8_mul_const(pc, s2, 2),
                                 _gf8_mul_const(pc, s3, 3))))
        out.append(pc.xor(pc.xor(_gf8_mul_const(pc, s0, 3), s1),
                          pc.xor(s2, _gf8_mul_const(pc, s3, 2))))
    return out


def aes128_enc(pc: PC, key: Sequence[Bits], pt: Sequence[Bits]) -> List[Bits]:
    """AES-128 encryption of one 16-byte block under a shared 16-byte key."""
    assert len(key) == 16 and len(pt) == 16
    # key schedule: w[i] 4-byte words; generate 44 words
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [aes_sbox(pc, b) for b in t]        # SubWord
            t[0] = pc.xor(t[0], pc.const_bits(_rcon(i // 4), 8))
        w.append([pc.xor(w[i - 4][j], t[j]) for j in range(4)])

    def add_round_key(st: List[Bits], rnd: int) -> List[Bits]:
        return [pc.xor(st[4 * i + j], w[4 * rnd + i][j])
                for i in range(4) for j in range(4)]

    st = add_round_key(list(pt), 0)
    for rnd in range(1, 10):
        st = [aes_sbox(pc, b) for b in st]
        st = _shift_rows(st)
        st = _mix_columns(pc, st)
        st = add_round_key(st, rnd)
    st = [aes_sbox(pc, b) for b in st]
    st = _shift_rows(st)
    st = add_round_key(st, 10)
    return st


def _rcon(i: int) -> int:
    r = 1
    for _ in range(i - 1):
        r = _gf8_mul_public(r, 2)
    return r


# --------------------------------------------------------------------------
# GHASH + AES-GCM
# --------------------------------------------------------------------------

def pack_be(pc: PC, bs: Sequence[Bits]) -> Bits:
    """wire-order byte list -> one Bits whose value is int(bs, 'big')."""
    return pc._pack(list(reversed(list(bs))))


def unpack_be(pc: PC, x: Bits, n: int) -> List[Bits]:
    """Bits with v = int(wire,'big') -> wire-order byte list of length n."""
    return list(reversed(pc._unpack(x, [8] * n)))


def gf128_mul(pc: PC, a: Bits, b: Bits) -> Bits:
    """Shared GF(2^128) product (GCM), one batched AND round.

    a.v/b.v are the NIST SP-800-38D Algorithm-1 representation
    (int(block, 'big')).  Iteration i takes multiplier wire-bit i = int bit
    (127-i) of b; the running V updates as V' = (V >> 1) ^ (V_0 ? R : 0) with
    R = 0xE1||0^120, which is a linear map in the shared carry bit and thus
    purely local.
    """
    R = 0xE1 << 120

    def v_next(v: Bits) -> Bits:
        carry = pc.slice(v, 0, 1)
        nv = (v.v >> 1) ^ (R if carry.v & 1 else 0)
        nt = ((v.t >> 1) ^ (R if carry.t & 1 else 0)
              if v.t is not None and carry.t is not None else None)
        return Bits(nv, 128, nt)

    pairs = []
    v = a
    for i in range(128):
        pairs.append((pc.rep_bit(pc.slice(b, 127 - i, 1), 128), v))
        v = v_next(v)
    terms = pc.and_pairs(pairs)
    acc = terms[0]
    for t in terms[1:]:
        acc = pc.xor(acc, t)
    return acc


def ghash(pc: PC, h: Bits, blocks: List[Bits]) -> Bits:
    """GHASH_H over 16-byte blocks; each block packed via ``pack_be``."""
    y = pc.const_bits(0, 128)
    for blk in blocks:
        y = gf128_mul(pc, pc.xor(y, blk), h)
    return y


def _pad16(pc: PC, data: Sequence[Bits]) -> List[Bits]:
    out = list(data)
    while len(out) % 16:
        out.append(pc.const_bits(0, 8))
    return out


def gcm_encrypt(pc: PC, key: Sequence[Bits], iv: bytes,
                aad: bytes, pt: Sequence[Bits]) -> Tuple[List[Bits], List[Bits]]:
    """AES-128-GCM encryption.  iv (12B) and aad are public; pt shared.
    Returns (ciphertext bytes, 16-byte tag) as shares.
    """
    assert len(key) == 16 and len(iv) == 12
    j0 = pub_bytes(pc, iv + b"\x00\x00\x00\x01")
    # s = E(K, J0) -- the tag mask;  h = E(K, 0^128) -- the GHASH key
    s_blk = aes128_enc(pc, key, j0)
    hkey = aes128_enc(pc, key, pub_bytes(pc, b"\x00" * 16))
    # GCTR: counter block i = iv || (i+1) as BE32
    ct: List[Bits] = []
    for i in range((len(pt) + 15) // 16):
        ctr = pub_bytes(pc, iv + (i + 2).to_bytes(4, "big"))
        ks = aes128_enc(pc, key, ctr)
        for j in range(16):
            idx = 16 * i + j
            if idx < len(pt):
                ct.append(pc.xor(pt[idx], ks[j]))
    # GHASH over aad || ct || len(aad)*8 || len(ct)*8  (all 16B-aligned)
    lens = pub_bytes(pc, (len(aad) * 8).to_bytes(8, "big")
                     + (len(ct) * 8).to_bytes(8, "big"))
    data = _pad16(pc, pub_bytes(pc, aad)) + _pad16(pc, ct) + lens
    blocks = [pack_be(pc, data[16 * i:16 * i + 16])
              for i in range(len(data) // 16)]
    tag = pc.xor(ghash(pc, pack_be(pc, hkey), blocks), pack_be(pc, s_blk))
    return ct, unpack_be(pc, tag, 16)


def gcm_open(pc: PC, key: Sequence[Bits], iv: bytes, aad: bytes,
             ct_bytes: bytes) -> Tuple[List[Bits], List[Bits]]:
    """Shared decryption path used by billing: the ciphertext is *public*
    (it's a window of a TLS record already received), the key is shared.
    Returns (plaintext byte shares, recomputed tag shares)."""
    assert len(key) == 16 and len(iv) == 12
    j0 = pub_bytes(pc, iv + b"\x00\x00\x00\x01")
    s_blk = aes128_enc(pc, key, j0)
    hkey = aes128_enc(pc, key, pub_bytes(pc, b"\x00" * 16))
    ct = pub_bytes(pc, ct_bytes)
    pt: List[Bits] = []
    for i in range((len(ct_bytes) + 15) // 16):
        ctr = pub_bytes(pc, iv + (i + 2).to_bytes(4, "big"))
        ks = aes128_enc(pc, key, ctr)
        for j in range(16):
            idx = 16 * i + j
            if idx < len(ct):
                pt.append(pc.xor(ct[idx], ks[j]))
    lens = pub_bytes(pc, (len(aad) * 8).to_bytes(8, "big")
                     + (len(ct) * 8).to_bytes(8, "big"))
    data = _pad16(pc, pub_bytes(pc, aad)) + _pad16(pc, ct) + lens
    blocks = [pack_be(pc, data[16 * i:16 * i + 16])
              for i in range(len(data) // 16)]
    tag = pc.xor(ghash(pc, pack_be(pc, hkey), blocks), pack_be(pc, s_blk))
    return pt, unpack_be(pc, tag, 16)
