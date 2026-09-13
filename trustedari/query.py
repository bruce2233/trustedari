"""Privacy-preserving query construction (paper Section 5 / Protocols 1-2).

Segments:  (theta, s, g, h)
  theta: P public | Af/Rf fixed-len private | Xf fixed-len shared |
         As/Rs variable private | Xs variable shared
  s:     padded content as h shared byte-Bits (pad byte = 0x00)
  g:     true length -- int when public (P/Af/Rf/Xf), Arith share when
         hidden (As/Rs/Xs)
  h:     public padded length

LDC  (left range has public length): sm = sl || sr, free (local).
SHC  (left range length hidden):    BlindRotate the right segment left by
         the secret pad distance d = h_l - g_l (Protocol 1 + Protocol 5).
Plan Ω: dynamic program over merge orders minimizing sum of SHC costs
         (cost = (h_l+h_r) * ceil(log2(h_l+h_r)); LDC merges are free).
Pi_I2S: arithmetic-shared body length -> shared ASCII decimal (Content-Length).
Pi_query: assemble then 2PC-AEAD(encrypt) under shared tk_capp; ciphertext
         and tag are public and forwarded by R as a normal TLS record.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Union

from . import circuits as C
from .twopc import PC, MODE_SIM, Bits, Arith

P, AF, RF, XF, AS, RS, XS = "P", "Af", "Rf", "Xf", "As", "Rs", "Xs"
PUB_LEN = {P, AF, RF, XF}
GK = 16        # bit width of length shares (max padded length 65535)
PAD = 0x00


@dataclass
class Seg:
    theta: str
    s: List[Bits]
    g: Union[int, Arith]
    h: int

    @property
    def len_public(self) -> bool:
        return isinstance(self.g, int)


def _pad_share_bytes(pc: PC, pad: bytes) -> List[Bits]:
    """Xf/Xs helper: each side's pad share is already its Bits share — the
    plaintext is the XOR of the two pads.  In sim mode exchange pads so both
    sides annotate the same truth (sim is truth-transparent anyway)."""
    if pc.mode == MODE_SIM:
        pc.chan.send(pc.side, "sim.t", pad)
        peer = pc.chan.recv(pc.side, "sim.t")
        t = bytes(x ^ y for x, y in zip(pad, peer))
        return [Bits(pc._split_int(tb, 256, additive=False), 8, tb)
                for tb in t]
    return [Bits(b, 8) for b in pad]


def _const_arith(pc: PC, v: int, k: int = GK) -> Arith:
    return Arith(v % (1 << k) if pc.side == 0 else 0, k,
                 v % (1 << k) if pc.mode == MODE_SIM else None)


def _to_arith(pc: PC, g: Union[int, Arith], k: int = GK) -> Arith:
    return _const_arith(pc, g, k) if isinstance(g, int) else g


def _arith_add(pc: PC, a: Arith, b: Arith) -> Arith:
    assert a.k == b.k
    return Arith((a.v + b.v) % (1 << a.k), a.k,
                 ((a.t or 0) + (b.t or 0)) % (1 << a.k)
                 if a.t is not None and b.t is not None else None)


def _arith_sub(pc: PC, a: Arith, b: Arith) -> Arith:
    assert a.k == b.k
    return Arith((a.v - b.v) % (1 << a.k), a.k,
                 ((a.t or 0) - (b.t or 0)) % (1 << a.k)
                 if a.t is not None and b.t is not None else None)


def make_segment(pc: PC, theta: str, content: Optional[bytes], h: int,
                 g: Optional[int] = None) -> Seg:
    """Instantiate a template segment on this party.

    P:          `content` is the public bytes (same on both sides), g = h.
    Af/Rf:      owner passes `content`; the other side passes None.  g = h.
    Xf:         each side passes its pad share via `content`; truth = xor.
                g = h.
    As/Rs:      owner passes `content` (<= h); non-owner passes None.
                g = true length, hidden (shared arith).
    Xs:         each side passes its pad share; truth = xor.  g hidden.
    """
    pad_content = (content or b"") + bytes(PAD for _ in range(h - len(content or b"")))
    if theta == P:
        s = C.pub_bytes(pc, pad_content)
        return Seg(theta, s, h, h)
    if theta in (AF, RF, XF):
        if theta == XF:
            s = _pad_share_bytes(pc, pad_content)
        else:
            owner = (theta == AF and pc.side == 0) or \
                    (theta == RF and pc.side == 1)
            s = C.share_byte_list(pc, owner, pad_content if owner
                                  else bytes(h))
        return Seg(theta, s, h, h)
    # variable-length
    if theta == XS:
        s = _pad_share_bytes(pc, pad_content)
    else:
        owner = (theta == AS and pc.side == 0) or \
                (theta == RS and pc.side == 1)
        s = C.share_byte_list(pc, owner, pad_content if owner else bytes(h))
    # the true length is contributed by the content owner (Xs: whoever set g)
    gowner = ((theta == AS and pc.side == 0)
            or (theta == RS and pc.side == 1)
            or (theta == XS and g is not None))
    gsh = pc.share_arith(gowner, g if gowner else 0, GK)
    return Seg(theta, s, gsh, h)


# ---------------------------------------------------------------------------
# Pi_LDC / Pi_SHC
# ---------------------------------------------------------------------------

def ldc(pc: PC, el: Seg, er: Seg) -> Seg:
    """Local deterministic concat (Protocol Pi_LDC): free, no interaction."""
    assert el.len_public
    gm = _arith_add(pc, _to_arith(pc, el.g), _to_arith(pc, er.g))
    if el.len_public and er.len_public:
        gm = el.g + er.g
        return Seg(XF, el.s + er.s, gm, el.h + er.h)
    return Seg(XS, el.s + er.s, gm, el.h + er.h)


def shc(pc: PC, el: Seg, er: Seg) -> Seg:
    """Structure-hiding concat (Protocol 1)."""
    hl, hr = el.h, er.h
    hm = hl + hr
    k = max(1, math.ceil(math.log2(hm)))
    va = el.s + [pc.const_bits(0, 8) for _ in range(hr)]
    v0 = [pc.const_bits(0, 8) for _ in range(hl)] + er.s
    d_a = _arith_sub(pc, _const_arith(pc, hl), _to_arith(pc, el.g))
    d_b = pc.slice(pc.a2b(d_a), 0, k)
    vb = pc.blind_rotate_left(v0, d_b)
    sm = [pc.xor(a, b) for a, b in zip(va, vb)]
    gm = _arith_add(pc, _to_arith(pc, el.g), _to_arith(pc, er.g))
    return Seg(XS, sm, gm, hm)


# ---------------------------------------------------------------------------
# Assembly plan Omega: DP over merge orders
# ---------------------------------------------------------------------------

def plan_assembly(thetas: Sequence[str], hs: Sequence[int]
                  ) -> List[Tuple[int, int, int]]:
    """DP: Gamma(i,j) = min_k Gamma(i,k)+Gamma(k+1,j)+Delta; Delta=0 iff the
    left range's length is public (all segments in it are P/fixed-len)."""
    L = len(thetas)
    pub = [[False] * L for _ in range(L)]
    for i in range(L):
        for j in range(i, L):
            pub[i][j] = all(thetas[t] in PUB_LEN for t in range(i, j + 1))
    hsum = [[0] * L for _ in range(L)]
    for i in range(L):
        for j in range(i, L):
            hsum[i][j] = sum(hs[i:j + 1])
    INF = float("inf")
    G = [[INF] * L for _ in range(L)]
    K = [[-1] * L for _ in range(L)]
    for i in range(L):
        G[i][i] = 0
    for w in range(2, L + 1):
        for i in range(L - w + 1):
            j = i + w - 1
            for k in range(i, j):
                hl, hr = hsum[i][k], hsum[k + 1][j]
                delta = 0 if pub[i][k] else (hl + hr) * \
                    max(1, math.ceil(math.log2(hl + hr)))
                c = G[i][k] + G[k + 1][j] + delta
                if c < G[i][j]:
                    G[i][j], K[i][j] = c, k
    steps: List[Tuple[int, int, int]] = []

    def emit(i: int, j: int) -> None:
        if i == j:
            return
        k = K[i][j]
        emit(i, k)
        emit(k + 1, j)
        steps.append((i, k, j))

    emit(0, L - 1)
    return steps


def assemble(pc: PC, segs: List[Seg],
             steps: Optional[List[Tuple[int, int, int]]] = None) -> Seg:
    """Run the assembly plan; returns the merged segment E[1,L]."""
    L = len(segs)
    if steps is None:
        steps = plan_assembly([s.theta for s in segs], [s.h for s in segs])
    tab = [[None] * L for _ in range(L)]
    for i, s in enumerate(segs):
        tab[i][i] = s
    for (i, k, j) in steps:
        el, er = tab[i][k], tab[k + 1][j]
        tab[i][j] = ldc(pc, el, er) if el.len_public else shc(pc, el, er)
    return tab[0][L - 1]


# ---------------------------------------------------------------------------
# Pi_I2S: shared integer -> shared ASCII decimal string (double dabble)
# ---------------------------------------------------------------------------

def i2s(pc: PC, g: Union[int, Arith], digits: int) -> Seg:
    """g (<= 10^digits - 1) -> ASCII decimal segment of fixed length `digits`
    with shared true length = `digits` (leading zeros are real bytes).
    Double-dabble: GK iterations of (nibble >= 5 -> +3, then shift left)."""
    ga = _to_arith(pc, g)
    gb = pc.a2b(ga)                        # GK-bit shared binary value
    bcd = [pc.const_bits(0, 4) for _ in range(digits)]  # bcd[0] = 1s digit
    for _ in range(GK):
        for dgt in range(digits):
            ge5 = _ge_const(pc, bcd[dgt], 5)
            bcd[dgt] = pc.mux(ge5, pc.add(bcd[dgt], pc.const_bits(3, 4)),
                              bcd[dgt])
        # shift: bit15 of gb enters bcd[0].0; carries ripple up the digits
        carry = pc.slice(gb, GK - 1, 1)
        gb = pc.slice(pc.shl_bits(gb, 1), 0, GK)
        for dgt in range(digits):
            nxt = pc.slice(bcd[dgt], 3, 1)
            bcd[dgt] = pc.slice(
                pc.concat(pc.slice(bcd[dgt], 0, 3), carry), 0, 4)
            carry = nxt
    out: List[Bits] = []
    for dgt in range(digits - 1, -1, -1):
        out.append(pc.concat(pc.const_bits(0x3, 4), bcd[dgt]))
    return Seg(XS, out, _const_arith(pc, digits), digits)


def _ge_const(pc: PC, x: Bits, c: int) -> Bits:
    """x >= c for small x: NOT the sign bit of (x - c) mod 2^(n+1)."""
    xa = pc.concat(pc.const_bits(0, 1), x)
    r = pc.sub(xa, pc.const_bits(c, xa.n))
    return pc.not_(pc.slice(r, xa.n - 1, 1))


# ---------------------------------------------------------------------------
# Pi_query: assemble + 2PC-AEAD + record wrap
# ---------------------------------------------------------------------------

def build_query(pc: PC, segs: List[Seg],
                steps: Optional[List[Tuple[int, int, int]]] = None
                ) -> List[Bits]:
    """Pi_query assembly stage: returns shared content bytes of E[1,L]."""
    return assemble(pc, segs, steps).s


def encrypt_query(pc: PC, q: Sequence[Bits], tk_capp_share: bytes,
                  iv_capp: bytes, aad: bytes) -> bytes:
    """Pi_2PC-AEAD: encrypt shared query under shared tk_capp -> public
    record body (ct || tag) both parties may see.  `tk_capp_share` is this
    party's own 16-byte share; the circuit key is tkA ^ tkR."""
    tkA = C.share_byte_list(pc, pc.side == 0, tk_capp_share)
    tkR = C.share_byte_list(pc, pc.side == 1, tk_capp_share)
    key = [pc.xor(a, b) for a, b in zip(tkA, tkR)]
    ct, tag = C.gcm_encrypt(pc, key, iv_capp, aad, q)
    return C.open_bytes(pc, ct + tag)


def query_record(pc: PC, q: Sequence[Bits], tk_capp_share: bytes,
                 iv_capp: bytes, *, use_sim_aead: bool = True) -> bytes:
    """Full Pi_query output: 5-byte header || ct || tag, open to both.
    Encrypts q as a TLS inner-plaintext (body || 0x17)."""
    inner = list(q) + [pc.const_bits(0x17, 8)]
    hdr = bytes([0x17, 0x03, 0x03]) + (len(inner) + 16).to_bytes(2, "big")
    if use_sim_aead:
        with pc.use(MODE_SIM):
            return hdr + encrypt_query(pc, inner, tk_capp_share, iv_capp, hdr)
    return hdr + encrypt_query(pc, inner, tk_capp_share, iv_capp, hdr)
