"""Verifiable billing (paper Section 6 / Figure 6).

Deviation note: the paper instantiates Ckt(X,W) as a gnark PLONK proof
(BN254/MiMC).  This reproduction runs the *same arithmetic relation* as an
interactive two-party circuit (A = prover, R = verifier) over the existing
OT-based engine -- a fair stand-in for the ZK proof since R learns only the
accept bit.  All circuit logic below is paper-faithful.

Public statement X = (tk_R_sapp, com_A, R_hat, r, phi, v, omega, d_t, j, k)
Private witness W = tk_A_sapp   (R_local is derived in-circuit)

  com_A ?= H(tk_A_sapp || r)                     -- commitment re-check
  tk_sapp = tk_A_sapp ^ tk_R_sapp                -- reconstruct
  R_local = Dec_tk_sapp(R_hat[omega])            -- AES-CTR window decrypt
  string/escape/depth FSM over R_local (fwd or rev per omega)
  R_local[j..k] ?= phi:v at depth d_t
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Sequence, Tuple

from . import circuits as C
from .twopc import PC, Bits, MODE_SIM

FWD, REV = "fwd", "rev"


@dataclass
class Window:
    o: int          # start block offset into the record ciphertext
    blocks: int     # number of 16B blocks
    rho: str        # parsing direction
    j: int          # pair start, relative to window plaintext
    k: int          # pair end (inclusive), relative to window plaintext


def select_window(ct_body_len: int, pair_start: int, pair_end: int) -> Window:
    """Adaptive boundary-anchored window selection (paper Sec. 6): a prefix
    window parsed forward from the JSON start vs a suffix window parsed
    backward from the JSON terminal boundary; the shorter wins."""
    nb = (ct_body_len + 15) // 16
    fwd_blocks = (pair_end + 15) // 16                      # [0, fwd)
    rev_start_blk = pair_start // 16
    rev_blocks = nb - rev_start_blk                         # [rev_start, nb)
    if rev_blocks < fwd_blocks:
        o = rev_start_blk
        return Window(o, rev_blocks, REV,
                      pair_start - 16 * o, pair_end - 16 * o - 1)
    return Window(0, fwd_blocks, FWD, pair_start, pair_end - 1)


# ---------------------------------------------------------------------------
# in-circuit primitives
# ---------------------------------------------------------------------------

def _eq8(pc: PC, b: Bits, c: int) -> Bits:
    return pc.eq_const(b, c)


def _andb(pc: PC, a: Bits, b: Bits) -> Bits:
    assert a.n == 1 and b.n == 1
    return pc.and_pairs([(a, b)])[0]


def _notb(pc: PC, a: Bits) -> Bits:
    return pc.xor(a, pc.const_bits(1, 1))


def _nandb(pc: PC, a: Bits, b: Bits) -> Bits:
    return _notb(pc, _andb(pc, a, b))


def _dec_window(pc: PC, tk: Sequence[Bits], iv: bytes,
                ct_win: bytes, o: int = 0) -> List[Bits]:
    """AES-CTR decrypt of ct_win = blocks [o, o+l) of the record body.
    Data block index i uses counter iv || BE32(i+2); here i = o + t."""
    pt: List[Bits] = []
    nblk = (len(ct_win) + 15) // 16
    for t in range(nblk):
        ctr = C.pub_bytes(pc, iv + (o + t + 2).to_bytes(4, "big"))
        ks = C.aes128_enc(pc, key=tk, pt=ctr)
        for j in range(16):
            idx = 16 * t + j
            if idx < len(ct_win):
                pt.append(pc.xor(pc.const_bits(ct_win[idx], 8), ks[j]))
    return pt


def _parse_fwd(pc: PC, cs: List[Bits]) -> Tuple[List[Bits], List[Bits]]:
    """Returns (b, d): b[i] = in-string state *before* byte i,
    d[i] = depth before byte i (8-bit two's complement)."""
    b: List[Bits] = []   # in-string state after processing byte i-1
    d: List[Bits] = []   # depth after processing byte i-1
    b_prev = pc.const_bits(0, 1)
    d_prev = pc.const_bits(0, 8)
    e_prev = pc.const_bits(0, 1)
    b_arr: List[Bits] = []
    d_arr: List[Bits] = []
    for c in cs:
        k34 = _eq8(pc, c, 34)     # '"'
        k92 = _eq8(pc, c, 92)     # '\'
        k123 = _eq8(pc, c, 123)   # '{'
        k125 = _eq8(pc, c, 125)   # '}'
        ne = _notb(pc, e_prev)
        e_i = _andb(pc, _andb(pc, ne, b_prev), k92)
        tog = _andb(pc, k34, ne)
        b_i = pc.xor(b_prev, tog)
        act = _notb(pc, b_prev)
        d_next = pc.add(
            pc.sub(d_prev,
                   pc.concat(pc.const_bits(0, 7),
                             _andb(pc, act, k125))),
            pc.concat(pc.const_bits(0, 7), _andb(pc, act, k123)))
        b_arr.append(b_prev)
        d_arr.append(d_prev)
        b_prev, d_prev, e_prev = b_i, d_next, e_i
    return b_arr, d_arr


def _parse_rev(pc: PC, cs: List[Bits],
               escapes_fwd: List[Bits]) -> Tuple[List[Bits], List[Bits]]:
    """Backward scan: r[i] = inside-string at position i, d[i] = depth at i
    (equal to forward depth-before-i).  Escapes are local, computed forward.
    """
    m = len(cs)
    r = [pc.const_bits(0, 1)] * m          # r[i]: position i inside string
    d = [pc.const_bits(0, 8)] * m          # depth at position i
    r_next = pc.const_bits(0, 1)
    d_next = pc.const_bits(0, 8)
    for i in range(m - 1, -1, -1):
        # r_i = r_{i+1} unless c_i is a real (unescaped) '"' -> then toggle
        realq = _andb(pc, _eq8(pc, cs[i], 34), _notb(pc, escapes_fwd[i]))
        r_i = pc.xor(r_next, realq)
        r[i] = r_i
        k123 = _eq8(pc, cs[i], 123)
        k125 = _eq8(pc, cs[i], 125)
        act = _notb(pc, r_i)
        d[i] = pc.add(
            pc.sub(d_next,
                   pc.concat(pc.const_bits(0, 7), _andb(pc, act, k123))),
            pc.concat(pc.const_bits(0, 7), _andb(pc, act, k125)))
        r_next, d_next = r_i, d[i]
    return r, d


def _escapes(pc: PC, cs: List[Bits]) -> List[Bits]:
    """e_i = c_i is inside a string AND preceded by an active backslash run.
    Forward recurrence needs string state too; compute (b, e) jointly."""
    b_prev = pc.const_bits(0, 1)
    e_prev = pc.const_bits(0, 1)
    out = []
    for c in cs:
        k34 = _eq8(pc, c, 34)
        k92 = _eq8(pc, c, 92)
        ne = _notb(pc, e_prev)
        out.append(e_prev)          # e for NEXT byte is this byte's e state
        e_prev = _andb(pc, _andb(pc, ne, b_prev), k92)
        # careful: e_i (as "c_i is escaped") = e_{i-1}_active; store that.
        b_prev = pc.xor(b_prev, _andb(pc, k34, ne))
    return out


# ---------------------------------------------------------------------------
# the billing relation
# ---------------------------------------------------------------------------

def verify_billing(pc: PC, *, tk_share: bytes, com_A: bytes, r: bytes,
                   record: bytes, iv_sapp: bytes, win: Window,
                   pair_bytes: bytes, d_t: int) -> int:
    """Run Ckt(X, W).  Returns accept bit (1/0), opened to both parties.

    tk_share : this party's 16-byte share of tk_sapp.
    record   : full TLS response record (public input R_hat).
    win      : selected window descriptor.
    pair_bytes: the exact byte pattern '"<phi>":<v>' enforced at j..k.
    """
    aad = record[:5]
    body = record[5:]
    ct_win = body[16 * win.o:16 * (win.o + win.blocks)]

    # each side contributes its own 16B share of tk_sapp
    tkA = C.share_byte_list(pc, pc.side == 0, tk_share)
    tkR = C.share_byte_list(pc, pc.side == 1, tk_share)
    tk_full = [pc.xor(a, b) for a, b in zip(tkA, tkR)]

    # (1) commitment check: com_A = H(tk_A || r)
    com = C.sha256_digest_bytes(pc, tkA + C.pub_bytes(pc, r))
    com_ok = _fold_and(pc, [_eq8(pc, cb, com_A[i])
                            for i, cb in enumerate(com)])

    # (2) decrypt window -> R_local shares
    pt = _dec_window(pc, tk_full, iv_sapp, ct_win, win.o)

    # (3) parser FSM
    if win.rho == FWD:
        b_arr, d_arr = _parse_fwd(pc, pt)
        in_str = b_arr
    else:
        esc = _escapes(pc, pt)
        in_str, d_arr = _parse_rev(pc, pt, esc)

    # (4) enforce pair bytes and depth
    n = len(pair_bytes)
    assert win.k - win.j + 1 == n
    byte_ok = _fold_and(pc, [_eq8(pc, pt[win.j + t], pair_bytes[t])
                             for t in range(n)])
    dep_ok = pc.eq_const(d_arr[win.j], d_t)
    accept = _fold_and(pc, [com_ok, byte_ok, dep_ok])
    return pc.open(accept)


def _fold_and(pc: PC, bits: List[Bits]) -> Bits:
    cur = bits
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur) - 1, 2):
            nxt.append((cur[i], cur[i + 1]))
        if len(cur) % 2:
            nxt.append((cur[-1], pc.const_bits(1, 1)))
        cur = pc.and_pairs(nxt)
    return cur[0]
