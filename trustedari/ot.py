"""Oblivious transfer: Chou-Orlandi base OT + IKNP-style OT extension.

Semi-honest model (the paper's threat model).  Base OTs run over secp256k1;
the extension expands them to large batches of OTs with symmetric crypto only.

Layout of an extension batch (sender -> receiver direction):
  * one-time base phase: extension *sender* picks s in {0,1}^ELL and runs ELL
    base OTs as *receiver* against the extension *receiver*, who supplies
    ELL random seed pairs (k0_i, k1_i).
  * per batch of m OTs: receiver sends U_i = G(k0_i) ^ G(k1_i) ^ r  (i<ELL,
    r = choice-bit vector of length m).  Sender forms Q_i = G(k_{s_i}) ^ s_i*U_i;
    row j then satisfies q_j = t_j ^ r_j*s, so encrypting (m0,m1) under
    masks derived from q_j / q_j^s lets the receiver open exactly its choice.
"""
from __future__ import annotations

import hashlib
from typing import List, Tuple

import numpy as np

from . import curve
from .channel import Chan

ELL = 128          # base-OT count / security parameter for the extension
SEED = 16          # seed bytes


def _prg(seed: bytes, out_bits: int) -> bytes:
    """Expand a seed to ceil(out_bits/8) bytes; tail bits zeroed."""
    n = (out_bits + 7) // 8
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(seed + ctr.to_bytes(4, "little")).digest()
        ctr += 1
    if out_bits % 8:
        out[-1] &= (1 << (out_bits % 8)) - 1
    return bytes(out[:n])


def _row_hash(row: bytes, idx: int, out_len: int) -> bytes:
    """Correlation-robust-ish mask: expand H(row || idx || ctr) to out_len."""
    out = bytearray()
    ctr = 0
    base = row + idx.to_bytes(8, "little")
    while len(out) < out_len:
        out += hashlib.sha256(base + ctr.to_bytes(4, "little")).digest()
        ctr += 1
    return bytes(out[:out_len])


def _cols_to_rows(cols: List[bytes], m: int) -> List[bytes]:
    """Transpose ELL columns of m bits -> m rows of ELL bits (16-byte each)."""
    nbytes = (m + 7) // 8
    arr = np.unpackbits(
        np.frombuffer(b"".join(cols), dtype=np.uint8).reshape(ELL, nbytes),
        axis=1, count=m, bitorder="little",
    )                                          # (ELL, m)
    rows = np.packbits(arr.T, axis=1, bitorder="little")  # (m, ELL/8)
    return [rows[j].tobytes() for j in range(m)]


class OTExt:
    """One-directional OT extension between two parties.

    role: 'sender' -> this party will supply message pairs;
          'receiver' -> this party will supply choice bits.
    `side` is this party's endpoint index on the channel (0/1).
    """

    def __init__(self, chan: Chan, side: int, role: str) -> None:
        self.chan = chan
        self.side = side          # my endpoint id (0 sends into _q[0])
        self.role = role
        self.ot_count = 0
        # state filled by base_init
        self.s = None             # sender only: int ELL-bit secret
        self.k_choice = None      # sender only: list of chosen seeds
        self.k0 = None            # receiver only: list of seeds
        self.k1 = None

    # ---- Chou-Orlandi base OTs -------------------------------------------
    def _co_send_many(self, pairs: List[Tuple[bytes, bytes]]) -> None:
        """We are the CO sender for len(pairs) OTs in one shot."""
        y = curve.rand_scalar()
        S = curve.point_mul(y)
        self.chan.send(self.side, "co.S", curve.ser_point(S))
        for i, (m0, m1) in enumerate(pairs):
            Rb = curve.deser_point(self.chan.recv(self.side, f"co.R{i}"))
            k0 = curve.hash_point(curve.point_mul(y, Rb), b"co0")
            k1 = curve.hash_point(
                curve.point_mul(y, curve.point_sub(Rb, S)), b"co1")
            e0 = bytes(a ^ b for a, b in zip(m0, k0))
            e1 = bytes(a ^ b for a, b in zip(m1, k1))
            self.chan.send(self.side, f"co.e{i}", e0 + e1)

    def _co_recv_many(self, choices: List[int], mlen: int) -> List[bytes]:
        """We are the CO receiver; returns chosen messages."""
        S = curve.deser_point(self.chan.recv(self.side, "co.S"))
        out = []
        for i, b in enumerate(choices):
            x = curve.rand_scalar()
            Rb = curve.point_mul(x)
            if b:
                Rb = curve.point_add(Rb, S)
            self.chan.send(self.side, f"co.R{i}", curve.ser_point(Rb))
            k = curve.hash_point(curve.point_mul(x, S), b"co0" if b == 0 else b"co1")
            # NOTE: for b=0 key is H(xS,co0) matching sender's k0; for b=1 the
            # sender's k1 = H(y(R-S)) = H(xS) - use same label co1 there.
            e = self.chan.recv(self.side, f"co.e{i}")
            e_b = e[mlen * b: mlen * (b + 1)]
            out.append(bytes(a ^ c for a, c in zip(e_b, k)))
        return out

    def base_init(self) -> None:
        """Run the one-time base OTs (roles swapped vs extension direction)."""
        if self.role == "sender":
            s = int.from_bytes(curve.hash_point(
                curve.point_mul(curve.rand_scalar()), b"iknp.s"), "little") & ((1 << ELL) - 1)
            self.s = s
            choices = [(s >> i) & 1 for i in range(ELL)]
            self.k_choice = self._co_recv_many(choices, SEED)
        else:
            self.k0 = [curve.hash_point(
                curve.point_mul(curve.rand_scalar()), b"iknp.k")[:SEED]
                for _ in range(ELL)]
            self.k1 = [curve.hash_point(
                curve.point_mul(curve.rand_scalar()), b"iknp.k2")[:SEED]
                for _ in range(ELL)]
            self._co_send_many(list(zip(self.k0, self.k1)))

    # ---- extension batches ------------------------------------------------
    def send(self, m0s: bytes, m1s: bytes, m: int, w: int) -> None:
        """Sender: m OTs, payloads w bytes each (m0s/m1s = m*w bytes)."""
        assert self.role == "sender" and len(m0s) == len(m1s) == m * w
        U = [self.chan.recv(self.side, f"u{i}") for i in range(ELL)]
        s_bytes = self.s.to_bytes(ELL // 8, "little")
        qcols = []
        for i in range(ELL):
            g = _prg(self.k_choice[i], m)
            if (self.s >> i) & 1:
                g = bytes(a ^ b for a, b in zip(g, U[i]))
            qcols.append(g)
        qrows = _cols_to_rows(qcols, m)
        e0 = bytearray(m * w)
        e1 = bytearray(m * w)
        for j in range(m):
            mask0 = _row_hash(qrows[j], j, w)
            qx = bytes(a ^ b for a, b in zip(qrows[j], s_bytes))
            mask1 = _row_hash(qx, j, w)
            base = j * w
            for t in range(w):
                e0[base + t] = m0s[base + t] ^ mask0[t]
                e1[base + t] = m1s[base + t] ^ mask1[t]
        self.chan.send(self.side, "e0", bytes(e0))
        self.chan.send(self.side, "e1", bytes(e1))
        self.ot_count += m

    def recv_start(self, choices: bytes, m: int, w: int) -> None:
        """Receiver phase 1: build and send the U columns (non-blocking).

        Split into two phases so a bidirectional batch can send its U's
        before either side blocks waiting for masked payloads.
        """
        assert self.role == "receiver" and len(choices) == (m + 7) // 8
        self._choices = choices
        self._m = m
        self._w = w
        for i in range(ELL):
            g0 = _prg(self.k0[i], m)
            g1 = _prg(self.k1[i], m)
            u = bytes(a ^ b ^ c for a, b, c in zip(g0, g1, choices))
            self.chan.send(self.side, f"u{i}", u)

    def recv_finish(self) -> bytes:
        """Receiver phase 2: read masked payloads, decrypt chosen messages."""
        choices, m, w = self._choices, self._m, self._w
        tcols = [_prg(self.k0[i], m) for i in range(ELL)]
        trows = _cols_to_rows(tcols, m)
        e0 = self.chan.recv(self.side, "e0")
        e1 = self.chan.recv(self.side, "e1")
        out = bytearray(m * w)
        for j in range(m):
            b = (choices[j // 8] >> (j % 8)) & 1
            e = e1 if b else e0
            mask = _row_hash(trows[j], j, w)
            base = j * w
            for t in range(w):
                out[base + t] = e[base + t] ^ mask[t]
        self.ot_count += m
        return bytes(out)
