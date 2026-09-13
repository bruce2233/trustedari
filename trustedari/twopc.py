"""Two-party computation engine (semi-honest GMW over IKNP OT extension).

Share domains
-------------
* ``Bits``  : XOR-shared bit-string (each party holds one int share ``v``).
* ``Arith`` : additively shared integer mod 2**k  (used for hidden lengths).
* ``Fld``   : additively shared element of the secp256k1 base field (ECtF).

Backends
--------
* ``mode='ot'``  -- every AND/multiplication is executed with the real
  IKNP-extended Chou-Orlandi OT protocol over the party channel.
* ``mode='sim'`` -- simulation accelerator: gate results are resolved through
  truth values carried on the share objects (a trusted-evaluator stand-in for
  "the 2PC backend evaluates circuit C").  Party views keep identical
  semantics: each side only sees its own random shares plus protocol
  messages.  We use it for the large *standard* crypto circuits
  (SHA-256 / AES / GHASH) where a pure-Python OT evaluation would take tens
  of minutes; the paper-faithful protocol pieces (SHC / I2S / ECtF / billing
  parser) still run under 'ot'.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import List, Optional, Sequence, Tuple

from .channel import Chan
from .curve import P as FIELD_P
from .ot import OTExt

MODE_OT = "ot"
MODE_SIM = "sim"


class Bits:
    __slots__ = ("v", "n", "t")

    def __init__(self, v: int, n: int, t: Optional[int] = None):
        self.v = v          # my party's share (int, n bits)
        self.n = n          # bit length
        self.t = t          # sim-only: true value (None in ot mode)


class Arith:
    __slots__ = ("v", "k", "t")

    def __init__(self, v: int, k: int, t: Optional[int] = None):
        self.v = v
        self.k = k
        self.t = t


class Fld:
    __slots__ = ("v", "t")

    def __init__(self, v: int, t: Optional[int] = None):
        self.v = v
        self.t = t


def _det(vid: int, mod: int) -> int:
    return int.from_bytes(
        hashlib.sha256(b"tsplit" + vid.to_bytes(8, "little")).digest(),
        "little") % mod


class World:
    def __init__(self) -> None:
        self.chan_ar = Chan()       # agent <-> ARI
        self.chan_rs = Chan()       # ARI <-> provider


class PC:
    """One party's 2PC context."""

    def __init__(self, world: World, chan: Chan, side: int,
                 mode: str = MODE_OT):
        self.world = world
        self.chan = chan
        self.side = side
        self.mode = mode
        self.ot_send = OTExt(chan, side, "sender")
        self.ot_recv = OTExt(chan, side, "receiver")
        self.ot_rounds = 0
        self._mode_stack: List[str] = []
        self._split_ctr = 0

    # -- init --------------------------------------------------------------
    def _ensure_ot(self) -> None:
        """Lazy one-time base OTs. Order is side-dependent: side1 must run the
        CO-sender half (ot_recv.base_init) before its CO-receiver half, or both
        parties block waiting for the peer's S point."""
        if self.ot_send.k_choice is not None or self.mode == MODE_SIM:
            return
        if self.side == 0:
            self.ot_send.base_init()
            self.ot_recv.base_init()
        else:
            self.ot_recv.base_init()
            self.ot_send.base_init()

    def init_ot(self) -> None:
        self._ensure_ot()

    # -- mode switching -----------------------------------------------------
    def use(self, mode: str) -> "PC":
        """Context manager: temporarily switch evaluation backend."""
        self._mode_stack.append(self.mode)
        self.mode = mode
        if mode == MODE_OT:
            self._ensure_ot()
        return self

    def __enter__(self) -> "PC":
        return self

    def __exit__(self, *exc) -> bool:
        self.mode = self._mode_stack.pop()
        return False

    # ------------------------------------------------------------------
    # sim helpers
    # ------------------------------------------------------------------
    def _split_int(self, truth: int, mod: int, additive: bool) -> int:
        """Deterministic consistent split: side0 gets pad, side1 the rest."""
        self._split_ctr += 1
        pad = _det(self._split_ctr, mod)
        if self.side == 0:
            return pad
        if additive:
            return (truth - pad) % mod
        return truth ^ pad

    def _sim_truth(self, owner: bool, value: int, n: int) -> int:
        """In sim mode the owner ships the truth so both sides annotate `.t`
        identically (cheap in-memory channel; correctness annotation only)."""
        nb = (n + 7) // 8
        if owner:
            self.chan.send(self.side, "sim.t", value.to_bytes(nb, "little"))
            return value
        return int.from_bytes(self.chan.recv(self.side, "sim.t"), "little")

    # ------------------------------------------------------------------
    # share creation / opening
    # ------------------------------------------------------------------
    def share_bits(self, owner: bool, value: int, n: int) -> Bits:
        mask = (1 << n) - 1
        if self.mode == MODE_SIM:
            t = self._sim_truth(owner, value, n)
            v = self._split_int(t, 1 << n, additive=False)
            return Bits(v, n, t)
        if owner:
            r = secrets.randbits(n)
            self.chan.send(self.side, "shb", r.to_bytes((n + 7) // 8, "little"))
            return Bits((value ^ r) & mask, n)
        return Bits(int.from_bytes(self.chan.recv(self.side, "shb"), "little"), n)

    def share_bytes(self, owner: bool, data: bytes) -> Bits:
        return self.share_bits(owner, int.from_bytes(data, "little"),
                               8 * len(data))

    def share_arith(self, owner: bool, value: int, k: int) -> Arith:
        mod = 1 << k
        if self.mode == MODE_SIM:
            t = self._sim_truth(owner, value % mod, k)
            v = self._split_int(t, mod, additive=True)
            return Arith(v, k, t)
        if owner:
            r = secrets.randbelow(mod)
            self.chan.send(self.side, "sha", r.to_bytes((k + 7) // 8, "little"))
            return Arith((value - r) % mod, k)
        return Arith(int.from_bytes(self.chan.recv(self.side, "sha"), "little"), k)

    def share_field(self, owner: bool, value: int) -> Fld:
        if self.mode == MODE_SIM:
            t = self._sim_truth(owner, value % FIELD_P, 256)
            v = self._split_int(t, FIELD_P, additive=True)
            return Fld(v, t)
        if owner:
            r = secrets.randbelow(FIELD_P)
            self.chan.send(self.side, "shf", r.to_bytes(32, "little"))
            return Fld((value - r) % FIELD_P)
        return Fld(int.from_bytes(self.chan.recv(self.side, "shf"), "little"))

    def const_bits(self, value: int, n: int) -> Bits:
        """Public constant: A holds it, R holds 0 (consistent share)."""
        value &= (1 << n) - 1
        t = value if self.mode == MODE_SIM else None
        return Bits(value if self.side == 0 else 0, n, t)

    def rand_bits(self, n: int) -> Bits:
        """Joint random Bits: truth unknown to each party (xor of two pads)."""
        if self.mode == MODE_SIM:
            self._split_ctr += 1
            s0 = _det(self._split_ctr, 1 << n)
            s1 = _det(self._split_ctr + (1 << 40), 1 << n)
            return Bits(s0 if self.side == 0 else s1, n, s0 ^ s1)
        return Bits(secrets.randbits(n), n)

    def rand_field(self) -> Fld:
        if self.mode == MODE_SIM:
            self._split_ctr += 1
            s0 = _det(self._split_ctr, FIELD_P)
            s1 = _det(self._split_ctr + (1 << 40), FIELD_P)
            return Fld(s0 if self.side == 0 else s1, (s0 + s1) % FIELD_P)
        return Fld(secrets.randbelow(FIELD_P))

    def rand_arith(self, k: int) -> Arith:
        if self.mode == MODE_SIM:
            self._split_ctr += 1
            s0 = _det(self._split_ctr, 1 << k)
            s1 = _det(self._split_ctr + (1 << 40), 1 << k)
            return Arith(s0 if self.side == 0 else s1, k, (s0 + s1) % (1 << k))
        return Arith(secrets.randbelow(1 << k), k)

    # -- opening -------------------------------------------------------------
    def _share_len(self, x) -> int:
        if isinstance(x, Bits):
            return x.n
        if isinstance(x, Arith):
            return x.k
        return 256

    def open(self, x) -> int:
        n = self._share_len(x)
        self.chan.send(self.side, "op", x.v.to_bytes((n + 7) // 8, "little"))
        peer = int.from_bytes(self.chan.recv(self.side, "op"), "little")
        if isinstance(x, Bits):
            return x.v ^ peer
        if isinstance(x, Arith):
            return (x.v + peer) % (1 << x.k)
        return (x.v + peer) % FIELD_P

    def open_to(self, x, to_side: int):
        """Only party `to_side` learns the value."""
        n = self._share_len(x)
        if self.side == to_side:
            peer = int.from_bytes(self.chan.recv(self.side, "op"), "little")
            if isinstance(x, Bits):
                return x.v ^ peer
            if isinstance(x, Arith):
                return (x.v + peer) % (1 << x.k)
            return (x.v + peer) % FIELD_P
        self.chan.send(self.side, "op", x.v.to_bytes((n + 7) // 8, "little"))
        return None

    # -- helpers --------------------------------------------------------------
    def _pack(self, pieces: Sequence[Bits]) -> Bits:
        """Concatenate LSB-first: pieces[0] occupies the lowest bits."""
        v = 0
        shift = 0
        t = None
        for p in pieces:
            v |= p.v << shift
            if p.t is not None:
                t = (t or 0) | (p.t << shift)
            shift += p.n
        return Bits(v, shift, t if self.mode == MODE_SIM else None)

    def _unpack(self, x: Bits, sizes: Sequence[int]) -> List[Bits]:
        out = []
        shift = 0
        for n in sizes:
            v = (x.v >> shift) & ((1 << n) - 1)
            t = (x.t >> shift) & ((1 << n) - 1) if x.t is not None else None
            out.append(Bits(v, n, t))
            shift += n
        return out

    # -- local ops ------------------------------------------------------------
    def xor(self, a: Bits, b: Bits) -> Bits:
        assert a.n == b.n
        t = (a.t ^ b.t) if (a.t is not None and b.t is not None) else None
        return Bits(a.v ^ b.v, a.n, t)

    def not_(self, a: Bits) -> Bits:
        t = a.t ^ ((1 << a.n) - 1) if a.t is not None else None
        v = a.v ^ ((1 << a.n) - 1) if self.side == 0 else a.v
        return Bits(v, a.n, t)

    def shl_bits(self, a: Bits, s: int) -> Bits:
        mask = (1 << a.n) - 1
        t = (a.t << s) & mask if a.t is not None else None
        return Bits((a.v << s) & mask, a.n, t)

    def shr_bits(self, a: Bits, s: int) -> Bits:
        t = a.t >> s if a.t is not None else None
        return Bits(a.v >> s, a.n, t)

    def rotl(self, a: Bits, s: int) -> Bits:
        mask = (1 << a.n) - 1
        s %= a.n
        v = ((a.v << s) | (a.v >> (a.n - s))) & mask
        t = ((a.t << s) | (a.t >> (a.n - s))) & mask if a.t is not None else None
        return Bits(v, a.n, t)

    def rotr(self, a: Bits, s: int) -> Bits:
        return self.rotl(a, a.n - s)

    def concat(self, hi: Bits, lo: Bits) -> Bits:
        t = (hi.t << lo.n) | lo.t if (hi.t is not None and lo.t is not None) \
            else None
        return Bits((hi.v << lo.n) | lo.v, hi.n + lo.n, t)

    def slice(self, a: Bits, lo: int, n: int) -> Bits:
        m = (1 << n) - 1
        t = (a.t >> lo) & m if a.t is not None else None
        return Bits((a.v >> lo) & m, n, t)

    def rep_bit(self, b: Bits, n: int) -> Bits:
        assert b.n == 1
        t = (b.t & 1) * ((1 << n) - 1) if b.t is not None else None
        return Bits(b.v * ((1 << n) - 1), n, t)

    def bits_to_bytes(self, x: Bits) -> Bits:
        return x  # int storage is already little-endian byte order

    # -- interactive ops ------------------------------------------------------
    def and_bits(self, a: Bits, b: Bits) -> Bits:
        """GMW AND of equal-width shares; one bidirectional OT round."""
        assert a.n == b.n
        m = a.n
        if self.mode == MODE_SIM:
            assert a.t is not None and b.t is not None, \
                "sim AND on un-annotated shares (t=None)"
            t = a.t & b.t
            v = self._split_int(t, 1 << m, additive=False)
            return Bits(v, m, t)

        self._ensure_ot()
        # direction 1: I am the receiver (choices = my share bits of a)
        nbytes = (m + 7) // 8
        self.ot_recv.recv_start(a.v.to_bytes(nbytes, "little"), m, 1)
        # direction 2: I am the sender (peer's choices = its share bits of a)
        rints = [secrets.randbelow(2) for _ in range(m)]
        m0 = bytearray(m)
        m1 = bytearray(m)
        for i in range(m):
            m0[i] = rints[i]
            m1[i] = rints[i] ^ ((b.v >> i) & 1)
        self.ot_send.send(bytes(m0), bytes(m1), m, 1)
        got = self.ot_recv.recv_finish()
        rsent = 0
        for i in range(m):
            rsent |= rints[i] << i
        rrecv = 0
        for i in range(m):
            rrecv |= (got[i] & 1) << i
        return Bits(((a.v & b.v) ^ rsent ^ rrecv) & ((1 << m) - 1), m)

    def and_pairs(self, pairs: Sequence[Tuple[Bits, Bits]]) -> List[Bits]:
        """Batched AND: all pairs evaluated in a single OT round."""
        if not pairs:
            return []
        a = self._pack([p[0] for p in pairs])
        b = self._pack([p[1] for p in pairs])
        z = self.and_bits(a, b)
        return self._unpack(z, [p[0].n for p in pairs])

    def mux(self, sel: Bits, x1: Bits, x0: Bits) -> Bits:
        """sel ? x1 : x0 elementwise. One AND round."""
        assert sel.n == 1 and x1.n == x0.n
        return self.xor(x0, self.and_bits(self.rep_bit(sel, x0.n),
                                          self.xor(x0, x1)))

    def mux_bytes(self, sel: Bits, x1: List[Bits], x0: List[Bits]) -> List[Bits]:
        if not x1:
            return []
        diffs = self._pack([self.xor(x0[i], x1[i]) for i in range(len(x1))])
        selrep = self._pack([self.rep_bit(sel, 8) for _ in range(len(x1))])
        z = self.and_bits(selrep, diffs)
        zs = self._unpack(z, [8] * len(x1))
        return [self.xor(x0[i], zs[i]) for i in range(len(x1))]

    # -- arithmetic on Bits ----------------------------------------------------
    def add(self, a: Bits, b: Bits) -> Bits:
        """Kogge-Stone parallel-prefix adder, mod 2**a.n (log-depth ANDs)."""
        n = a.n
        g, p = self.and_pairs([(a, b)])[0], self.xor(a, b)
        l = 1
        while l < n:
            t1, t2 = self.and_pairs([(p, self.shl_bits(g, l)),
                                     (p, self.shl_bits(p, l))])
            g, p = self.xor(g, t1), t2
            l <<= 1
        return self.xor(self.xor(a, b), self.shl_bits(g, 1))

    def sub(self, a: Bits, b: Bits) -> Bits:
        return self.add(a, self.add(self.not_(b), self.const_bits(1, a.n)))

    def eq_const(self, a: Bits, c: int) -> Bits:
        """1-bit share: [a == c]."""
        inv = self.not_(self.xor(a, self.const_bits(c, a.n)))
        cur = self._unpack(inv, [1] * a.n)
        while len(cur) > 1:
            lvl = []
            for i in range(0, len(cur) - 1, 2):
                lvl.append((cur[i], cur[i + 1]))
            if len(cur) % 2:
                lvl.append((cur[-1], self.const_bits(1, 1)))
            cur = self.and_pairs(lvl)
        return cur[0]

    def eq(self, a: Bits, b: Bits) -> Bits:
        return self.eq_const_bits(self.xor(a, b))

    def eq_const_bits(self, d: Bits) -> Bits:
        inv = self.not_(d)
        cur = self._unpack(inv, [1] * d.n)
        while len(cur) > 1:
            lvl = []
            for i in range(0, len(cur) - 1, 2):
                lvl.append((cur[i], cur[i + 1]))
            if len(cur) % 2:
                lvl.append((cur[-1], self.const_bits(1, 1)))
            cur = self.and_pairs(lvl)
        return cur[0]

    # -- domain conversions ---------------------------------------------------
    def _share_int_as_bits(self, value_on_side: int, owner_side: int,
                           n: int) -> Bits:
        """Bits whose truth is a party-private int held by owner_side."""
        if self.mode == MODE_SIM:
            v = self._split_int(value_on_side, 1 << n, additive=False)
            return Bits(v, n, value_on_side)
        return Bits(value_on_side if self.side == owner_side else 0, n)

    def a2b(self, a: Arith) -> Bits:
        """Arithmetic mod 2**k -> bitwise sharing (secure adder on share bits)."""
        if self.mode == MODE_SIM and a.t is not None:
            mine = a.v
            peer = (a.t - mine) % (1 << a.k)
            op0 = mine if self.side == 0 else peer
            op1 = peer if self.side == 0 else mine
            b0 = Bits(op0 if self.side == 0 else 0, a.k, op0)
            b1 = Bits(op1 if self.side == 1 else 0, a.k, op1)
            return self.add(b0, b1)
        b0 = Bits(a.v if self.side == 0 else 0, a.k)
        b1 = Bits(a.v if self.side == 1 else 0, a.k)
        return self.add(b0, b1)

    def b2a(self, x: Bits) -> Arith:
        """XOR shares -> additive shares mod 2**x.n.

        Identity: x0 ^ x1 = x0 + x1 - 2*(x0 & x1).  The doubled-AND term is
        produced directly as *additive* shares via n OTs of w = ceil(n/8)
        bytes: as sender I offer (s_j, s_j + x_j*2^j); as receiver I choose on
        my share bits.  Recv_j = s_j^peer + x_j*peer_j*2^j, so
        sum_j Recv_j - sum_j s_j^me is an additive share of 2*(x0 & x1).
        """
        n = x.n
        mod = 1 << n
        if self.mode == MODE_SIM:
            t = x.t % mod if x.t is not None else 0
            v = self._split_int(t, mod, additive=True)
            return Arith(v, n, x.t)
        self._ensure_ot()
        w = (n + 7) // 8
        self.ot_recv.recv_start(x.v.to_bytes(w, "little"), n, w)
        m0 = bytearray(n * w)
        m1 = bytearray(n * w)
        rsums = 0
        for j in range(n):
            s = secrets.randbelow(mod)
            rsums = (rsums + s) % mod
            off = j * w
            m0[off:off + w] = s.to_bytes(w, "little")
            m1[off:off + w] = ((s + (((x.v >> j) & 1) << j)) % mod) \
                .to_bytes(w, "little")
        self.ot_send.send(bytes(m0), bytes(m1), n, w)
        got = self.ot_recv.recv_finish()
        recv_sum = 0
        for j in range(n):
            recv_sum = (recv_sum + int.from_bytes(
                got[j * w:(j + 1) * w], "little")) % mod
        and2 = (recv_sum - rsums) % mod          # share of 2*(x0 & x1)
        return Arith((x.v - and2) % mod, n)

    # -- structure-hiding rotation --------------------------------------------
    def blind_rotate_left(self, v: List[Bits], d_bits: Bits) -> List[Bits]:
        """Protocol 5 (Pi_BlindRotate): oblivious left-shift of byte vector v
        by a secret distance d (bit-decomposed share), zero-fill overflow."""
        n = len(v)
        if n == 0:
            return []
        cur = list(v)
        for l in range(d_bits.n):
            d_l = self.slice(d_bits, l, 1)
            delta = 1 << l
            x1 = [cur[i + delta] if i + delta < n else self.const_bits(0, 8)
                  for i in range(n)]
            cur = self.mux_bytes(d_l, x1, cur)
        return cur

    # -- field ops (for ECtF) ---------------------------------------------------
    def fadd(self, a: Fld, b: Fld) -> Fld:
        t = (a.t + b.t) % FIELD_P if (a.t is not None and b.t is not None) else None
        return Fld((a.v + b.v) % FIELD_P, t)

    def fsub(self, a: Fld, b: Fld) -> Fld:
        t = (a.t - b.t) % FIELD_P if (a.t is not None and b.t is not None) else None
        return Fld((a.v - b.v) % FIELD_P, t)

    def fmul(self, a: Fld, b: Fld) -> Fld:
        """Shared field multiplication via 256 parallel 32-byte OTs each way."""
        if self.mode == MODE_SIM:
            t = (a.t * b.t) % FIELD_P if (a.t is not None and b.t is not None) \
                else None
            v = self._split_int(t or 0, FIELD_P, additive=True)
            return Fld(v, t)
        self._ensure_ot()
        # direction 1: I receive; choices = bits of my a-share
        choices = a.v.to_bytes(32, "little")
        self.ot_recv.recv_start(choices, 256, 32)
        # direction 2: I send; pair (r_j, r_j + b*2^j)
        rsums = 0
        m0 = bytearray(256 * 32)
        m1 = bytearray(256 * 32)
        for j in range(256):
            r = secrets.randbelow(FIELD_P)
            rsums = (rsums + r) % FIELD_P
            off = j * 32
            m0[off:off + 32] = r.to_bytes(32, "little")
            m1[off:off + 32] = ((r + (b.v << j)) % FIELD_P) \
                .to_bytes(32, "little")
        self.ot_send.send(bytes(m0), bytes(m1), 256, 32)
        got = self.ot_recv.recv_finish()
        my_sum = (a.v * b.v) % FIELD_P
        for j in range(256):
            my_sum = (my_sum + int.from_bytes(
                got[j * 32:(j + 1) * 32], "little")) % FIELD_P
        return Fld((my_sum - rsums) % FIELD_P)

    def fmul_pub(self, a: Fld, c: int) -> Fld:
        t = (a.t * c) % FIELD_P if a.t is not None else None
        return Fld((a.v * c) % FIELD_P, t)

    def finv(self, a: Fld) -> Fld:
        """a^{-1} mod p via masked open: t = open(a*r); a^{-1} = r*t^{-1}."""
        r = self.rand_field()
        t = self.open(self.fmul(a, r))
        tinv = pow(t, FIELD_P - 2, FIELD_P)
        t = a.t if a.t is not None else None
        return Fld((r.v * tinv) % FIELD_P,
                   pow(t, FIELD_P - 2, FIELD_P) if t is not None else None)
