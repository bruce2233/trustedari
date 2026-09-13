import os, sys, secrets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trustedari.twopc import World, PC, Bits, Arith, MODE_OT, MODE_SIM
from trustedari.channel import run_two_parties


def make(mode=MODE_OT):
    w = World()
    a = PC(w, w.chan_ar, 0, mode)
    r = PC(w, w.chan_ar, 1, mode)
    return w, a, r


def check(name, got, want):
    assert got == want, f"{name}: got {got} want {want}"
    print(f"  ok {name} = {got}")


def test_and(mode):
    w, A, R = make(mode)
    xs = [secrets.randbits(64) for _ in range(3)]
    ys = [secrets.randbits(64) for _ in range(3)]

    def fa():
        xa = [A.share_bits(True, x, 64) for x in xs]
        ya = [A.share_bits(False, 0, 64) for _ in ys]
        return [A.open(A.and_bits(xa[i], ya[i])) for i in range(3)]

    def fr():
        xb = [R.share_bits(False, 0, 64) for _ in xs]
        yb = [R.share_bits(True, y, 64) for y in ys]
        return [R.open(R.and_bits(xb[i], yb[i])) for i in range(3)]

    out, _ = run_two_parties(fa, fr)
    for i in range(3):
        check(f"and[{i}]", out[i], xs[i] & ys[i])


def test_add_mux(mode):
    w, A, R = make(mode)
    x, y = secrets.randbits(32), secrets.randbits(32)
    sel = secrets.randbelow(2)
    m1, m0 = secrets.randbits(40), secrets.randbits(40)

    def fa():
        xa = A.share_bits(True, x, 32)
        ya = A.share_bits(False, 0, 32)
        s = A.open(A.add(xa, ya))
        d = A.open(A.sub(xa, ya))
        c = A.share_bits(True, sel, 1)
        mx = A.open(A.mux(c, A.share_bits(True, m1, 40),
                          A.share_bits(True, m0, 40)))
        e = A.open(A.eq_const(xa, x))
        return s, d, mx, e

    def fr():
        xb = R.share_bits(False, 0, 32)
        yb = R.share_bits(True, y, 32)
        s = R.open(R.add(xb, yb))
        d = R.open(R.sub(xb, yb))
        c = R.share_bits(False, 0, 1)
        mx = R.open(R.mux(c, R.share_bits(False, 0, 40),
                          R.share_bits(False, 0, 40)))
        e = R.open(R.eq_const(xb, x))
        return s, d, mx, e

    out, _ = run_two_parties(fa, fr)
    check("add", out[0], (x + y) & 0xFFFFFFFF)
    check("sub", out[1], (x - y) & 0xFFFFFFFF)
    check("mux", out[2], m1 if sel else m0)
    check("eq", out[3], 1)


def test_blind_rotate(mode):
    w, A, R = make(mode)
    n = 40
    v = [secrets.randbelow(256) for _ in range(n)]
    d = secrets.randbelow(n)

    def fa():
        vb = [A.share_bits(True, b, 8) for b in v]
        da = A.a2b(A.share_arith(True, d, 8))   # FA2B(d_arith) bit decomp
        out = A.blind_rotate_left(vb, da)
        return [A.open(b) for b in out]

    def fr():
        vb = [R.share_bits(False, 0, 8) for _ in v]
        db = R.a2b(R.share_arith(False, 0, 8))
        out = R.blind_rotate_left(vb, db)
        return [R.open(b) for b in out]

    out, _ = run_two_parties(fa, fr)
    want = v[d:] + [0] * d
    check("blind_rotate", out, want)


def test_a2b_b2a_field(mode):
    w, A, R = make(mode)
    x = secrets.randbits(24)
    fa_, fb_ = secrets.randbelow(2**255), secrets.randbelow(2**255)

    def fa():
        xa = A.share_arith(True, x, 24)
        xb = A.a2b(xa)
        xo = A.open(xb)
        xa2 = A.open(A.b2a(xb))
        fx = A.share_field(True, fa_)
        fy = A.share_field(False, 0)
        pr = A.open(A.fmul(fx, fy))
        iv = A.open(A.fmul(A.finv(fx), fx))
        return xo, xa2, pr, iv

    def fr():
        xa = R.share_arith(False, 0, 24)
        xb = R.a2b(xa)
        xo = R.open(xb)
        xa2 = R.open(R.b2a(xb))
        fx = R.share_field(False, 0)
        fy = R.share_field(True, fb_)
        pr = R.open(R.fmul(fx, fy))
        iv = R.open(R.fmul(R.finv(fx), fx))
        return xo, xa2, pr, iv

    out, _ = run_two_parties(fa, fr)
    from trustedari.curve import P
    check("a2b", out[0], x)
    check("b2a", out[1], x)
    check("fmul", out[2], (fa_ * fb_) % P)
    check("finv", out[3], 1)


if __name__ == "__main__":
    mode = MODE_OT if os.environ.get("MODE", "ot") == "ot" else MODE_SIM
    print(f"== engine tests, mode={mode} ==")
    test_and(mode)
    test_add_mux(mode)
    test_blind_rotate(mode)
    test_a2b_b2a_field(mode)
    print("all engine tests passed")
