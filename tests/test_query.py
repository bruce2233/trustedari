import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trustedari.twopc import World, PC, MODE_OT, MODE_SIM, Arith
from trustedari.channel import run_two_parties
from trustedari import query as Q
from trustedari import circuits as C


# -- template --------------------------------------------------------------
# POST /x HTTP/1.1\r\nContent-Length: NNNN\r\n\r\n{"item":"..","buyer":"..",
#                                                   "coupon":".."}
# segments:  [P pre][Xf len][P mid1][Af item][P mid2][As buyer][P mid3]
#          [Rs coupon][P tail]
SEG_DEF = [
    (Q.P, b'POST /x HTTP/1.1\r\nContent-Length: '),
    (Q.XF, None),                       # Content-Length via I2S (4 digits)
    (Q.P, b'\r\n\r\n{"item":"'),
    (Q.AF, b'ITEM-042'),                # fixed 8 bytes
    (Q.P, b'","buyer":"'),
    (Q.AS, b'alice'),                   # hidden length, owner = agent
    (Q.P, b'","coupon":"'),
    (Q.RS, b'SAVE10'),                  # hidden length, owner = relay
    (Q.P, b'"}'),
]
H_ITEM = 8
H_BUYER = 16
H_COUPON = 12
BODY_G = 9 + H_ITEM + 11 + 5 + 12 + 6 + 2   # true body len (alice=5, SAVE10=6)


def _mk_segs(pc):
    segs = []
    i2s_idx = None
    for i, (theta, content) in enumerate(SEG_DEF):
        if i == 1:
            i2s_idx = i
            segs.append(None)
            continue
        h = {Q.AF: H_ITEM, Q.AS: H_BUYER, Q.RS: H_COUPON}.get(theta)
        owner_has = ((theta == Q.AS and pc.side == 0)
                     or (theta == Q.RS and pc.side == 1)
                     or theta == Q.P or theta == Q.AF and pc.side == 0)
        segs.append(Q.make_segment(
            pc, theta, content if owner_has else None, h or len(content),
            g=len(content) if owner_has else None))
    # I2S: body length = shared segment g's + public body bytes
    ga = Q._const_arith(pc, 0)
    for i in (3, 5, 7):            # Af item / As buyer / Rs coupon
        ga = Q._arith_add(pc, ga, Q._to_arith(pc, segs[i].g))
    for c in (9, 11, 12, 2):       # body syntax bytes inside P segments
        ga = Q._arith_add(pc, ga, Q._const_arith(pc, c))
    segs[1] = Q.i2s(pc, ga, 4)
    return segs


def test_query():
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)
    steps = Q.plan_assembly([t for t, _ in SEG_DEF],
                            [34, 4, 13, H_ITEM, 11, H_BUYER, 12, H_COUPON,
                             2])

    def f(pc):
        with pc.use(MODE_SIM):
            segs = _mk_segs(pc)
            q = Q.build_query(pc, segs, steps)
            return C.open_bytes(pc, q), pc.open(segs[1].g)
    (qa, la), _ = run_two_parties(lambda: f(A), lambda: f(R))
    want = (b'POST /x HTTP/1.1\r\nContent-Length: 0053\r\n\r\n'
            b'{"item":"ITEM-042","buyer":"alice","coupon":"SAVE10"}')
    # pads make it longer than the clean string; strip NULs to compare
    assert qa.replace(b"\x00", b"") == want.replace(b"\x00", b""), \
        f"\n got {qa!r}\nwant {want!r}"
    assert la == 4
    print("  ok query: assembled + I2S Content-Length correct")
    print("   ", qa)


def test_shc_only():
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)

    def f(pc):
        a = Q.make_segment(pc, Q.AS, b"AB" if pc.side == 0 else None, 4, g=2)
        b = Q.make_segment(pc, Q.RS, b"XYZ" if pc.side == 1 else None, 4, g=3)
        m = Q.shc(pc, a, b)
        return C.open_bytes(pc, m.s), pc.open(m.g)
    (sm, gm), _ = run_two_parties(lambda: f(A), lambda: f(R))
    assert sm == b"ABXYZ\x00\x00\x00", sm
    assert gm == 5
    print("  ok SHC: hidden-boundary concat correct")


def test_xs_shared_segment():
    """Xs: neither party knows the field — A and R each hold a pad share."""
    import secrets
    target = b"hello!"
    pad_a = secrets.token_bytes(6)
    pad_b = bytes(x ^ y for x, y in zip(pad_a, target))
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)

    def f(pc):
        mine = pad_a if pc.side == 0 else pad_b
        xs = Q.make_segment(pc, Q.XS, mine, 6,
                            g=6 if pc.side == 0 else None)
        m = Q.shc(pc, Q.make_segment(pc, Q.P, b"[", 1), xs)
        m = Q.shc(pc, m, Q.make_segment(pc, Q.P, b"]", 1))
        return C.open_bytes(pc, m.s), pc.open(m.g)
    (sm, gm), _ = run_two_parties(lambda: f(A), lambda: f(R))
    assert sm == b"[hello!]", sm
    assert gm == 8
    print("  ok XS: both-party-shared hidden segment merged correctly")


if __name__ == "__main__":
    print("== query tests ==")
    test_shc_only()
    test_xs_shared_segment()
    test_query()
    print("all query tests passed")
