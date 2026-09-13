import hashlib
import hmac as _hmac
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trustedari.twopc import World, PC, MODE_OT, MODE_SIM
from trustedari.channel import run_two_parties
from trustedari import circuits as C
from trustedari import curve


def make(mode):
    w = World()
    return PC(w, w.chan_ar, 0, mode), PC(w, w.chan_ar, 1, mode)


def check(name, got, want):
    assert got == want, f"{name}: got {got.hex() if isinstance(got, bytes) else got}\n  want {want.hex() if isinstance(want, bytes) else want}"
    print(f"  ok {name}")


def run_both(fa, fr):
    out, _ = run_two_parties(fa, fr)
    return out


def test_sha256(mode):
    A, R = make(mode)
    msg = secrets.token_bytes(50)
    want = hashlib.sha256(msg).digest()

    def f(pc, owner):
        bs = C.share_byte_list(pc, owner, msg if owner else b"\x00" * 50)
        return C.open_bytes(pc, C.sha256_digest_bytes(pc, bs))

    out = run_both(lambda: f(A, True), lambda: f(R, False))
    check("sha256", out, want)


def test_hmac_hkdf(mode):
    A, R = make(mode)
    key = secrets.token_bytes(32)
    msg = secrets.token_bytes(40)
    want = _hmac.new(key, msg, hashlib.sha256).digest()
    salt = secrets.token_bytes(32)

    def f(pc, owner):
        k = C.share_byte_list(pc, owner, key if owner else b"\x00" * 32)
        m = C.pub_bytes(pc, msg)
        hm = C.hmac_sha256(pc, k, m)
        s = C.share_byte_list(pc, owner, salt if owner else b"\x00" * 32)
        prk = C.hkdf_extract(pc, s, k)
        okm = C.hkdf_expand_label(pc, prk, "c hs traffic", b"ctx", 32)
        return C.open_bytes(pc, hm), C.open_bytes(pc, okm)

    out = run_both(lambda: f(A, True), lambda: f(R, False))
    check("hmac", out[0], want)
    # reference hkdf-expand-label
    prk_ref = _hmac.new(salt, key, hashlib.sha256).digest()
    info = (32).to_bytes(2, "big") + bytes([len(b"tls13 c hs traffic")]) \
        + b"tls13 c hs traffic" + b"\x03ctx"
    t1 = _hmac.new(prk_ref, info + b"\x01", hashlib.sha256).digest()
    check("hkdf_expand_label", out[1], t1)


def test_ectf(mode):
    A, R = make(mode)
    ra, rb = curve.rand_scalar(), curve.rand_scalar()
    Y = curve.point_mul(curve.rand_scalar())
    pa = curve.point_mul(ra, Y)
    pb = curve.point_mul(rb, Y)
    want = curve.point_to_field(curve.point_add(pa, pb))

    def f(pc, pt):
        return pc.open(C.ectf_x_add(pc, pt))

    out = run_both(lambda: f(A, pa), lambda: f(R, pb))
    check("ectf x-add", out, want)


def test_aes(mode):
    A, R = make(mode)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    def f(pc, owner):
        k = C.share_byte_list(pc, owner, key if owner else b"\x00" * 16)
        p = C.pub_bytes(pc, pt)
        return C.open_bytes(pc, C.aes128_enc(pc, k, p))

    out = run_both(lambda: f(A, True), lambda: f(R, False))
    check("aes128", out, want)


def test_gcm(mode):
    A, R = make(mode)
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    pt = secrets.token_bytes(48)
    aad = b"hdr12345"
    # NIST-flavored reference via our own public-domain impl
    want_ct, want_tag = _ref_gcm(key, iv, aad, pt)

    def f(pc, owner):
        k = C.share_byte_list(pc, owner, key if owner else b"\x00" * 16)
        p = C.share_byte_list(pc, owner, pt if owner else b"\x00" * len(pt))
        ct, tag = C.gcm_encrypt(pc, k, iv, aad, p)
        return C.open_bytes(pc, ct), C.open_bytes(pc, tag)

    out = run_both(lambda: f(A, True), lambda: f(R, False))
    check("gcm.ct", out[0], want_ct)
    check("gcm.tag", out[1], want_tag)


# --- tiny public reference AES-GCM (for cross-checking the 2PC one) ---------

def _ref_aes_block(key: bytes, pt: bytes) -> bytes:
    S = _AES_SBOX
    st = list(pt)
    rk = _ref_key_sched(key)
    def ark(st, r):
        for i in range(16):
            st[i] ^= rk[r * 16 + i]
    ark(st, 0)
    for r in range(1, 10):
        st = [S[b] for b in st]
        st = [st[0], st[5], st[10], st[15], st[4], st[9], st[14], st[3],
              st[8], st[13], st[2], st[7], st[12], st[1], st[6], st[11]]
        for c in range(4):
            s0, s1, s2, s3 = st[4 * c:4 * c + 4]
            st[4 * c + 0] = _x2(s0) ^ _x2(s1) ^ s1 ^ s2 ^ s3
            st[4 * c + 1] = s0 ^ _x2(s1) ^ _x2(s2) ^ s2 ^ s3
            st[4 * c + 2] = s0 ^ s1 ^ _x2(s2) ^ _x2(s3) ^ s3
            st[4 * c + 3] = _x2(s0) ^ s0 ^ s1 ^ s2 ^ _x2(s3)
        ark(st, r)
    st = [S[b] for b in st]
    st = [st[0], st[5], st[10], st[15], st[4], st[9], st[14], st[3],
          st[8], st[13], st[2], st[7], st[12], st[1], st[6], st[11]]
    ark(st, 10)
    return bytes(st)


def _x2(a):
    return ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF


def _ref_key_sched(key):
    S = _AES_SBOX
    w = list(key)
    rc = 1
    for i in range(16, 176, 4):
        t = w[i - 4:i]
        if i % 16 == 0:
            t = [S[t[1]] ^ rc, S[t[2]], S[t[3]], S[t[0]]]
            rc = _x2(rc)
        w += [w[i - 16 + j] ^ t[j] for j in range(4)]
    return w


def _gf128_ref(a: int, b: int) -> int:
    """GCM field multiply; inputs in wire (big-endian-bit) order."""
    R = 0xE1 << 120
    z = 0
    v = a
    for i in range(128):
        if (b >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (R if v & 1 else 0)
    return z


def _ref_gcm(key, iv, aad, pt):
    def b2i(x):
        return int.from_bytes(x, "big")
    h = b2i(_ref_aes_block(key, b"\x00" * 16))
    j0 = iv + b"\x00\x00\x00\x01"
    ct = b""
    ctr = 1
    for i in range(0, len(pt), 16):
        ctr += 1
        blk = pt[i:i + 16]
        ks = _ref_aes_block(key, iv + ctr.to_bytes(4, "big"))
        ct += bytes(a ^ b for a, b in zip(blk, ks))
    def ghash(data):
        y = 0
        for i in range(0, len(data), 16):
            y = _gf128_ref(y ^ b2i(data[i:i + 16]), h)
        return y
    def pad16(x):
        return x + b"\x00" * ((-len(x)) % 16)
    sdata = pad16(aad) + pad16(ct) + (len(aad) * 8).to_bytes(8, "big") \
        + (len(ct) * 8).to_bytes(8, "big")
    s = b2i(_ref_aes_block(key, j0))
    tag = (ghash(sdata) ^ s).to_bytes(16, "big")
    return ct, tag


_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
]


if __name__ == "__main__":
    mode = MODE_OT if os.environ.get("MODE", "sim") == "ot" else MODE_SIM
    print(f"== circuits tests, mode={mode} ==")
    test_sha256(mode)
    test_hmac_hkdf(mode)
    test_ectf(mode)
    test_aes(mode)
    test_gcm(mode)
    print("all circuits tests passed")
