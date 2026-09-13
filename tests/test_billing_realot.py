"""Billing verification under the REAL OT backend (no sim).

Uses a minimal synthetic record so the in-circuit AES-CTR window is small:
body {"t":42}, fwd window = 2 blocks.  Proves the Figure-6 circuit is
executable as an interactive 2PC, not only in simulation.
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustedari.twopc import World, PC, MODE_OT
from trustedari.channel import run_two_parties
from trustedari import billing as B, util
import secrets


def _record(tk: bytes, iv: bytes, body: bytes) -> bytes:
    inner = body + bytes([util.CT_APPDATA])
    hdr = bytes([util.CT_APPDATA, 0x03, 0x03]) + (len(inner) + 16).to_bytes(2, "big")
    return hdr + util.tls_aead_encrypt(tk, iv, 0, hdr, inner)


def test_billing_realot():
    tk = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    tkA = secrets.token_bytes(16)
    tkR = bytes(a ^ b for a, b in zip(tk, tkA))
    r = secrets.token_bytes(32)
    com_A = util.h256(tkA + r)

    body = b'{"t":42}'
    resp = _record(tk, iv, body)
    pat = b'"t":42'
    j0 = body.index(pat)
    win = B.select_window(len(resp) - 5, j0, j0 + len(pat))
    assert win.blocks <= 2, win
    print("  window:", win)

    def side(pc, share):
        return B.verify_billing(pc, tk_share=share, com_A=com_A, r=r,
                                record=resp, iv_sapp=iv, win=win,
                                pair_bytes=pat, d_t=1)

    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)
    t0 = time.time()
    ok, _ = run_two_parties(lambda: side(A, tkA), lambda: side(R, tkR))
    dt = time.time() - t0
    comm = w.chan_ar.bytes_sent
    assert ok == 1
    print(f"  ok real-OT billing: accept=1  ({dt:.1f}s, "
          f"A->R {comm[0]}B, R->A {comm[1]}B)")

    # tampered ciphertext byte inside the window -> reject
    tampered = bytearray(resp)
    tampered[5 + 16 * win.o + 2] ^= 0x01
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)
    def side_t(pc, share):
        return B.verify_billing(pc, tk_share=share, com_A=com_A, r=r,
                                record=bytes(tampered), iv_sapp=iv, win=win,
                                pair_bytes=pat, d_t=1)
    ok, _ = run_two_parties(lambda: side_t(A, tkA), lambda: side_t(R, tkR))
    assert ok == 0
    print("  ok real-OT billing: tampered ciphertext rejected")


if __name__ == "__main__":
    print("== real-OT billing tests ==")
    test_billing_realot()
    print("all real-OT billing tests passed")
