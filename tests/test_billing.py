"""End-to-end: handshake -> private query -> response -> verifiable billing."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustedari.twopc import World, PC, MODE_OT, MODE_SIM
from trustedari.channel import run_two_parties
from trustedari.tls_provider import TLSProvider
from trustedari import handshake as H, query as Q, billing as B, util

# query template: {"tokens":<Af 2>,"q":"<As pad8>"}
PRE, MID, TAIL = b'{"tokens":', b',"q":"', b'"}'


def _segs(pc, qv: bytes):
    return [Q.make_segment(pc, Q.P, PRE, len(PRE)),
            Q.make_segment(pc, Q.AF, b"10" if pc.side == 0 else None, 2),
            Q.make_segment(pc, Q.P, MID, len(MID)),
            Q.make_segment(pc, Q.AS,
                           qv if pc.side == 0 else None, len(qv) + 4,
                           len(qv) if pc.side == 0 else None),
            Q.make_segment(pc, Q.P, TAIL, len(TAIL))]


def _build(pc, tk_share, iv, qv):
    with pc.use(MODE_SIM):
        q = Q.build_query(pc, _segs(pc, qv))
        return Q.query_record(pc, q, tk_share, iv)


def _run_once(qv: bytes = b"translate"):
    """Full run: returns (S, agent_result, relay_result, response_record, body)."""
    S = TLSProvider("api.example.com")
    w = World(); A = PC(w, w.chan_ar, 0, MODE_OT); R = PC(w, w.chan_ar, 1, MODE_OT)

    def agent(pc):
        a = H.agent_handshake(pc, S.ca_pk, "api.example.com")
        _build(pc, a.tk_capp_share, a.iv_capp, qv)   # interactive; ct public
        resp = pc.chan.recv(pc.side, "resp")
        pt = util.tls_aead_decrypt(a.tk_sapp, a.iv_sapp, 0,
                                   resp[:5], resp[5:])
        body, _ = util.strip_inner_padding(pt)
        return a, resp, body

    def relay(pc):
        r = H.relay_handshake(pc, S)
        rec = _build(pc, r.tk_capp_share, r.iv_capp, qv)
        resp = S.on_query(rec)
        pc.chan.send(pc.side, "resp", resp)
        return r

    (a, resp, body), r = run_two_parties(lambda: agent(A), lambda: relay(R))
    return S, a, r, resp, body


def _verify(a_share, r_share, com_A, rcom, resp, iv, win, pat, d_t):
    w = World(); A = PC(w, w.chan_ar, 0, MODE_OT); R = PC(w, w.chan_ar, 1, MODE_OT)
    def side(pc, share):
        with pc.use(MODE_SIM):
            return B.verify_billing(pc, tk_share=share, com_A=com_A, r=rcom,
                                    record=resp, iv_sapp=iv, win=win,
                                    pair_bytes=pat, d_t=d_t)
    ok, _ = run_two_parties(lambda: side(A, a_share),
                            lambda: side(R, r_share))
    return ok


def test_billing():
    S, a, r, resp, body = _run_once()
    assert S.established
    doc = json.loads(body)
    v = str(doc["usage"]["total_tokens"]).encode()
    pat = b'"total_tokens": ' + v
    j0 = body.index(pat)
    win = B.select_window(len(resp) - 5, j0, j0 + len(pat))
    print("  window:", win)

    ok = _verify(a.tkA_sapp_share, r.tk_sapp_share, a.com_A, a.r, resp,
                 a.iv_sapp, win, pat, d_t=2)
    assert ok == 1, "honest billing should verify"
    print("  ok billing: honest claim verified (accept=1)")

    bad = b'"total_tokens": 00'
    ok = _verify(a.tkA_sapp_share, r.tk_sapp_share, a.com_A, a.r, resp,
                 a.iv_sapp, win, bad, d_t=2)
    assert ok == 0, "forged value must be rejected"
    print("  ok billing: forged value rejected (accept=0)")

    ok = _verify(a.tkA_sapp_share, r.tk_sapp_share, a.com_A, a.r, resp,
                 a.iv_sapp, win, pat, d_t=1)
    assert ok == 0, "wrong depth must be rejected"
    print("  ok billing: wrong depth rejected")

    ok = _verify(a.tkA_sapp_share, r.tk_sapp_share, b"\x00" * 32, a.r, resp,
                 a.iv_sapp, win, pat, d_t=2)
    assert ok == 0
    print("  ok billing: bad commitment rejected")

    ok = _verify(a.tkA_sapp_share,
                 bytes(x ^ 0xFF for x in r.tk_sapp_share), a.com_A, a.r,
                 resp, a.iv_sapp, win, pat, d_t=2)
    assert ok == 0
    print("  ok billing: tampered key share rejected")


def test_billing_rev_window():
    """Long echoed field pushes the billed pair to the tail -> rev window."""
    S, a, r, resp, body = _run_once(b"x" * 200)
    doc = json.loads(body)
    pat = b'"total_tokens": ' + str(doc["usage"]["total_tokens"]).encode()
    j0 = body.index(pat)
    win = B.select_window(len(resp) - 5, j0, j0 + len(pat))
    assert win.rho == B.REV, f"expected rev window, got {win}"
    print("  window:", win)
    ok = _verify(a.tkA_sapp_share, r.tk_sapp_share, a.com_A, a.r, resp,
                 a.iv_sapp, win, pat, d_t=2)
    assert ok == 1
    print("  ok billing: rev-window claim verified")


def test_billing_string_braces():
    """'{' / '}' and '\\"' INSIDE strings must not perturb the FSM depth."""
    S, a, r, resp, body = _run_once(b"brace{}in\\u0022str")
    doc = json.loads(body)
    pat = b'"total_tokens": ' + str(doc["usage"]["total_tokens"]).encode()
    j0 = body.index(pat)
    win = B.select_window(len(resp) - 5, j0, j0 + len(pat))
    print("  window:", win)
    ok = _verify(a.tkA_sapp_share, r.tk_sapp_share, a.com_A, a.r, resp,
                 a.iv_sapp, win, pat, d_t=2)
    assert ok == 1, "braces inside strings must not perturb depth"
    print("  ok billing: escaped-quote/brace body verified")


if __name__ == "__main__":
    print("== billing tests ==")
    test_billing()
    test_billing_rev_window()
    test_billing_string_braces()
    print("all billing tests passed")
