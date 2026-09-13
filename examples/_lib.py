"""Shared pipeline for downstream TrustedARI application demos."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustedari.twopc import World, PC, MODE_OT, MODE_SIM
from trustedari.channel import run_two_parties
from trustedari.tls_provider import TLSProvider
from trustedari import handshake as H, query as Q, billing as B, util


def run_app(S: TLSProvider, name: str, segs_fn, pat_fn, d_t: int,
            forged_fn):
    """End-to-end: Pi_ths handshake -> Pi_query -> response -> billing.

    segs_fn(pc) -> [Seg]   per-side template segments
    pat_fn(body) -> bytes  the exact '"<phi>": <v>' pattern to enforce
    """
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)
    t0 = time.time()

    def agent(pc):
        a = H.agent_handshake(pc, S.ca_pk, name)
        with pc.use(MODE_SIM):
            q = Q.build_query(pc, segs_fn(pc))
            Q.query_record(pc, q, a.tk_capp_share, a.iv_capp)
        resp = pc.chan.recv(pc.side, "resp")
        pt = util.tls_aead_decrypt(a.tk_sapp, a.iv_sapp, 0,
                                   resp[:5], resp[5:])
        body, _ = util.strip_inner_padding(pt)
        return a, resp, body

    def relay(pc):
        r = H.relay_handshake(pc, S)
        with pc.use(MODE_SIM):
            q = Q.build_query(pc, segs_fn(pc))
            rec = Q.query_record(pc, q, r.tk_capp_share, r.iv_capp)
        resp = S.on_query(rec)
        pc.chan.send(pc.side, "resp", resp)
        return r

    (a, resp, body), r = run_two_parties(lambda: agent(A), lambda: relay(R))
    assert S.established
    pat = pat_fn(body)
    j0 = body.index(pat)
    win = B.select_window(len(resp) - 5, j0, j0 + len(pat))

    def verify(pc, share, p):
        with pc.use(MODE_SIM):
            return B.verify_billing(pc, tk_share=share, com_A=a.com_A,
                                    r=a.r, record=resp, iv_sapp=a.iv_sapp,
                                    win=win, pair_bytes=p, d_t=d_t)

    w2 = World()
    A2, R2 = PC(w2, w2.chan_ar, 0, MODE_OT), PC(w2, w2.chan_ar, 1, MODE_OT)
    ok, _ = run_two_parties(lambda: verify(A2, a.tkA_sapp_share, pat),
                            lambda: verify(R2, r.tk_sapp_share, pat))

    w3 = World()
    A3, R3 = PC(w3, w3.chan_ar, 0, MODE_OT), PC(w3, w3.chan_ar, 1, MODE_OT)
    forged_pat = forged_fn(body)
    bad, _ = run_two_parties(lambda: verify(A3, a.tkA_sapp_share, forged_pat),
                             lambda: verify(R3, r.tk_sapp_share, forged_pat))

    comm = w.chan_ar.bytes_sent
    return dict(body=body, pat=pat, win=win, accept=ok, forged=bad,
                dt=time.time() - t0, comm=comm[0] + comm[1])
