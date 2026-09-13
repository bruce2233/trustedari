"""TrustedARI end-to-end demo (paper 2606.15822 core reproduction).

Agent A + ARI R jointly emulate a TLS client for an unmodified provider S:
  1. Pi_ths   : 3-party handshake (A+R emulate client; R cannot misroute)
  2. Pi_query : privacy-preserving query from a template (LDC/SHC + 2PC-AEAD)
  3. billing  : verifiable claim of a billed field inside the TLS response

Runs both parties in-process as threads over a strict-FIFO channel.
Standard crypto (SHA-256/AES/GHASH inside circuits) runs in "sim" mode for
speed; the paper-faithful machinery (ECtF, SHC, parser FSM, key commit) uses
the real OT-based GMW engine.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trustedari.twopc import World, PC, MODE_OT, MODE_SIM
from trustedari.channel import run_two_parties
from trustedari.tls_provider import TLSProvider
from trustedari import handshake as H, query as Q, billing as B, util

PRE, MID, TAIL = b'{"tokens":', b',"q":"', b'"}'
QVAL = b"translate"


def segs(pc):
    return [Q.make_segment(pc, Q.P, PRE, len(PRE)),
            Q.make_segment(pc, Q.AF, b"10" if pc.side == 0 else None, 2),
            Q.make_segment(pc, Q.P, MID, len(MID)),
            Q.make_segment(pc, Q.AS, QVAL if pc.side == 0 else None,
                           len(QVAL) + 4,
                           len(QVAL) if pc.side == 0 else None),
            Q.make_segment(pc, Q.P, TAIL, len(TAIL))]


def main():
    S = TLSProvider("api.example.com")
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)
    t0 = time.time()

    def agent(pc):
        print("[A] handshake with virtual client (Pi_ths) ...")
        a = H.agent_handshake(pc, S.ca_pk, "api.example.com")
        print(f"[A] handshake ok; cert name '{a.server_name}' verified; "
              f"com_A = {a.com_A.hex()[:24]}...")
        with pc.use(MODE_SIM):
            q = Q.build_query(pc, segs(pc))
            rec = Q.query_record(pc, q, a.tk_capp_share, a.iv_capp)
        resp = pc.chan.recv(pc.side, "resp")
        pt = util.tls_aead_decrypt(a.tk_sapp, a.iv_sapp, 0,
                                   resp[:5], resp[5:])
        body, _ = util.strip_inner_padding(pt)
        print(f"[A] response plaintext: {body.decode()}")
        return a, resp, body

    def relay(pc):
        print("[R] relaying handshake (sees only ciphertext) ...")
        r = H.relay_handshake(pc, S)
        print(f"[R] handshake done; holds share of tk_sapp only; "
              f"sees com_A = {r.com_A.hex()[:24]}...")
        with pc.use(MODE_SIM):
            q = Q.build_query(pc, segs(pc))
            rec = Q.query_record(pc, q, r.tk_capp_share, r.iv_capp)
        print(f"[R] forwarding opaque record ({len(rec)}B) to S ...")
        resp = S.on_query(rec)
        pc.chan.send(pc.side, "resp", resp)
        return r

    (a, resp, body), r = run_two_parties(lambda: agent(A), lambda: relay(R))
    print(f"[*] S.established = {S.established}")
    hs_comm = w.chan_ar.bytes_sent
    print(f"[*] A<->R comm so far: {hs_comm[0] + hs_comm[1]} B "
          f"(includes sim-truth sync traffic)")

    # ---- verifiable billing --------------------------------------------
    doc = json.loads(body)
    v = str(doc["usage"]["total_tokens"]).encode()
    pat = b'"total_tokens": ' + v
    j0 = body.index(pat)
    win = B.select_window(len(resp) - 5, j0, j0 + len(pat))
    print(f"[*] billing: claim usage.total_tokens={v.decode()} "
          f"window o={win.o} nblk={win.blocks} dir={win.rho}")

    w2 = World()
    A2 = PC(w2, w2.chan_ar, 0, MODE_OT)
    R2 = PC(w2, w2.chan_ar, 1, MODE_OT)

    def verify(pc, share):
        with pc.use(MODE_SIM):
            return B.verify_billing(pc, tk_share=share, com_A=a.com_A,
                                    r=a.r, record=resp, iv_sapp=a.iv_sapp,
                                    win=win, pair_bytes=pat, d_t=2)
    ok, _ = run_two_parties(lambda: verify(A2, a.tkA_sapp_share),
                            lambda: verify(R2, r.tk_sapp_share))
    vc = w2.chan_ar.bytes_sent
    print(f"[*] billing verification: accept = {ok}  "
          f"(verify comm {vc[0] + vc[1]} B)")
    assert ok == 1

    # tampering fails
    def verify_bad(pc, share):
        with pc.use(MODE_SIM):
            return B.verify_billing(pc, tk_share=share, com_A=a.com_A,
                                    r=a.r, record=resp, iv_sapp=a.iv_sapp,
                                    win=win,
                                    pair_bytes=b'"total_tokens": 00',
                                    d_t=2)
    w3 = World()
    A3 = PC(w3, w3.chan_ar, 0, MODE_OT)
    R3 = PC(w3, w3.chan_ar, 1, MODE_OT)
    bad, _ = run_two_parties(lambda: verify_bad(A3, a.tkA_sapp_share),
                             lambda: verify_bad(R3, r.tk_sapp_share))
    print(f"[*] forged claim 'total_tokens: 00': accept = {bad} (rejected)")
    assert bad == 0
    print(f"[*] done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
