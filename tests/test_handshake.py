import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trustedari.twopc import World, PC, MODE_OT
from trustedari.channel import run_two_parties
from trustedari.handshake import agent_handshake, relay_handshake
from trustedari.tls_provider import TLSProvider


def test_handshake():
    S = TLSProvider("api.example.com")
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)

    ra, rr = run_two_parties(
        lambda: agent_handshake(A, S.ca_pk, "api.example.com"),
        lambda: relay_handshake(R, S))
    assert ra.ok, "agent handshake failed"
    assert rr.ok, "relay handshake failed"
    assert S.established, "provider did not accept client finished"

    # sanity: shared tk_capp truth equals provider's
    from trustedari import util
    tk_capp = bytes(a ^ b for a, b in
                    zip(ra.tk_capp_share, rr.tk_capp_share))
    assert tk_capp == S.tk_capp, "reconstructed tk_capp mismatch"
    assert ra.tk_sapp == S.tk_sapp, "agent tk_sapp mismatch"
    # R never learns tk_sapp
    assert rr.tk_sapp_share != S.tk_sapp
    print("  ok handshake: cert verify + CF accepted; keys consistent")
    return ra, rr, S


def test_misrouting():
    """A wrong-name/wrong-cert provider must be rejected by the agent."""
    S = TLSProvider("evil.example.com")
    w = World()
    A = PC(w, w.chan_ar, 0, MODE_OT)
    R = PC(w, w.chan_ar, 1, MODE_OT)
    ra, rr = run_two_parties(
        lambda: agent_handshake(A, S.ca_pk, "api.example.com"),
        lambda: relay_handshake(R, S))
    assert not ra.ok, "agent accepted wrong cert name!"
    print("  ok misrouting: agent rejected foreign certificate")


if __name__ == "__main__":
    print("== handshake tests ==")
    test_handshake()
    test_misrouting()
    print("all handshake tests passed")
