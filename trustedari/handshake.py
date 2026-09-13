"""ARI-adapted three-party TLS handshake (paper Protocol 3, Pi_ths).

Parties: agent A (PC side 0), ARI R (side 1), provider S (a synchronous
TLSProvider object that R drives, standing in for the real network link).

Flow (paper-faithful):
  A,R: r_i, Z_i = g^{r_i};  R sends CKS = Z_A + Z_R inside the CH to S.
  both: ssk_i = Y^{r_i};  ECtF -> additive shares of DHE = x((rA+rR)Y).
  2PC : HS = Extract(0, DHE);  PC_HS cached HMAC states (ExpandOptm).
        CHTS, SHTS, dHS expansions; R hands CHTS_R, SHTS_R to A.
  A   : DeriveTK -> tk_chs, tk_shs, fk_s; decrypts EE/CRT/CV/SF; verifies
        provider cert, CertificateVerify, server Finished (anti-misrouting).
        A then forwards H2 = H(CH..SF) to R (R can't see the flight).
  2PC : MS = Extract(dHS, 0); CATS, SATS; DeriveTKOptm -> shared tk_capp /
        public iv_capp and shared tk_sapp / public iv_sapp.
  A   : commits tk_A_sapp (com_A = H(share || r)) to R; R reveals tk_R_sapp
        -> only A holds full tk_sapp (only A decrypts responses).
  A   : fk_c = DeriveTK(CHTS) locally; CF = HMAC(fk_c, H(CH..SF)); sent via
        R as a normal client Finished under tk_chs.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Tuple

from . import circuits as C
from . import curve, util
from .twopc import PC, MODE_SIM, Bits


@dataclass
class AgentResult:
    ok: bool
    transcript: bytes          # CH .. SF plaintext handshake bytes
    tk_capp_share: bytes       # A's share of the client-app key
    iv_capp: bytes
    tk_sapp: bytes             # full server-app key (A only)
    iv_sapp: bytes
    tkA_sapp_share: bytes      # A's share that com_A commits to
    com_A: bytes
    r: bytes                   # commitment randomness (billing public input)
    server_name: str = ""
    dbg: dict = None           # derived hs keys for debugging


@dataclass
class RelayResult:
    ok: bool
    tk_capp_share: bytes       # R's share of tk_capp
    iv_capp: bytes
    tk_sapp_share: bytes       # R's share of tk_sapp
    iv_sapp: bytes
    com_A: bytes


def _own_share(pc: PC, bs) -> bytes:
    """Extract own share of a byte list (no interaction)."""
    return C.pack_bytes(pc, bs).v.to_bytes(len(bs), "little")


def _open_to_a(pc: PC, bs):
    """Both sides call: side 0 learns the truth, side 1 learns nothing."""
    v = pc.open_to(C.pack_bytes(pc, bs), 0)
    return None if v is None else v.to_bytes(len(bs), "little")


def _open_pub(pc: PC, bs) -> bytes:
    v = pc.open(C.pack_bytes(pc, bs))
    return v.to_bytes(len(bs), "little")


def _ks_phase1(pc: PC, ssk: Tuple[int, int], h0: bytes):
    """ECtF -> DHE shares -> HS -> CHTS/SHTS/dHS shares."""
    with pc.use(MODE_SIM):
        dhe_f = C.ectf_x_add(pc, ssk)
        dhe_bits = C.fld_to_bits(pc, dhe_f)
        dhe_b = C.unpack_be(pc, dhe_bits, 32)
        hs = C.hkdf_extract(pc, [], dhe_b)
        pc_hs = C.hmac_precompute_sh(pc, hs)
        chts = C.expand_optm(pc, pc_hs, "c hs traffic", h0, 32)
        shts = C.expand_optm(pc, pc_hs, "s hs traffic", h0, 32)
        dhs = C.expand_optm(pc, pc_hs, "derived", util.h256(b""), 32)
    return chts, shts, dhs


def _ks_phase2(pc: PC, dhs, h2: bytes):
    """dHS -> MS -> CATS/SATS -> shared app keys + public ivs."""
    with pc.use(MODE_SIM):
        pc_dhs = C.hmac_precompute_sh(pc, dhs)
        ms = C.hmac_from_pc(pc, pc_dhs, C.pub_bytes(pc, b"\x00" * 32))
        pc_ms = C.hmac_precompute_sh(pc, ms)
        cats = C.expand_optm(pc, pc_ms, "c ap traffic", h2, 32)
        sats = C.expand_optm(pc, pc_ms, "s ap traffic", h2, 32)
        pc_cats = C.hmac_precompute_sh(pc, cats)
        tk_capp, iv_capp = C.derive_tk_optm(pc, pc_cats)
        pc_sats = C.hmac_precompute_sh(pc, sats)
        tk_sapp, iv_sapp = C.derive_tk_optm(pc, pc_sats)
        iv_capp_b = _open_pub(pc, iv_capp)
        iv_sapp_b = _open_pub(pc, iv_sapp)
    return dict(tk_capp=tk_capp, tk_sapp=tk_sapp,
                iv_capp=iv_capp_b, iv_sapp=iv_sapp_b)


def agent_handshake(pc: PC, ca_pk: curve.Point,
                    want_name: str = "api.example.com") -> AgentResult:
    """Run the agent side of Pi_ths."""
    rA = curve.rand_scalar()
    ZA = curve.point_mul(rA)
    pc.chan.send(pc.side, "za", curve.ser_point(ZA))
    ZR = curve.deser_point(pc.chan.recv(pc.side, "zb"))
    cks = curve.point_add(ZA, ZR)

    ch = b"CH" + secrets.token_bytes(32) + curve.ser_point(cks)
    pc.chan.send(pc.side, "ch", ch)
    shf = pc.chan.recv(pc.side, "shf")          # SH || encrypted flight
    sh = shf[:67]
    Y = curve.deser_point(sh[34:67])
    ssk = curve.point_mul(rA, Y)

    transcript = bytearray(ch + sh)
    h0 = util.h256(bytes(transcript))

    chts, shts, dhs = _ks_phase1(pc, ssk, h0)

    # -- R hands over its handshake-traffic shares ---------------------------
    chts_b = _open_to_a(pc, chts)
    shts_b = _open_to_a(pc, shts)
    tk_chs, iv_chs = (util.hkdf_expand_label(chts_b, "key", b"", 16),
                      util.hkdf_expand_label(chts_b, "iv", b"", 12))
    tk_shs, iv_shs = (util.hkdf_expand_label(shts_b, "key", b"", 16),
                      util.hkdf_expand_label(shts_b, "iv", b"", 12))
    fk_s = util.hkdf_expand_label(shts_b, "finished", b"", 32)

    # -- decrypt + verify the server flight ----------------------------------
    flight = None
    try:
        flight = _decrypt_hs_flight(shf[67:], tk_shs, iv_shs)
    except Exception:
        import sys
        print(f"A-decrypt-fail shts={shts_b.hex()} tk_shs={tk_shs.hex()} "
              f"iv={iv_shs.hex()}", file=sys.stderr)
        raise
    ee = flight[:2]
    assert ee == b"EE"
    crt = _parse_crt(flight)
    name_len = crt[3]
    name = crt[4:4 + name_len].decode()
    pk = curve.deser_point(crt[4 + name_len:4 + name_len + 33])
    cert_sig = crt[4 + name_len + 33:4 + name_len + 97]
    cv_off = 2 + _crt_len(crt)
    cv = flight[cv_off:cv_off + 66]
    assert cv[:2] == b"CV"
    cv_sig = cv[2:66]
    sf = flight[cv_off + 66:cv_off + 66 + 34]
    assert sf[:2] == b"SF"
    sf_mac = sf[2:34]

    ok = util.ecdsa_verify(ca_pk, util.h256(name.encode()
                                          + curve.ser_point(pk)), cert_sig)
    ok = ok and (name == want_name)
    cv_ctx = b"TLS13 ServerCV\x00" + util.h256(bytes(transcript) + ee + crt)
    ok = ok and util.ecdsa_verify(pk, cv_ctx, cv_sig)
    ok = ok and (util.hmac256(fk_s, util.h256(
        bytes(transcript) + ee + crt + cv)) == sf_mac)
    transcript += ee + crt + cv + sf

    # -- phase 2: app secrets -------------------------------------------------
    h2 = util.h256(bytes(transcript))
    pc.chan.send(pc.side, "h2", h2)
    app = _ks_phase2(pc, dhs, h2)

    # -- commit-reveal on tk_sapp ---------------------------------------------
    tkA_sapp = _own_share(pc, app["tk_sapp"])
    tkA_capp = _own_share(pc, app["tk_capp"])
    com_r = secrets.token_bytes(32)
    com_A = util.h256(tkA_sapp + com_r)
    pc.chan.send(pc.side, "com", com_A)
    tkR_sapp = pc.chan.recv(pc.side, "tksr")
    tk_sapp = bytes(a ^ b for a, b in zip(tkA_sapp, tkR_sapp))

    # -- client Finished (local, from full CHTS) ------------------------------
    fk_c = util.hkdf_expand_label(chts_b, "finished", b"", 32)
    cf = b"CF" + util.hmac256(fk_c, util.h256(bytes(transcript)))
    transcript += cf
    pc.chan.send(pc.side, "cf", _enc_hs_record(tk_chs, iv_chs, 0, cf))
    ok = ok and pc.chan.recv(pc.side, "cfok") == b"\x01"

    return AgentResult(ok=ok, transcript=bytes(transcript),
                       tk_capp_share=tkA_capp, iv_capp=app["iv_capp"],
                       tk_sapp=tk_sapp, iv_sapp=app["iv_sapp"],
                       tkA_sapp_share=tkA_sapp, com_A=com_A, r=com_r,
                       server_name=name,
                       dbg={"chts": chts_b, "shts": shts_b,
                            "tk_shs": tk_shs, "iv_shs": iv_shs})


def relay_handshake(pc: PC, S) -> RelayResult:
    """Run the ARI (relay) side of Pi_ths against provider S."""
    rR = curve.rand_scalar()
    ZR = curve.point_mul(rR)
    ZA = curve.deser_point(pc.chan.recv(pc.side, "za"))
    pc.chan.send(pc.side, "zb", curve.ser_point(ZR))
    cks = curve.point_add(ZA, ZR)

    ch = pc.chan.recv(pc.side, "ch")
    assert ch[:2] == b"CH" and ch[34:67] == curve.ser_point(cks)
    shf = S.on_client_hello(ch)
    pc.chan.send(pc.side, "shf", shf)
    Y = curve.deser_point(shf[34:67])
    ssk = curve.point_mul(rR, Y)

    h0 = util.h256(ch + shf[:67])
    chts, shts, dhs = _ks_phase1(pc, ssk, h0)

    # R releases its handshake-traffic shares to A
    _open_to_a(pc, chts)
    _open_to_a(pc, shts)

    h2 = pc.chan.recv(pc.side, "h2")
    app = _ks_phase2(pc, dhs, h2)

    com_A = pc.chan.recv(pc.side, "com")
    pc.chan.send(pc.side, "tksr", _own_share(pc, app["tk_sapp"]))
    cf = pc.chan.recv(pc.side, "cf")
    ok = S.on_client_finished(cf)
    pc.chan.send(pc.side, "cfok", b"\x01" if ok else b"\x00")
    return RelayResult(ok=ok,
                       tk_capp_share=_own_share(pc, app["tk_capp"]),
                       iv_capp=app["iv_capp"],
                       tk_sapp_share=_own_share(pc, app["tk_sapp"]),
                       iv_sapp=app["iv_sapp"],
                       com_A=com_A)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _crt_len(crt: bytes) -> int:
    return 4 + crt[3] + 97


def _parse_crt(flight: bytes) -> bytes:
    assert flight[2:5] == b"CRT"
    return flight[2:2 + _crt_len(flight[2:])]


def _decrypt_hs_flight(blob: bytes, tk: bytes, iv: bytes) -> bytes:
    out = bytearray()
    off = 0
    seq = 0
    while off < len(blob):
        ln = int.from_bytes(blob[off + 3:off + 5], "big")
        rec = blob[off:off + 5 + ln]
        pt = util.tls_aead_decrypt(tk, iv, seq, rec[:5], rec[5:])
        assert pt is not None, "server flight record failed to decrypt"
        body, ct = util.strip_inner_padding(pt)
        assert ct == util.CT_HANDSHAKE
        out += body
        off += 5 + ln
        seq += 1
    return bytes(out)


def _enc_hs_record(tk: bytes, iv: bytes, seq: int, msgs: bytes) -> bytes:
    inner = msgs + bytes([util.CT_HANDSHAKE])
    hdr = bytes([util.CT_APPDATA, 0x03, 0x03]) + \
        (len(inner) + 16).to_bytes(2, "big")
    return hdr + util.tls_aead_encrypt(tk, iv, seq, hdr, inner)
