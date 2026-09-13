"""Emulated service provider S: an *unmodified* TLS-1.3-like server.

S speaks ordinary TLS 1.3 (ECDHE key_share, AES-128-GCM, SHA-256/HKDF,
Certificate + CertificateVerify + Finished) against a "client" that is in
reality emulated jointly by agent A and ARI R (TrustedARI Pi_ths).

Message encodings (TLS-shaped, minimal):

  ClientHello : b"CH"  | client_random(32) | key_share(33, SEC-compressed)
  ServerHello : b"SH"  | server_random(32) | key_share(33)
  -- then handshake messages encrypted under tk_shs as TLS records --
  EncryptedExt: b"EE"  | b""
  Certificate : b"CRT" | name_len(1) | name | pk(33) | sig(64, self-signed)
  CertVerify  : b"CV"  | sig(64 over ctx = "TLS13 ServerCV" || 0 ||
                          H(CH..CRT))
  Fin(S)      : b"SF"  | mac(32 = HMAC(fk_s, H(CH..CV)))
  -- client then sends its Finished, encrypted under tk_chs --
  Fin(C)      : b"CF"  | mac(32 = HMAC(fk_c, H(CH..SF)))

Application data is a normal TLS record: header(5) || ct || tag.  Query and
response bodies are JSON; billing is verified on a window of the response.
"""
from __future__ import annotations

import json
import secrets
from typing import Optional, Tuple

from . import curve, util


class TLSProvider:
    """One connection's worth of server state, driven synchronously by R."""

    def __init__(self, name: str = "api.example.com") -> None:
        self.name = name
        self.cert_sk = curve.rand_scalar()
        self.cert_pk = curve.point_mul(self.cert_sk)
        # CA issues a signature binding name -> pk (simplified chain)
        self.ca_sk = curve.rand_scalar()
        self.ca_pk = curve.point_mul(self.ca_sk)
        self.cert_sig = util.ecdsa_sign(
            self.ca_sk, util.h256(name.encode() + util_ser(self.cert_pk)))
        self.transcript = bytearray()
        self.y = curve.rand_scalar()
        self.Y = curve.point_mul(self.y)
        self.seq_c = 0      # client->server record seq
        self.seq_s = 0
        self.established = False

    # -- helpers ------------------------------------------------------------
    def _ks(self, secret: bytes, label: str, ctx_msgs: bytes) -> bytes:
        return util.derive_secret(secret, label, ctx_msgs)

    @staticmethod
    def _aead_key_iv(secret: bytes) -> Tuple[bytes, bytes]:
        return (util.hkdf_expand_label(secret, "key", b"", 16),
                util.hkdf_expand_label(secret, "iv", b"", 12))

    # -- handshake ----------------------------------------------------------
    def on_client_hello(self, ch: bytes) -> bytes:
        """Returns SH || (encrypted server flight)."""
        assert ch[:2] == b"CH"
        self.client_random = ch[2:34]
        cks = curve.deser_point(ch[34:67])
        self.transcript += ch

        dhe = curve.point_to_field(curve.point_mul(self.y, cks)) \
            .to_bytes(32, "big")
        self.sh = b"SH" + secrets.token_bytes(32) + curve.ser_point(self.Y)
        self.transcript += self.sh

        # ---- key schedule (paper's chain): HS -> CHTS/SHTS -> MS -> CAT/SAT
        self.hs = util.hkdf_extract(b"", dhe)
        self.chts = self._ks(self.hs, "c hs traffic", bytes(self.transcript))
        self.shts = self._ks(self.hs, "s hs traffic", bytes(self.transcript))
        tk_chs, iv_chs = self._aead_key_iv(self.chts)
        tk_shs, iv_shs = self._aead_key_iv(self.shts)
        self.tk_chs, self.iv_chs = tk_chs, iv_chs
        self.hs_seq_s = 0
        self.hs_seq_c = 0

        # server flight messages (each a handshake msg, sent under tk_shs)
        ee = b"EE"
        crt = (b"CRT" + bytes([len(self.name)]) + self.name.encode()
               + util_ser(self.cert_pk) + self.cert_sig)
        cv_ctx = b"TLS13 ServerCV\x00" + util.h256(
            bytes(self.transcript) + ee + crt)
        cv = b"CV" + util.ecdsa_sign(self.cert_sk, cv_ctx)
        flight = ee + crt + cv
        self.transcript += flight
        fk_s = util.hkdf_expand_label(self.shts, "finished", b"", 32)
        sf = b"SF" + util.hmac256(fk_s, util.h256(bytes(self.transcript)))
        self.transcript += sf
        flight += sf

        # wrap each handshake message as an app-data record under tk_shs
        out = bytearray(self.sh)
        out += self._enc_record(tk_shs, iv_shs, "hs_seq_s", flight,
                                util.CT_HANDSHAKE)
        # ---- application secrets
        dhs = self._ks(self.hs, "derived", b"")
        self.ms = util.hkdf_extract(dhs, b"\x00" * 32)
        self.cats = self._ks(self.ms, "c ap traffic", bytes(self.transcript))
        self.sats = self._ks(self.ms, "s ap traffic", bytes(self.transcript))
        self.tk_capp, self.iv_capp = self._aead_key_iv(self.cats)
        self.tk_sapp, self.iv_sapp = self._aead_key_iv(self.sats)
        self.fk_c = util.hkdf_expand_label(self.chts, "finished", b"", 32)
        self.sf_transcript = bytes(self.transcript)   # CH..SF
        return bytes(out)

    def _enc_record(self, key: bytes, iv: bytes, seq_attr: str,
                    msgs: bytes, inner_ct: int) -> bytes:
        seq = getattr(self, seq_attr)
        setattr(self, seq_attr, seq + 1)
        inner = msgs + bytes([inner_ct])
        hdr = util.wrap_record(util.CT_APPDATA, b"")[:5]
        hdr = bytes([util.CT_APPDATA, 0x03, 0x03]) + \
            (len(inner) + 16).to_bytes(2, "big")
        return hdr + util.tls_aead_encrypt(key, iv, seq, hdr, inner)

    def on_client_finished(self, rec: bytes) -> bool:
        """Verify the client Finished record (under tk_chs)."""
        assert rec[0] == util.CT_APPDATA
        ln = int.from_bytes(rec[3:5], "big")
        pt = util.tls_aead_decrypt(
            self.tk_chs, self.iv_chs, self.hs_seq_c, rec[:5], rec[5:5 + ln])
        self.hs_seq_c += 1
        if pt is None:
            return False
        body, ct = util.strip_inner_padding(pt)
        assert ct == util.CT_HANDSHAKE and body[:2] == b"CF"
        want = util.hmac256(self.fk_c, util.h256(self.sf_transcript))
        if body[2:34] != want:
            return False
        self.transcript += body
        self.established = True
        return True

    # -- application data ----------------------------------------------------
    def on_query(self, rec: bytes) -> bytes:
        """Decrypt a query record, produce a JSON response record."""
        assert self.established
        ln = int.from_bytes(rec[3:5], "big")
        pt = util.tls_aead_decrypt(
            self.tk_capp, self.iv_capp, self.seq_c, rec[:5], rec[5:5 + ln])
        self.seq_c += 1
        if pt is None:
            raise ValueError("bad query record (tag mismatch)")
        body, ct = util.strip_inner_padding(pt)
        assert ct == util.CT_APPDATA
        # template padding convention: variable segments are NUL-padded
        body = body.replace(b"\x00", b"")
        query = json.loads(body)

        resp = self._respond(query)
        inner = json.dumps(resp).encode() + bytes([util.CT_APPDATA])
        hdr = bytes([util.CT_APPDATA, 0x03, 0x03]) + \
            (len(inner) + 16).to_bytes(2, "big")
        rec_out = hdr + util.tls_aead_encrypt(
            self.tk_sapp, self.iv_sapp, self.seq_s, hdr, inner)
        self.seq_s += 1
        return rec_out

    def _respond(self, query: dict) -> dict:
        """Billing-relevant JSON response."""
        tokens = int(query.get("tokens", 0))
        unit = 3  # price units per token
        return {
            "status": "ok",
            "echo": query.get("q", ""),
            "usage": {
                "prompt_tokens": tokens // 2,
                "completion_tokens": tokens - tokens // 2,
                "total_tokens": tokens,
                "price": tokens * unit,
                "currency": "credit",
            },
            "request_id": secrets.token_hex(8),
        }


def util_ser(pt: curve.Point) -> bytes:
    return curve.ser_point(pt)
