# TrustedARI — core functionality reproduction (arXiv 2606.15822)

A working Python reproduction of the three core protocols from the
TrustedARI paper: an agent **A** and an Accountability Relay Interposer
**R** jointly emulate a *virtual TLS client* against an unmodified service
provider **S**, with privacy-preserving queries and verifiable billing.

All three parties run in-process as Python threads over a strict-FIFO byte
channel (`channel.py`), so the whole demo needs no network and no external
crypto services.

## Protocol coverage

| Paper component | File | Notes |
|---|---|---|
| Π_ths — 3-party ARI TLS handshake | `trustedari/handshake.py` | Full Protocol-3 flow: client random `r_i → Z_i` ECDHE split (`CKS = Z_A + Z_R`), per-party `ssk_i = Y^{r_i}`, ECtF point-add x-coordinate in the field, `fld_to_bits` to 256-bit shares, HKDF chain (HS→CHTS/SHTS→dHS→MS→CATS/SATS), 2PC `derive_tk`, agent-side server-flight decrypt + cert/CV/SF verification, commit `com_A = H(tk_A_sapp ∥ r)`, CF record relayed to S. |
| Template query (Π_LDC / Π_SHC / Π_I2S / Π_2PC-AEAD) | `trustedari/query.py` | Segment types `P / Af / Rf / Xf / As / Rs / Xs`; DP assembly plan minimizing `Σ (hl+hr)·⌈log2⌉` SHC cost; structure-hiding concat via arith→bits + `blind_rotate_left`; double-dabble I2S for `Content-Length`; 2PC AES-128-GCM encryption of the shared query under shared `tk_capp`, ct+tag public. |
| Verifiable billing (§6, Figure 6) | `trustedari/billing.py` | Adaptive boundary window (fwd prefix vs rev suffix, shorter wins); in-circuit AES-CTR window decrypt under reconstructed `tk_sapp`; JSON string/escape/depth FSM (`e_i`, `b_i`, `d_i` recurrences, fwd and rev); enforces `R_local[j..k] = φ:v` at declared depth `d_t`; re-checks `com_A = H(tk_A ∥ r)`; opens a single accept bit. |
| Unmodified TLS provider | `trustedari/tls_provider.py` | TLS-1.3-shaped server: CH/SH with ECDHE key_share, server flight (EE/CRT/CV/SF) under `tk_shs`, client-Finished check, JSON query/response over app records. Knows nothing about A/R. |

## Engine

`trustedari/twopc.py` + `ot.py` implement a GMW-style 2PC engine:
Chou-Orlandi base OTs → IKNP OT extension (`ELL=128`), XOR `Bits`,
additive `Arith` (mod 2^k) and `Fld` (mod secp256k1 p) shares; batched AND,
MUX, add/sub, eq, a2b/b2a, `blind_rotate_left`, field mul/inv.
`twopc.PC.use(MODE_SIM)` is a sim-only backend: shares are regenerated from
a truth annotation `.t`, so it preserves value correctness at real-2PC speed
— used for the standard crypto bulk (SHA-256/HMAC/AES/GHASH). The
paper-faithful 2PC steps (ECtF, SHC rotations, I2S dabble, the billing
parser/commit circuit) run under the real OT backend.

`trustedari/circuits.py` holds the 2PC-friendly crypto: SHA-256 (incl.
midstate `sha256_from_state` for HMAC precompute), HKDF expand with TLS-1.3
labels, ECtF x-coordinate add, `fld_to_bits`, AES-128 encrypt, GHASH/GCM.

## Deviations from the paper

- **Billing proof → interactive 2PC verification.** The paper instantiates
  Ckt(X,W) as a gnark PLONK proof over BN254/MiMC (no Go toolchain here).
  We run the *same relation* as an interactive two-party circuit — the same
  fairness: R (verifier) learns only the accept bit; soundness rests on the
  2PC engine instead of ZK.
- Crypto circuits (SHA-256/AES/GHASH) evaluate in `sim` mode for speed;
  the security-relevant steps run under real OT (see `MODE_OT` in tests).
- TLS is TLS-1.3-shaped but minimal: cert chain is a single CA signature,
  records use AES-128-GCM, no 0-RTT/resumption.

## Run

```bash
python3 demo.py              # full pipeline + one attack rejection
python3 tests/test_engine.py    # OT / share / primitive tests
python3 tests/test_circuits.py  # SHA-256/HMAC/AES/GHASH vectors
python3 tests/test_handshake.py # Π_ths + anti-misrouting (wrong cert name)
python3 tests/test_query.py     # SHC + Xs + template + I2S Content-Length
python3 tests/test_billing.py   # end-to-end + fwd/rev windows + 5 cases
python3 tests/test_billing_realot.py  # Figure-6 circuit under real OT
```

`test_billing_realot.py` runs the full billing circuit under the real
OT backend (no sim): a 1-block window verifies in ~16 s and ~4.3 MB of
A<->R traffic each way on this box, and a tampered ciphertext byte is
rejected.  `test_billing.py` additionally covers braces and an escaped
quote `\"` *inside* JSON strings — the FSM must keep them out of the
depth counter — in both window directions.

## Downstream application examples (`examples/`)

Two complete services built on the same pipeline — each subclasses
`TLSProvider` (so S stays unmodified) and supplies only a query template
plus the billed-field pattern:

```bash
python3 examples/llm_billing.py   # LLM API: hidden prompt + verified tokens
python3 examples/shop_order.py    # shop order: hidden addr + verified total
python3 examples/sub2api_relay.py # sub2api relay: quota charged only on accept
```

- **llm_billing** — `{"model":..,"prompt":"<As 53B>","max_tokens":"<Af>"}`;
  the prompt is agent-private. S answers OpenAI-style usage JSON; the
  billing circuit proves `usage.total_tokens` (depth 2) before R settles
  payment. Forging the count by −5 is rejected.
- **shop_order** — `{"sku":"<Af>","qty":"<Af>","addr":"<As>"}`; the
  shipping address stays hidden-length-private. S returns
  `{"order_id","total_cents","status"}`; circuit proves `total_cents`
  (depth 1) so R can release escrow. A −1 cent forgery is rejected.
- **sub2api_relay** — models a sub2api-style relay station: subscriber
  A holds an `sk-` key, R forwards the request to an unmodified
  OpenAI-compatible upstream (`api.openai.com`), and the subscriber's
  token quota is deducted only after the billing circuit accepts
  `usage.total_tokens` — under-reporting it by −8 is rejected and no
  quota is deducted. The file's docstring maps the three hooks a real
  deployment needs (`forward record → upstream roundtrip →
  verify-then-charge`).

## What the demo shows

`demo.py` runs handshake → query → response → billing in ~2s:

- R relays handshake bytes but learns only *shares* of the traffic keys; it
  cannot read A's query or S's response, and presenting a wrong service
  name breaks A's cert check (anti-misrouting).
- The query `{"tokens":10,"q":"translate"}` is assembled from a template
  with agent-private segments padded and SHC-merged — R sees only an opaque
  TLS record; the body length stays hidden (`As`/`Rs` types).
- Billing proves `usage.total_tokens = 10` sits at depth 2 inside the
  TLS-sealed response; forged values, wrong depth, bad commitments and
  tampered key shares are all rejected.
