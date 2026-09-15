"""App 3: a sub2api-style relay station with verifiable token billing.

Scenario (matches a real sub2api deployment):
  - Subscriber A holds an API key (sk-alice-...) issued by relay R.
  - R forwards A's chat request to the upstream provider S
    (an unmodified OpenAI-compatible endpoint, api.openai.com).
  - The prompt stays private to A (As segment): the relay must not see it.
  - Before R deducts tokens from the subscriber's quota, A and R run the
    billing circuit on the upstream response: A cannot under-report
    total_tokens (user cheating), R cannot over-report (relay padding the
    bill), and R still learns nothing except the accept bit.

In a real deployment the three hooks are:
    rec = forward_client_record(...)        # R relays the opaque TLS record
    resp = upstream.roundtrip(rec)          # S answers, R forwards it back
    if verify_billing_with_A(resp, ...):    # 2PC check, one bit out
        quota[user] -= total_tokens         # only then charge the subscriber

Query template (subscriber-private content):
  {"model":"gpt-4o-mini","messages":[{"role":"user","content":"<As>"}]}
Upstream response (OpenAI-compatible):
  {"id":..,"choices":[..],"usage":{"prompt_tokens":N,
   "completion_tokens":N,"total_tokens":N}}
The billed field '"total_tokens": N' sits at JSON depth 2 -> d_t = 2.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import secrets

from trustedari.tls_provider import TLSProvider
from trustedari import query as Q
from _lib import run_app

PRICE_MICROS_PER_TOKEN = 15  # $0.015 / 1k tokens


class UpstreamOpenAI(TLSProvider):
    """The upstream S: an ordinary OpenAI-compatible endpoint."""

    def __init__(self):
        super().__init__("api.openai.com")

    def _respond(self, query: dict) -> dict:
        msgs = query.get("messages", [])
        prompt = "".join(m.get("content", "") for m in msgs)
        p_tok = max(1, len(prompt) // 4)            # fake tokenizer
        c_tok = max(1, len(prompt) // 6)
        total = p_tok + c_tok
        return {
            "id": "chatcmpl-" + secrets.token_hex(6),
            "object": "chat.completion",
            "model": query.get("model", ""),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant",
                            "content": "ok " + secrets.token_hex(8)},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": p_tok,
                "completion_tokens": c_tok,
                "total_tokens": total,
            },
        }


PROMPT = b"Explain the paper's 3-party handshake in one line."


def segs(pc):
    pre = b'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"'
    tail = b'"}]}'
    return [Q.make_segment(pc, Q.P, pre, len(pre)),
            Q.make_segment(pc, Q.AS,
                           PROMPT if pc.side == 0 else None,
                           len(PROMPT) + 8,
                           len(PROMPT) if pc.side == 0 else None),
            Q.make_segment(pc, Q.P, tail, len(tail))]


def billed_total(body) -> int:
    return json.loads(body)["usage"]["total_tokens"]


def pat_fn(body):
    return b'"total_tokens": ' + str(billed_total(body)).encode()


def forged(body):
    """Subscriber tries to under-report by 8 tokens -> must be rejected."""
    return b'"total_tokens": ' + str(max(0, billed_total(body) - 8)).encode()


class Sub2APIStation:
    """Relay-side business logic, as in a sub2api deployment."""

    def __init__(self):
        self.quota = {"sk-alice": 1_000_000}       # tokens left
        self.charges = []

    def charge(self, key: str, tokens: int):
        if self.quota.get(key, 0) < tokens:
            raise RuntimeError("insufficient quota")
        self.quota[key] -= tokens
        self.charges.append((key, tokens))


def main():
    station = Sub2APIStation()
    S = UpstreamOpenAI()
    key = "sk-alice"

    print(f"[*] subscriber {key} quota before: "
          f"{station.quota[key]} tokens")

    res = run_app(S, "api.openai.com", segs, pat_fn, d_t=2,
                  forged_fn=forged)

    body = res["body"]
    print(f"[*] upstream response: {body.decode()}")
    print(f"[*] R sees only: opaque TLS record "
          f"({len(body)}B, prompt hidden)")

    # Relay-side settlement: charge ONLY if the circuit accepts.
    honest = res["accept"]
    if honest:
        station.charge(key, billed_total(body))
    print(f"[*] honest claim accept={honest} -> "
          f"quota after charge: {station.quota[key]} "
          f"(-{station.charges[-1][1] if station.charges else 0})")

    # A forged claim is rejected: nothing is deducted.
    print(f"[*] subscriber under-reports 'total_tokens-8': "
          f"accept={res['forged']} -> quota stays {station.quota[key]}")

    print(f"[*] comm A<->R: {res['comm']} B, wall {res['dt']:.1f}s")
    assert honest == 1 and res["forged"] == 0
    assert station.quota[key] == 1_000_000 - billed_total(body)


if __name__ == "__main__":
    print("== app3: sub2api relay station, verifiable usage billing ==")
    main()
