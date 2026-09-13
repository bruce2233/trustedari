"""App 1: LLM API with verifiable token billing.

Scenario: agent A buys LLM completions from provider S through relay R.
  - The prompt is agent-private (As segment): R must not learn it.
  - max_tokens is fixed-width agent-private (Af).
  - S answers OpenAI-style usage JSON; A must prove to R the *real*
    total_tokens so R can settle payment for the ARI service.

  q = {"model":"gpt-mini","prompt":"<As>","max_tokens":<Af 3>}
  resp = {"id":..,"model":..,"usage":{"prompt_tokens":..,"completion_tokens":..,
          "total_tokens":..},"cost_micros":..}
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


class LLMProvider(TLSProvider):
    """OpenAI-shaped completions endpoint."""

    def __init__(self):
        super().__init__("llm.example.com")

    def _respond(self, query: dict) -> dict:
        prompt = query.get("prompt", "")
        p_tok = max(1, len(prompt) // 4)               # fake tokenizer
        c_tok = max(1, int(query.get("max_tokens", 1)) // 2)
        total = p_tok + c_tok
        return {
            "id": "chatcmpl-" + secrets.token_hex(6),
            "model": query.get("model", ""),
            "usage": {
                "prompt_tokens": p_tok,
                "completion_tokens": c_tok,
                "total_tokens": total,
            },
            "cost_micros": total * 250,                # 0.25$ per 1k tokens
        }


PROMPT = b"Summarize the ARI relay model in one sentence."
MAXTOK = b"064"


def segs(pc):
    pre = b'{"model":"gpt-mini","prompt":"'
    mid = b'","max_tokens":"'
    tail = b'"}'
    return [Q.make_segment(pc, Q.P, pre, len(pre)),
            Q.make_segment(pc, Q.AS,
                           PROMPT if pc.side == 0 else None,
                           len(PROMPT) + 8,
                           len(PROMPT) if pc.side == 0 else None),
            Q.make_segment(pc, Q.P, mid, len(mid)),
            Q.make_segment(pc, Q.AF, MAXTOK if pc.side == 0 else None, 3),
            Q.make_segment(pc, Q.P, tail, len(tail))]


def pat_fn(body):
    doc = json.loads(body)
    return b'"total_tokens": ' + str(doc["usage"]["total_tokens"]).encode()


def forged(body):
    doc = json.loads(body)
    v = doc["usage"]["total_tokens"]
    return b'"total_tokens": ' + str(max(0, v - 5)).encode()


def main():
    S = LLMProvider()
    res = run_app(S, "llm.example.com", segs, pat_fn, d_t=2,
                  forged_fn=forged)
    print(f"[*] response: {res['body'].decode()}")
    print(f"[*] billed field: {res['pat'].decode()}  window={res['win'].rho}")
    print(f"[*] honest claim accept={res['accept']}   "
          f"forged 'total_tokens-5' accept={res['forged']}")
    print(f"[*] comm {res['comm']} B, wall {res['dt']:.1f}s")
    assert res["accept"] == 1 and res["forged"] == 0


if __name__ == "__main__":
    print("== app1: LLM API verifiable token billing ==")
    main()
