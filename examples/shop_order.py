"""App 2: e-commerce order with verifiable total price.

Scenario: agent A orders goods from shop S through relay R.
  - sku/qty fixed-width agent-private (Af), delivery address hidden-length
    private (As): R sees only an opaque record, not what/where was ordered.
  - S replies {"order_id":..,"total_cents":..,"status":"confirmed"};
    billing circuit proves A's reported total matches the TLS record, so R
    can release escrowed payment without seeing the order details.

  q = {"sku":"<Af 6>","qty":<Af 2>,"addr":"<As>"}
  resp = {"order_id":"ORD-..","total_cents":12900,"status":"confirmed",
          "sku":"..","eta_days":3}
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


class ShopProvider(TLSProvider):
    PRICE_TABLE = {"SKU-12": 6450, "SKU-34": 1299}

    def __init__(self):
        super().__init__("shop.example.com")

    def _respond(self, query: dict) -> dict:
        sku = query.get("sku", "")
        qty = int(query.get("qty", 0))
        total = self.PRICE_TABLE.get(sku, 0) * qty
        return {
            "order_id": "ORD-" + secrets.token_hex(4).upper(),
            "total_cents": total,
            "status": "confirmed" if total else "out_of_stock",
            "sku": sku,
            "eta_days": 3,
        }


SKU, QTY = b"SKU-12", b"02"
ADDR = b"221B Baker Street, London"


def segs(pc):
    pre = b'{"sku":"'
    m1 = b'","qty":"'
    m2 = b'","addr":"'
    tail = b'"}'
    return [Q.make_segment(pc, Q.P, pre, len(pre)),
            Q.make_segment(pc, Q.AF, SKU if pc.side == 0 else None, 6),
            Q.make_segment(pc, Q.P, m1, len(m1)),
            Q.make_segment(pc, Q.AF, QTY if pc.side == 0 else None, 2),
            Q.make_segment(pc, Q.P, m2, len(m2)),
            Q.make_segment(pc, Q.AS, ADDR if pc.side == 0 else None,
                           len(ADDR) + 8,
                           len(ADDR) if pc.side == 0 else None),
            Q.make_segment(pc, Q.P, tail, len(tail))]


def pat_fn(body):
    doc = json.loads(body)
    return b'"total_cents": ' + str(doc["total_cents"]).encode()


def forged(body):
    doc = json.loads(body)
    return b'"total_cents": ' + str(doc["total_cents"] - 1).encode()


def main():
    S = ShopProvider()
    res = run_app(S, "shop.example.com", segs, pat_fn, d_t=1,
                  forged_fn=forged)
    print(f"[*] response: {res['body'].decode()}")
    print(f"[*] billed field: {res['pat'].decode()}  window={res['win'].rho}")
    print(f"[*] honest claim accept={res['accept']}   "
          f"forged 'total_cents-1' accept={res['forged']}")
    print(f"[*] comm {res['comm']} B, wall {res['dt']:.1f}s")
    assert res["accept"] == 1 and res["forged"] == 0


if __name__ == "__main__":
    print("== app2: e-commerce order, verified total price ==")
    main()
