"""Synchronous in-process channel between protocol parties.

Each party runs in its own thread; the only data it can observe are (a) its
local state and (b) messages it explicitly receives over the channel -- this is
what makes each party's *view* well-defined in the simulation.

The channel counts transferred bytes so the demo can report communication
costs the same way the paper's evaluation does.
"""
from __future__ import annotations

import queue
import threading
from typing import Any, Tuple


class Chan:
    """Bidirectional tagged channel between exactly two parties."""

    def __init__(self) -> None:
        self._q = (queue.Queue(), queue.Queue())
        self.bytes_sent = (0, 0)  # per direction
        self.msgs_sent = (0, 0)

    def send(self, side: int, tag: str, payload: bytes) -> None:
        """Side `side` sends; the *peer* (endpoint 1-side) reads it."""
        assert isinstance(payload, (bytes, bytearray))
        self._q[side].put((tag, bytes(payload)))
        self.bytes_sent = (
            self.bytes_sent[0] + (len(payload) if side == 0 else 0),
            self.bytes_sent[1] + (len(payload) if side == 1 else 0),
        )
        self.msgs_sent = (
            self.msgs_sent[0] + (1 if side == 0 else 0),
            self.msgs_sent[1] + (1 if side == 1 else 0),
        )

    def recv(self, side: int, tag: str, timeout: float = 300.0) -> bytes:
        t, p = self._q[1 - side].get(timeout=timeout)
        assert t == tag, f"protocol desync: expected {tag!r}, got {t!r}"
        return p

    @property
    def total_bytes(self) -> int:
        return sum(self.bytes_sent)


def run_two_parties(fn_a, fn_r, timeout: float = 600.0) -> Tuple[Any, Any]:
    """Run party-A and party-R roles in threads. Returns (a_out, r_out)."""
    out_a, out_r = [], []
    err = []

    def wrap(fn, out):
        try:
            out.append(fn())
        except Exception as e:  # pragma: no cover - surfaced to caller
            import traceback
            traceback.print_exc()
            err.append(e)

    ta = threading.Thread(target=wrap, args=(fn_a, out_a), daemon=True)
    tr = threading.Thread(target=wrap, args=(fn_r, out_r), daemon=True)
    ta.start()
    tr.start()
    ta.join(timeout)
    tr.join(timeout)
    if ta.is_alive() or tr.is_alive():
        raise TimeoutError("two-party protocol did not finish (deadlock?)")
    if err:
        raise err[0]
    return (out_a[0] if out_a else None), (out_r[0] if out_r else None)
