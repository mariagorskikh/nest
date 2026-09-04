"""Negotiation layer: alternating offers with an auditable session."""

from __future__ import annotations

from typing import Any

from . import register


class NegotiationError(Exception):
    pass


@register("negotiation", "haggle.v1")
class Haggle:
    """Offer, counter, accept, with alternation enforced and recorded."""

    def __init__(self, engine):
        self.engine = engine
        self.sessions: dict[str, dict[str, Any]] = {}
        self._seq = 0

    def start(self, buyer: str, seller: str, subject: str) -> str:
        self._seq += 1
        nid = f"n-{self._seq}"
        self.sessions[nid] = {"buyer": buyer, "seller": seller,
                              "subject": subject, "turn": buyer,
                              "last_cents": None, "state": "open",
                              "offers": []}
        self.engine.emit(buyer, "negotiation_started", nid,
                         {"seller": seller, "subject": subject})
        return nid

    def _step(self, nid: str, by: str) -> dict[str, Any]:
        s = self.sessions[nid]
        if s["state"] != "open":
            raise NegotiationError(f"session {nid} is {s['state']}")
        if by != s["turn"]:
            raise NegotiationError(f"not {by}'s turn in {nid}")
        return s

    def offer(self, nid: str, by: str, cents: int) -> None:
        s = self._step(nid, by)
        s["offers"].append((by, cents))
        s["last_cents"] = cents
        s["turn"] = s["seller"] if by == s["buyer"] else s["buyer"]
        kind = "offer_made" if by == s["buyer"] else "counter_made"
        self.engine.emit(by, kind, nid, {"cents": cents})

    def accept(self, nid: str, by: str) -> int:
        s = self._step(nid, by)
        s["state"] = "agreed"
        cents = s["last_cents"]
        self.engine.emit(by, "offer_accepted", nid, {"cents": cents})
        return cents

    def abandon(self, nid: str, by: str, reason: str = "") -> None:
        s = self.sessions[nid]
        s["state"] = "abandoned"
        detail = {"reason": reason} if reason else {}
        self.engine.emit(by, "negotiation_abandoned", nid, detail)

    def agreed_price(self, nid: str) -> int | None:
        s = self.sessions[nid]
        return s["last_cents"] if s["state"] == "agreed" else None
