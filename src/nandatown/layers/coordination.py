"""Coordination layer: contract-net task allocation.

An issuer announces a task, bidders place bids, and the award rule picks
the winner: lowest bid for procurement, highest for auctions. Late bids
are rejected once the task closes.
"""

from __future__ import annotations

from typing import Any

from . import register


@register("coordination", "contractnet.v1")
class ContractNet:
    """Announce, bid, award, with a declared award rule per task."""

    def __init__(self, engine):
        self.engine = engine
        self.tasks: dict[str, dict[str, Any]] = {}

    def announce(self, issuer: str, task_id: str, spec: dict[str, Any],
                 rule: str = "lowest") -> None:
        self.tasks[task_id] = {"issuer": issuer, "spec": spec, "rule": rule,
                               "bids": {}, "state": "open", "winner": None}
        self.engine.emit(issuer, "task_announced", task_id,
                         {"spec": spec, "rule": rule})

    def bid(self, task_id: str, bidder: str, cents: int) -> bool:
        task = self.tasks[task_id]
        if task["state"] != "open":
            self.engine.emit("town", "bid_rejected", task_id,
                             {"bidder": bidder, "cents": cents,
                              "reason": "task closed"})
            return False
        if bidder in task["bids"]:
            self.engine.emit("town", "bid_rejected", task_id,
                             {"bidder": bidder, "cents": cents,
                              "reason": "duplicate bid"})
            return False
        task["bids"][bidder] = cents
        self.engine.emit(bidder, "bid_placed", task_id, {"cents": cents})
        return True

    def award(self, task_id: str) -> tuple[str, int] | None:
        task = self.tasks[task_id]
        task["state"] = "closed"
        if not task["bids"]:
            self.engine.emit(task["issuer"], "task_unfilled", task_id, {})
            return None
        reverse = task["rule"] == "highest"
        winner, cents = sorted(task["bids"].items(),
                               key=lambda kv: (-kv[1] if reverse else kv[1],
                                               kv[0]))[0]
        task["winner"] = (winner, cents)
        self.engine.emit(task["issuer"], "task_awarded", task_id,
                         {"winner": winner, "cents": cents,
                          "rule": task["rule"],
                          "bids": dict(sorted(task["bids"].items()))})
        return winner, cents
