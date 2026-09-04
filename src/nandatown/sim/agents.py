"""Reference role agents: sealed, mechanical, deterministic state machines.

The toys are fixed, so runs are repeatable; there is no model inference,
so no tokens burn. Each agent touches the world only through its
TownAPI, and every decision rule is visible here.
"""

from __future__ import annotations

from typing import Any

from .api import TownAPI

ROLES: dict[str, type] = {}


def role(name: str):
    def wrap(cls):
        cls.role = name
        ROLES[name] = cls
        return cls
    return wrap


class SimAgent:
    role = "base"

    def __init__(self, name: str, config: dict[str, Any], api: TownAPI):
        self.name = name
        self.config = config
        self.api = api

    def on_start(self) -> None:
        pass

    def on_message(self, msg: dict[str, Any]) -> None:
        handler = getattr(self, "handle_" + msg["kind"], None)
        if handler is None:
            self.api.observe("message_unhandled", msg["message_id"],
                            {"kind": msg["kind"]})
            return
        handler(msg)


# -- marketplace -------------------------------------------------------


@role("seller")
class Seller(SimAgent):
    def on_start(self):
        c = self.config
        self.stock = c.get("stock", 10)
        self.api.register([f"sell.{c['sku']}"],
                          {"sku": c["sku"], "ask_cents": c["ask_cents"]})

    def handle_quote_request(self, msg):
        self.api.reply(msg, "quote_response",
                       {"sku": self.config["sku"],
                        "unit_cents": self.config["ask_cents"]})

    def handle_nego_offer(self, msg):
        nid = msg["body"]["nid"]
        offered = msg["body"]["cents"]
        floor = self.config["floor_cents"]
        ask = self.config["ask_cents"]
        neg = self.api._engine.layers["negotiation"]
        if offered >= floor:
            cents = neg.accept(nid, self.name)
            self.api.reply(msg, "nego_accepted", {"nid": nid, "cents": cents})
        else:
            counter = max(floor, (offered + ask) // 2)
            neg.offer(nid, self.name, counter)
            self.api.reply(msg, "nego_counter", {"nid": nid, "cents": counter})

    def handle_purchase_order(self, msg):
        body = msg["body"]
        if self.stock < body["quantity"]:
            self.api.reply(msg, "order_rejected",
                           {"order_id": body["order_id"],
                            "reason": "out of stock"})
            return
        self.stock -= body["quantity"]
        self.api.reply(msg, "delivery",
                       {"order_id": body["order_id"], "sku": body["sku"],
                        "quantity": body["quantity"]})


@role("buyer")
class Buyer(SimAgent):
    def on_start(self):
        self.round = 0
        self.quotes: dict[str, int] = {}
        self.active: dict[str, Any] = {}
        self.released: set[str] = set()
        self.api.register(["buy"])
        self.api.later(0.5, self.start_round)

    def start_round(self):
        self.round += 1
        self.quotes = {}
        preferred = self.api.recall("preferred_seller")
        if preferred:
            targets = [preferred]
        else:
            cards = self.api.lookup(f"sell.{self.config['sku']}")[:2]
            targets = [c["name"] for c in cards]
        if not targets:
            self.api.observe("buyer_gave_up", self.name,
                            {"reason": "no sellers found"})
            return
        for t in targets:
            self.api.send(t, "quote_request", {"sku": self.config["sku"]})
        self.api.later(self.config.get("quotes_wait", 1.0), self.close_quotes)

    def handle_quote_response(self, msg):
        self.quotes[msg["sender"]] = msg["body"]["unit_cents"]

    def close_quotes(self):
        if not self.quotes:
            self.api.observe("buyer_gave_up", self.name,
                            {"reason": "no quotes arrived"})
            return
        seller, ask = min(self.quotes.items(), key=lambda kv: (kv[1], kv[0]))
        nid = self.api.negotiation_start(seller, self.config["sku"])
        first = min(int(ask * 0.8), self.config["cap_cents"])
        self.api.negotiation_offer(nid, first)
        self.active = {"nid": nid, "seller": seller, "ask": ask}
        self.api.send(seller, "nego_offer", {"nid": nid, "cents": first})

    def handle_nego_counter(self, msg):
        cents = msg["body"]["cents"]
        if cents <= self.config["cap_cents"]:
            self.api.negotiation_accept(msg["body"]["nid"])
            self._purchase(cents)
        else:
            neg = self.api._engine.layers["negotiation"]
            neg.abandon(msg["body"]["nid"], self.name,
                        reason="price_above_cap")

    def handle_nego_accepted(self, msg):
        self._purchase(msg["body"]["cents"])

    def _purchase(self, unit_cents: int):
        if unit_cents > self.config["cap_cents"]:
            neg = self.api._engine.layers["negotiation"]
            neg.abandon(self.active["nid"], self.name,
                        reason="price_above_cap")
            return
        qty = self.config["quantity"]
        order_id = f"order-{self.name}-{self.round}"
        self.api.escrow_hold(unit_cents * qty, ref=order_id)
        self.api.send(self.active["seller"], "purchase_order",
                      {"order_id": order_id, "sku": self.config["sku"],
                       "quantity": qty, "unit_cents": unit_cents})

    def handle_delivery(self, msg):
        order_id = msg["body"]["order_id"]
        if order_id in self.released:
            self.api.observe("duplicate_recognized", order_id,
                            {"kind": "delivery"})
            return
        self.released.add(order_id)
        self.api.escrow_release(order_id, msg["sender"])
        self.api.rate(msg["sender"], "good")
        self.api.remember("preferred_seller", msg["sender"])
        if self.round < self.config.get("rounds", 1):
            self.api.later(1.0, self.start_round)


@role("spoofer")
class Spoofer(SimAgent):
    """Registers a capability card signed with the wrong key."""

    def on_start(self):
        self.api.register([self.config["claimed_capability"]],
                          {"note": "totally legitimate"},
                          forge_key_of=self.config.get("forge_key_of",
                                                       "shadow"))

    def handle_quote_request(self, msg):
        self.api.reply(msg, "quote_response",
                       {"sku": msg["body"]["sku"], "unit_cents": 1})


# -- auction -----------------------------------------------------------


@role("auctioneer")
class Auctioneer(SimAgent):
    def on_start(self):
        self.api.register(["auction.host"])
        self.paid = False
        self.api.later(0.5, self.open_auction)

    def open_auction(self):
        c = self.config
        self.task_id = f"auction-{c['item']}"
        self.api.announce(self.task_id, {"item": c["item"]}, rule="highest")
        self.bidders = [b["name"] for b in self.api.lookup("auction.bid")]
        for b in self.bidders:
            self.api.send(b, "auction_open",
                          {"task_id": self.task_id, "item": c["item"]})
        self.api.later(c.get("close_after", 3.0), self.close)

    def handle_auction_bid(self, msg):
        coord = self.api._engine.layers["coordination"]
        coord.bid(msg["body"]["task_id"], msg["sender"],
                  msg["body"]["cents"])

    def close(self):
        awarded = self.api.award(self.task_id)
        if awarded is None:
            return
        winner, cents = awarded
        self.api.send(winner, "auction_won",
                      {"task_id": self.task_id, "cents": cents})
        for b in self.bidders:
            self.api.send(b, "auction_result",
                          {"task_id": self.task_id, "winner": winner,
                           "cents": cents})

    def handle_auction_payment(self, msg):
        if self.paid:
            return
        self.paid = True
        self.api.send(msg["sender"], "item_delivery",
                      {"task_id": msg["body"]["task_id"],
                       "item": self.config["item"]})


@role("bidder")
class Bidder(SimAgent):
    def on_start(self):
        self.api.register(["auction.bid"])

    def handle_auction_open(self, msg):
        body = msg["body"]
        delay = self.config.get("bid_delay", 1.0)
        self.api.later(delay, lambda: self.api.send(
            msg["sender"], "auction_bid",
            {"task_id": body["task_id"],
             "cents": self.config["valuation_cents"]}))

    def handle_auction_won(self, msg):
        body = msg["body"]
        self.api.pay(msg["sender"], body["cents"], memo=body["task_id"])
        self.api.reply(msg, "auction_payment",
                       {"task_id": body["task_id"], "cents": body["cents"]})

    def handle_auction_result(self, msg):
        self.api.remember("auction_result", msg["body"])

    def handle_item_delivery(self, msg):
        self.api.rate(msg["sender"], "good")


# -- voting ------------------------------------------------------------


@role("ballot_box")
class BallotBox(SimAgent):
    def on_start(self):
        self.api.register(["vote.tally"])
        self.voted: set[str] = set()
        self.counts: dict[str, int] = {c: 0 for c in self.config["choices"]}
        self.api.later(0.5, self.open_vote)

    def open_vote(self):
        self.voters = [v["name"] for v in self.api.lookup("vote.cast")]
        for v in self.voters:
            self.api.send(v, "vote_open",
                          {"choices": self.config["choices"]})
        self.api.later(self.config.get("close_after", 3.0), self.tally)

    def handle_ballot(self, msg):
        voter = msg["sender"]
        choice = msg["body"]["choice"]
        if voter in self.voted:
            self.api.observe("ballot_rejected", voter,
                            {"reason": "already voted"})
            return
        if choice not in self.counts:
            self.api.observe("ballot_rejected", voter,
                            {"reason": "unknown choice"})
            return
        self.voted.add(voter)
        self.counts[choice] += 1
        self.api.observe("ballot_cast", voter, {"choice": choice})

    def tally(self):
        self.api.observe("vote_result", "vote",
                        {"counts": self.counts,
                         "total": sum(self.counts.values())})
        for v in self.voters:
            self.api.send(v, "vote_result", {"counts": self.counts})


@role("voter")
class Voter(SimAgent):
    def on_start(self):
        self.api.register(["vote.cast"])

    def handle_vote_open(self, msg):
        self.api.reply(msg, "ballot", {"choice": self.config["choice"]})
        if self.config.get("double_vote"):
            self.api.later(0.2, lambda: self.api.reply(
                msg, "ballot", {"choice": self.config["choice"]}))

    def handle_vote_result(self, msg):
        self.api.remember("vote_result", msg["body"]["counts"])


# -- consensus ---------------------------------------------------------


@role("proposer")
class Proposer(SimAgent):
    def on_start(self):
        self.api.register(["consensus.propose"])
        self.acks: set[str] = set()
        self.committed = False
        self.api.later(0.5, self.start_proposal)

    def start_proposal(self):
        self.acceptors = [a["name"]
                          for a in self.api.lookup("consensus.accept")]
        self.quorum = len(self.acceptors) // 2 + 1
        self._send_prepare(self.acceptors)
        self.api.later(self.config.get("retry_after", 1.5), self.check)

    def _send_prepare(self, targets):
        for a in targets:
            self.api.send(a, "prepare", {"value": self.config["value"]})

    def handle_prepare_ack(self, msg):
        self.acks.add(msg["sender"])
        if not self.committed and len(self.acks) >= self.quorum:
            self.committed = True
            self.api.observe("consensus_committed", self.config["value"],
                            {"acks": sorted(self.acks),
                             "quorum": self.quorum})
            for a in self.acceptors:
                self.api.send(a, "commit", {"value": self.config["value"]})

    def check(self):
        if self.committed:
            return
        missing = [a for a in self.acceptors if a not in self.acks]
        if missing:
            self.api.observe("proposal_retry", self.name,
                            {"missing": missing})
            self._send_prepare(missing)
            self.api.later(self.config.get("retry_after", 1.5), self.check)


@role("acceptor")
class Acceptor(SimAgent):
    def on_start(self):
        self.api.register(["consensus.accept"])

    def handle_prepare(self, msg):
        self.api.reply(msg, "prepare_ack", {"value": msg["body"]["value"]})

    def handle_commit(self, msg):
        value = msg["body"]["value"]
        self.api.remember("committed", value)
        self.api.observe("value_committed", self.name, {"value": value})


# -- supply chain ------------------------------------------------------


@role("customer")
class Customer(SimAgent):
    def on_start(self):
        self.api.register(["buy"])
        self.done = False
        self.api.later(0.5, self.place_order)

    def place_order(self):
        c = self.config
        makers = self.api.lookup(f"mfg.{c['product']}")
        if not makers:
            self.api.observe("buyer_gave_up", self.name,
                            {"reason": "no manufacturer"})
            return
        maker = makers[0]["name"]
        self.order_id = f"po-{c['product']}"
        self.api.escrow_hold(c["price_cents"], ref=self.order_id)
        self.api.send(maker, "order",
                      {"order_id": self.order_id, "product": c["product"],
                       "price_cents": c["price_cents"]})

    def handle_product_delivery(self, msg):
        if self.done:
            return
        self.done = True
        self.api.escrow_release(self.order_id, msg["sender"])
        self.api.rate(msg["sender"], "good")


@role("manufacturer")
class Manufacturer(SimAgent):
    def on_start(self):
        c = self.config
        self.api.register([f"mfg.{c['product']}"])
        self.parts_needed = list(c["components"])
        self.parts_done: set[str] = set()
        self.awards: dict[str, tuple[str, int]] = {}

    def handle_order(self, msg):
        self.order = msg["body"]
        self.order_sender = msg["sender"]
        for component in self.parts_needed:
            task_id = f"supply-{component}"
            self.api.announce(task_id, {"component": component},
                              rule="lowest")
            for s in self.api.lookup(f"supply.{component}"):
                self.api.send(s["name"], "supply_request",
                              {"task_id": task_id, "component": component})
            self.api.later(self.config.get("bid_wait", 1.0),
                           lambda t=task_id: self.award_task(t))

    def award_task(self, task_id):
        awarded = self.api.award(task_id)
        if awarded is None:
            return
        winner, cents = awarded
        self.awards[task_id] = (winner, cents)
        self.api.escrow_hold(cents, ref=task_id)
        self.api.send(winner, "part_order",
                      {"task_id": task_id, "cents": cents})

    def handle_part_delivery(self, msg):
        task_id = msg["body"]["task_id"]
        if task_id in self.parts_done:
            return
        self.parts_done.add(task_id)
        self.api.escrow_release(task_id, msg["sender"])
        self.api.rate(msg["sender"], "good")
        if len(self.parts_done) == len(self.parts_needed):
            self.api.later(self.config.get("assembly_delay", 0.5),
                           self.assemble)

    def assemble(self):
        self.api.observe("product_assembled", self.order["order_id"],
                        {"parts": sorted(self.parts_done)})
        self.api.send(self.order_sender, "product_delivery",
                      {"order_id": self.order["order_id"],
                       "product": self.order["product"]})


@role("supplier")
class Supplier(SimAgent):
    def on_start(self):
        self.api.register([f"supply.{self.config['component']}"])

    def handle_supply_request(self, msg):
        self.api.bid(msg["body"]["task_id"], self.config["price_cents"])

    def handle_part_order(self, msg):
        self.api.reply(msg, "part_delivery",
                       {"task_id": msg["body"]["task_id"],
                        "component": self.config["component"]})
