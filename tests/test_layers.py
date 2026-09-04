import heapq
import random

import pytest

from nandatown.layers import DEFAULT_PLUGINS, LAYER_NAMES, UnknownPlugin, resolve
from nandatown.layers.data_facts import EvidenceError
from nandatown.layers.payments import PaymentError


class FakeEngine:
    def __init__(self, seed=42):
        self.rng = random.Random(seed)
        self.now = 0.0
        self.events = []
        self.delivered = []
        self._eseq = 0
        self._sseq = 0
        self._queue = []
        self.layers = {name: resolve(name, DEFAULT_PLUGINS[name])(self)
                       for name in LAYER_NAMES}

    def emit(self, observer, kind, subject, detail=None):
        self._eseq += 1
        self.events.append({"event_id": f"ev-{self._eseq}",
                            "observer": observer, "kind": kind,
                            "subject": subject, "detail": detail or {},
                            "at": self.now})
        return f"ev-{self._eseq}"

    def schedule(self, delay, fn):
        self._sseq += 1
        heapq.heappush(self._queue, (self.now + delay, self._sseq, fn))

    def deliver(self, to, envelope):
        self.delivered.append((to, envelope))

    def drain(self):
        while self._queue:
            at, _, fn = heapq.heappop(self._queue)
            self.now = at
            fn()

    def kinds(self):
        return [e["kind"] for e in self.events]


@pytest.fixture()
def eng():
    return FakeEngine()


def test_every_layer_has_a_default_plugin(eng):
    assert set(eng.layers) == set(LAYER_NAMES)
    with pytest.raises(UnknownPlugin):
        resolve("payments", "nope.v9")
    with pytest.raises(UnknownPlugin):
        resolve("not_a_layer", "x")


def test_ledger_conservation_and_escrow(eng):
    pay = eng.layers["payments"]
    pay.open_account("buyer", 10000)
    pay.open_account("seller", 0)
    start = pay.total()
    pay.hold("buyer", 3990, ref="order-1")
    assert pay.balance("buyer") == 6010
    assert pay.total() == start
    pay.release("order-1", "seller")
    assert pay.balance("seller") == 3990
    assert pay.total() == start
    with pytest.raises(PaymentError):
        pay.release("order-1", "seller")
    pay.hold("buyer", 1000, ref="order-2")
    pay.refund("order-2")
    assert pay.balance("buyer") == 6010 - 3990 + 3990
    assert pay.total() == start
    with pytest.raises(PaymentError):
        pay.transfer("seller", "buyer", 99999, memo="too much")
    assert "payment_rejected" in eng.kinds()


def test_auth_rejects_forged_sender(eng):
    identity = eng.layers["identity"]
    auth = eng.layers["auth"]
    identity.create("honest")
    identity.create("spoofer")
    payload = {"claim": "I am honest"}
    forged = auth.sign_as("spoofer", payload)
    assert auth.verify("honest", payload, forged) is False
    assert "signature_invalid" in eng.kinds()
    genuine = auth.sign_as("honest", payload)
    assert auth.verify("honest", payload, genuine) is True


def test_registry_verification_and_trust_ranking(eng):
    identity = eng.layers["identity"]
    auth = eng.layers["auth"]
    registry = eng.layers["registry"]
    trust = eng.layers["trust"]
    for name in ["seller-a", "seller-b", "spoofer"]:
        identity.create(name)
    card_a = identity.card("seller-a", ["sell.widget"], {"ask": 2000})
    card_b = identity.card("seller-b", ["sell.widget"], {"ask": 1995})
    registry.publish("seller-a", card_a, auth.sign_as("seller-a", card_a))
    registry.publish("seller-b", card_b, auth.sign_as("seller-b", card_b))
    fake = identity.card("spoofer", ["sell.widget"], {})
    fake = dict(fake, name="seller-a-lookalike")
    registry.publish("spoofer", fake, auth.sign_as("spoofer", card_a))
    assert "card_unverified" in eng.kinds()
    names = registry.names_with("sell.widget")
    assert "seller-a-lookalike" not in names
    trust.update("buyer", "seller-b", "good", "fact-1")
    assert registry.names_with("sell.widget")[0] == "seller-b"


def test_transport_faults(eng):
    comms = eng.layers["communication"]
    transport = eng.layers["transport"]
    transport.configure([{"action": "drop", "kind": "ping", "nth": 2}])
    for _ in range(3):
        env = comms.envelope("a", "b", "ping", {})
        transport.send("a", "b", env)
    eng.drain()
    assert len(eng.delivered) == 2
    assert eng.kinds().count("message_dropped") == 1

    eng2 = FakeEngine()
    t2 = eng2.layers["transport"]
    c2 = eng2.layers["communication"]
    t2.configure([{"action": "duplicate", "kind": "ping", "nth": 1}])
    t2.send("a", "b", c2.envelope("a", "b", "ping", {}))
    eng2.drain()
    assert len(eng2.delivered) == 2
    assert "message_duplicated" in eng2.kinds()


def test_negotiation_alternation_and_agreement(eng):
    neg = eng.layers["negotiation"]
    nid = neg.start("buyer", "seller", "widget")
    neg.offer(nid, "buyer", 1600)
    with pytest.raises(Exception):
        neg.offer(nid, "buyer", 1500)
    neg.offer(nid, "seller", 1800)
    price = neg.accept(nid, "buyer")
    assert price == 1800
    assert neg.agreed_price(nid) == 1800
    kinds = eng.kinds()
    assert "offer_made" in kinds and "counter_made" in kinds
    assert "offer_accepted" in kinds


def test_privacy_redaction(eng):
    priv = eng.layers["privacy"]
    priv.configure(["budget_cents"])
    record = {"detail": {"budget_cents": 9999, "sku": "widget",
                         "nested": [{"budget_cents": 1}]}}
    out = priv.redact(record)
    assert out["detail"]["budget_cents"] == "[redacted]"
    assert out["detail"]["nested"][0]["budget_cents"] == "[redacted]"
    assert out["detail"]["sku"] == "widget"
    assert record["detail"]["budget_cents"] == 9999


def test_data_facts_signed_and_not_self_written(eng):
    eng.layers["identity"].create("buyer")
    facts = eng.layers["data_facts"]
    rid = facts.attest("buyer", "seller", "trade.outcome", "good")
    assert rid == "fact-1"
    assert facts.about("seller")[0]["signature"]
    with pytest.raises(EvidenceError):
        facts.attest("seller", "seller", "trade.outcome", "good")


def test_contract_net_rules_and_late_bids(eng):
    coord = eng.layers["coordination"]
    coord.announce("mfg", "task-1", {"component": "axle"}, rule="lowest")
    coord.bid("task-1", "sup-a", 500)
    coord.bid("task-1", "sup-b", 400)
    winner, cents = coord.award("task-1")
    assert (winner, cents) == ("sup-b", 400)
    assert coord.bid("task-1", "sup-c", 100) is False
    assert "bid_rejected" in eng.kinds()
    coord.announce("auctioneer", "task-2", {"item": "print"}, rule="highest")
    coord.bid("task-2", "x", 700)
    coord.bid("task-2", "y", 900)
    assert coord.award("task-2") == ("y", 900)


def test_contract_net_rejects_duplicate_bid_and_preserves_first_amount(eng):
    """Sealed-bid contract retained from legacy PR #5 (@mariagorskikh)."""
    coord = eng.layers["coordination"]
    coord.announce("auctioneer", "sealed-task", {"item": "print"},
                   rule="highest")

    assert coord.bid("sealed-task", "bidder", 700) is True
    assert coord.bid("sealed-task", "bidder", 900) is False

    assert coord.award("sealed-task") == ("bidder", 700)
    placed = [event for event in eng.events
              if event["kind"] == "bid_placed"]
    assert len(placed) == 1
    rejected = [event for event in eng.events
                if event["kind"] == "bid_rejected"]
    assert rejected[-1]["detail"] == {
        "bidder": "bidder", "cents": 900, "reason": "duplicate bid",
    }


def test_memory_and_communication(eng):
    mem = eng.layers["memory"]
    mem.remember("buyer", "preferred_seller", "seller-b")
    assert mem.recall("buyer", "preferred_seller") == "seller-b"
    assert mem.recall("buyer", "missing") is None
    written = [e for e in eng.events if e["kind"] == "memory_written"]
    assert "value" not in written[0]["detail"]

    comms = eng.layers["communication"]
    m1 = comms.envelope("a", "b", "quote_request", {"sku": "w"})
    m2 = comms.reply(m1, "b", "quote_response", {"cents": 1995})
    assert m2["conversation"] == m1["conversation"]
    assert m2["to"] == "a"
    assert m1["message_id"] != m2["message_id"]
