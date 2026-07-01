# SPDX-License-Identifier: Apache-2.0
"""Conformance tests for all 12 reference plugins."""

from __future__ import annotations

import pytest
from nest_core.types import (
    AgentCard,
    AgentId,
    DatasetMetadata,
    Evidence,
    Message,
    MessageId,
    Money,
    NegotiationStatus,
    PaymentRef,
    PaymentStatus,
    Query,
    Receipt,
    ServiceRef,
    Statement,
    Task,
    Terms,
    Witness,
)

# ---------------------------------------------------------------------------
# 1. Transport: in_memory
# ---------------------------------------------------------------------------


class TestInMemoryTransport:
    @pytest.mark.asyncio
    async def test_send_receive(self) -> None:
        from nest_plugins_reference.transport.in_memory import (
            InMemoryNetwork,
            StandaloneInMemoryTransport,
        )

        network = InMemoryNetwork()
        t1 = StandaloneInMemoryTransport(AgentId("a1"), network)
        t2 = StandaloneInMemoryTransport(AgentId("a2"), network)

        await t1.send(AgentId("a2"), b"hello")
        sender, payload = await t2.receive()
        assert sender == AgentId("a1")
        assert payload == b"hello"

    @pytest.mark.asyncio
    async def test_broadcast(self) -> None:
        from nest_plugins_reference.transport.in_memory import (
            InMemoryNetwork,
            StandaloneInMemoryTransport,
        )

        network = InMemoryNetwork()
        t1 = StandaloneInMemoryTransport(AgentId("a1"), network)
        t2 = StandaloneInMemoryTransport(AgentId("a2"), network)
        t3 = StandaloneInMemoryTransport(AgentId("a3"), network)

        await t1.broadcast(b"announce")
        _, p2 = await t2.receive()
        _, p3 = await t3.receive()
        assert p2 == b"announce"
        assert p3 == b"announce"


# ---------------------------------------------------------------------------
# 2. Comms: nest_native
# ---------------------------------------------------------------------------


class TestNestNativeComms:
    def test_serialize_deserialize(self) -> None:
        from nest_plugins_reference.comms.nest_native import NestNativeComms

        comms = NestNativeComms(AgentId("a1"))
        msg = Message(
            id=MessageId("m1"),
            sender=AgentId("a1"),
            receiver=AgentId("a2"),
            payload=b"test data",
        )
        raw = comms.serialize(msg)
        msg2 = comms.deserialize(raw)
        assert msg2.id == msg.id
        assert msg2.sender == msg.sender
        assert msg2.payload == msg.payload

    @pytest.mark.asyncio
    async def test_send(self) -> None:
        from nest_plugins_reference.comms.nest_native import NestNativeComms

        comms = NestNativeComms(AgentId("a1"))
        msg = Message(
            id=MessageId("m1"),
            sender=AgentId("a1"),
            receiver=AgentId("a2"),
            payload=b"test",
        )
        resp = await comms.send(AgentId("a2"), msg)
        assert resp.success is True


# ---------------------------------------------------------------------------
# 3. Identity: did_key
# ---------------------------------------------------------------------------


class TestDidKeyIdentity:
    def test_sign_verify(self) -> None:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"payload")
        assert sig.signer == AgentId("a1")
        assert ident.verify(b"payload", sig, AgentId("a1"))

    def test_verify_wrong_payload(self) -> None:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        sig = ident.sign(b"payload")
        assert not ident.verify(b"wrong", sig, AgentId("a1"))

    def test_verify_peer_with_public_key_only(self) -> None:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        sender = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        verifier = DidKeyIdentity(AgentId("a2"), seed=b"seed")
        verifier.register_peer(AgentId("a1"), sender.public_key)

        sig = sender.sign(b"payload")
        assert verifier.verify(b"payload", sig, AgentId("a1"))

    def test_register_peer_rejects_private_key(self) -> None:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        with pytest.raises(ValueError, match="public keys only"):
            ident.register_peer(AgentId("a2"), ident.public_key, private_key=b"secret")

    @pytest.mark.asyncio
    async def test_resolve(self) -> None:
        from nest_plugins_reference.identity.did_key import DidKeyIdentity

        ident = DidKeyIdentity(AgentId("a1"), seed=b"seed")
        info = await ident.resolve(AgentId("a1"))
        assert info.agent_id == AgentId("a1")
        assert info.method == "did:key"
        assert len(info.public_key) > 0


# ---------------------------------------------------------------------------
# 4. Registry: in_memory
# ---------------------------------------------------------------------------


class TestInMemoryRegistry:
    @pytest.mark.asyncio
    async def test_register_lookup(self) -> None:
        from nest_plugins_reference.registry.in_memory import InMemoryRegistry

        reg = InMemoryRegistry()
        card = AgentCard(agent_id=AgentId("a1"), name="Seller", capabilities=["sell"])
        await reg.register(card)

        results = await reg.lookup(Query(capabilities=["sell"]))
        assert len(results) == 1
        assert results[0].agent_id == AgentId("a1")

    @pytest.mark.asyncio
    async def test_lookup_no_match(self) -> None:
        from nest_plugins_reference.registry.in_memory import InMemoryRegistry

        reg = InMemoryRegistry()
        card = AgentCard(agent_id=AgentId("a1"), name="Buyer", capabilities=["buy"])
        await reg.register(card)

        results = await reg.lookup(Query(capabilities=["sell"]))
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_deregister(self) -> None:
        from nest_plugins_reference.registry.in_memory import InMemoryRegistry

        reg = InMemoryRegistry()
        card = AgentCard(agent_id=AgentId("a1"), name="Agent", capabilities=["x"])
        await reg.register(card)
        await reg.deregister(AgentId("a1"))

        results = await reg.lookup(Query())
        assert len(results) == 0


# ---------------------------------------------------------------------------
# 5. Auth: jwt
# ---------------------------------------------------------------------------


class TestJwtAuth:
    @pytest.mark.asyncio
    async def test_issue_verify(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        auth = JwtAuth(secret=b"test-secret")
        token = await auth.issue(AgentId("a1"), ["read", "write"])
        ctx = await auth.verify(token)
        assert ctx.subject == AgentId("a1")
        assert ctx.scopes == ["read", "write"]

    @pytest.mark.asyncio
    async def test_revoke(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        auth = JwtAuth(secret=b"test-secret")
        token = await auth.issue(AgentId("a1"), ["read"])
        await auth.revoke(token)
        with pytest.raises(ValueError, match="revoked"):
            await auth.verify(token)

    @pytest.mark.asyncio
    async def test_invalid_signature(self) -> None:
        from nest_plugins_reference.auth.jwt_auth import JwtAuth

        auth = JwtAuth(secret=b"secret1")
        token = await auth.issue(AgentId("a1"), ["read"])

        auth2 = JwtAuth(secret=b"secret2")
        with pytest.raises(ValueError, match="signature"):
            await auth2.verify(token)


# ---------------------------------------------------------------------------
# 6. Trust: score_average
# ---------------------------------------------------------------------------


class TestScoreAverageTrust:
    @pytest.mark.asyncio
    async def test_default_score(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        score = await trust.score(AgentId("a1"))
        assert score.score == 0.5
        assert score.confidence == 0.0
        assert score.sample_count == 0

    @pytest.mark.asyncio
    async def test_report_updates_score(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        ev = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        await trust.report(AgentId("a1"), ev)
        await trust.report(AgentId("a1"), ev)

        score = await trust.score(AgentId("a1"))
        assert score.score == 1.0
        assert score.sample_count == 2

    @pytest.mark.asyncio
    async def test_negative_report(self) -> None:
        from nest_plugins_reference.trust.score_average import ScoreAverageTrust

        trust = ScoreAverageTrust()
        pos = Evidence(reporter=AgentId("a2"), subject=AgentId("a1"), kind="positive")
        neg = Evidence(reporter=AgentId("a3"), subject=AgentId("a1"), kind="negative")
        await trust.report(AgentId("a1"), pos)
        await trust.report(AgentId("a1"), neg)

        score = await trust.score(AgentId("a1"))
        assert score.score == 0.5


# ---------------------------------------------------------------------------
# 7. Payments: prepaid_credits
# ---------------------------------------------------------------------------


class TestPrepaidCredits:
    @pytest.mark.asyncio
    async def test_pay_and_verify(self) -> None:
        from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits

        pay = PrepaidCredits(AgentId("a1"), initial_balance=1000)
        receipt = await pay.pay(AgentId("a2"), Money(amount=100), PaymentRef("p1"))
        assert receipt.payer == AgentId("a1")
        assert receipt.payee == AgentId("a2")
        assert pay.balance(AgentId("a1")) == 900
        assert pay.balance(AgentId("a2")) == 100

        status = await pay.verify_payment(PaymentRef("p1"))
        assert status == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_insufficient_balance(self) -> None:
        from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits

        pay = PrepaidCredits(AgentId("a1"), initial_balance=10)
        with pytest.raises(ValueError, match="Insufficient"):
            await pay.pay(AgentId("a2"), Money(amount=100), PaymentRef("p1"))

    @pytest.mark.asyncio
    async def test_refund(self) -> None:
        from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits

        pay = PrepaidCredits(AgentId("a1"), initial_balance=1000)
        await pay.pay(AgentId("a2"), Money(amount=100), PaymentRef("p1"))
        await pay.refund(PaymentRef("p1"))
        assert pay.balance(AgentId("a1")) == 1000
        assert pay.balance(AgentId("a2")) == 0

    @pytest.mark.asyncio
    async def test_quote(self) -> None:
        from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits

        pay = PrepaidCredits(AgentId("a1"))
        q = await pay.quote(ServiceRef("svc"))
        assert q.price.amount == 10

    @pytest.mark.asyncio
    async def test_shared_ledger_debits_calling_agent(self) -> None:
        from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits

        balances = {AgentId("buyer"): 100, AgentId("seller"): 0}
        payments: dict[PaymentRef, Receipt] = {}
        buyer = PrepaidCredits(AgentId("buyer"), balances=balances, payments=payments)
        seller = PrepaidCredits(AgentId("seller"), balances=balances, payments=payments)

        await buyer.pay(AgentId("seller"), Money(amount=40), PaymentRef("p1"))

        assert buyer.balance(AgentId("buyer")) == 60
        assert seller.balance(AgentId("seller")) == 40
        assert await seller.verify_payment(PaymentRef("p1")) == PaymentStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_rejects_non_positive_payment(self) -> None:
        from nest_plugins_reference.payments.prepaid_credits import PrepaidCredits

        pay = PrepaidCredits(AgentId("a1"), initial_balance=100)
        with pytest.raises(ValueError, match="positive"):
            await pay.pay(AgentId("a2"), Money(amount=0), PaymentRef("p1"))


# ---------------------------------------------------------------------------
# 8. Coordination: contract_net
# ---------------------------------------------------------------------------


class TestContractNet:
    @pytest.mark.asyncio
    async def test_propose_participate_resolve(self) -> None:
        from nest_plugins_reference.coordination.contract_net import ContractNet

        manager = ContractNet(AgentId("mgr"))
        worker1 = ContractNet(AgentId("w1"))
        worker2 = ContractNet(AgentId("w2"))

        task = Task(id="t1", description="process")
        rnd = await manager.propose(task)

        await worker1.participate(rnd)
        await worker2.participate(rnd)

        outcome = await manager.resolve(rnd)
        assert outcome.task.id == "t1"
        assert outcome.winner is not None

    @pytest.mark.asyncio
    async def test_commit_cleans_up(self) -> None:
        from nest_plugins_reference.coordination.contract_net import ContractNet

        coord = ContractNet(AgentId("a1"))
        task = Task(id="t1", description="work")
        rnd = await coord.propose(task)
        await coord.participate(rnd)
        outcome = await coord.resolve(rnd)
        await coord.commit(outcome)


# ---------------------------------------------------------------------------
# 9. Negotiation: alternating_offers
# ---------------------------------------------------------------------------


class TestAlternatingOffers:
    @pytest.mark.asyncio
    async def test_open_offer_respond_close(self) -> None:
        from nest_plugins_reference.negotiation.alternating_offers import AlternatingOffers

        neg = AlternatingOffers(AgentId("a1"))
        session = await neg.open(AgentId("a2"), Terms(price=Money(amount=100)))
        assert session.status == NegotiationStatus.OPEN

        await neg.offer(session, Terms(price=Money(amount=80)))
        resp = await neg.respond(session)
        assert isinstance(resp.accepted, bool)

        agreement = await neg.close(session)
        assert agreement is not None
        assert agreement.session_id == session.id

    @pytest.mark.asyncio
    async def test_no_terms(self) -> None:
        from nest_plugins_reference.negotiation.alternating_offers import AlternatingOffers

        neg = AlternatingOffers(AgentId("a1"))
        session = await neg.open(AgentId("a2"), Terms())
        resp = await neg.respond(session)
        assert resp.accepted is True


# ---------------------------------------------------------------------------
# 10. Memory: blackboard
# ---------------------------------------------------------------------------


class TestBlackboard:
    @pytest.mark.asyncio
    async def test_read_write(self) -> None:
        from nest_plugins_reference.memory.blackboard import Blackboard

        bb = Blackboard()
        assert await bb.read("key") is None
        await bb.write("key", b"value")
        assert await bb.read("key") == b"value"

    @pytest.mark.asyncio
    async def test_cas_success(self) -> None:
        from nest_plugins_reference.memory.blackboard import Blackboard

        bb = Blackboard()
        await bb.write("x", b"old")
        assert await bb.cas("x", b"old", b"new") is True
        assert await bb.read("x") == b"new"

    @pytest.mark.asyncio
    async def test_cas_failure(self) -> None:
        from nest_plugins_reference.memory.blackboard import Blackboard

        bb = Blackboard()
        await bb.write("x", b"current")
        assert await bb.cas("x", b"wrong", b"new") is False
        assert await bb.read("x") == b"current"


# ---------------------------------------------------------------------------
# 11. Privacy: noop
# ---------------------------------------------------------------------------


class TestNoopPrivacy:
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_passthrough(self) -> None:
        from nest_plugins_reference.privacy.noop import NoopPrivacy

        priv = NoopPrivacy()
        ct = await priv.encrypt(b"secret", [AgentId("a1")])
        assert ct == b"secret"
        pt = await priv.decrypt(ct)
        assert pt == b"secret"

    @pytest.mark.asyncio
    async def test_prove_verify(self) -> None:
        from nest_plugins_reference.privacy.noop import NoopPrivacy

        priv = NoopPrivacy()
        stmt = Statement(predicate="test")
        witness = Witness(private_inputs={"x": "1"})
        proof = await priv.prove(stmt, witness)
        assert await priv.verify_proof(stmt, proof) is True


# ---------------------------------------------------------------------------
# 12. DataFacts: datafacts_v1
# ---------------------------------------------------------------------------


class TestDataFactsV1:
    @pytest.mark.asyncio
    async def test_publish_fetch(self) -> None:
        from nest_plugins_reference.datafacts.datafacts_v1 import DataFactsV1

        df = DataFactsV1()
        meta = DatasetMetadata(name="weather", owner=AgentId("a1"))
        url = await df.publish(meta)
        assert url == "df://weather"

        fetched = await df.fetch(url)
        assert fetched.name == "weather"
        assert fetched.owner == AgentId("a1")

    @pytest.mark.asyncio
    async def test_request_access(self) -> None:
        from nest_plugins_reference.datafacts.datafacts_v1 import DataFactsV1

        df = DataFactsV1()
        meta = DatasetMetadata(name="data", owner=AgentId("a1"))
        url = await df.publish(meta)
        grant = await df.request_access(url, AgentId("a2"))
        assert grant.grantee == AgentId("a2")
        assert grant.tier == "read"

    @pytest.mark.asyncio
    async def test_verify_freshness(self) -> None:
        from nest_plugins_reference.datafacts.datafacts_v1 import DataFactsV1

        df = DataFactsV1()
        meta = DatasetMetadata(name="fresh", owner=AgentId("a1"))
        url = await df.publish(meta)
        assert await df.verify_freshness(url) is True

    @pytest.mark.asyncio
    async def test_fetch_missing(self) -> None:
        from nest_core.types import DataFactsUrl
        from nest_plugins_reference.datafacts.datafacts_v1 import DataFactsV1

        df = DataFactsV1()
        with pytest.raises(KeyError):
            await df.fetch(DataFactsUrl("df://missing"))
