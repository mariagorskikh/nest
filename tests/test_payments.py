from copy import deepcopy

import pytest

from nandatown.layers.payments import Ledger, PaymentError


class IntSubclass(int):
    pass


class RecordingEngine:
    def __init__(self):
        self.events = []

    def emit(self, observer, kind, subject, detail=None):
        self.events.append(
            {
                "observer": observer,
                "kind": kind,
                "subject": subject,
                "detail": detail or {},
            }
        )


@pytest.fixture()
def ledger():
    engine = RecordingEngine()
    return Ledger(engine), engine


INVALID_CENTS = [True, False, 1.0, 1.5, "1", IntSubclass(1)]


@pytest.mark.parametrize("name", ["new-account", "existing-account"])
@pytest.mark.parametrize("cents", [*INVALID_CENTS, -1])
def test_open_account_rejects_invalid_cents_without_mutation(ledger, name, cents):
    pay, engine = ledger
    pay.open_account("existing-account", 100)
    before = (deepcopy(pay.balances), deepcopy(pay.escrow), deepcopy(engine.events))

    with pytest.raises(PaymentError):
        pay.open_account(name, cents)

    assert (pay.balances, pay.escrow, engine.events) == before


def test_open_account_accepts_zero_and_remains_idempotent(ledger):
    pay, engine = ledger

    pay.open_account("buyer", 0)
    pay.open_account("buyer", 100)

    assert pay.balance("buyer") == 0
    assert [event["kind"] for event in engine.events] == ["account_opened"]


@pytest.mark.parametrize("cents", [*INVALID_CENTS, 0, -1])
def test_transfer_rejects_invalid_cents_without_mutation(ledger, cents):
    pay, engine = ledger
    pay.open_account("buyer", 100)
    pay.open_account("seller", 25)
    before = (deepcopy(pay.balances), deepcopy(pay.escrow), deepcopy(engine.events))

    with pytest.raises(PaymentError):
        pay.transfer("buyer", "seller", cents, memo="order-1")

    assert (pay.balances, pay.escrow, engine.events) == before


@pytest.mark.parametrize("cents", [*INVALID_CENTS, 0, -1])
def test_hold_rejects_invalid_cents_without_mutation(ledger, cents):
    pay, engine = ledger
    pay.open_account("buyer", 100)
    before = (deepcopy(pay.balances), deepcopy(pay.escrow), deepcopy(engine.events))

    with pytest.raises(PaymentError):
        pay.hold("buyer", cents, ref="order-1")

    assert (pay.balances, pay.escrow, engine.events) == before
