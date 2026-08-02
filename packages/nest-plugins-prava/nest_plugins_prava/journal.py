# SPDX-License-Identifier: Apache-2.0
"""Durable-ish idempotency journal for PaymentRef → confirmed receipts.

In-process dict by default. Inject the same dict into a new PravaPayments
instance to simulate process restart recovery.

Example::

    journal: dict[str, dict] = {}
    pay = PravaPayments(AgentId("a"), journal=journal)
"""

from __future__ import annotations

from typing import Any

from nest_sdk import AgentId, Money, PaymentRef, PaymentStatus

from nest_plugins_prava.state import PaymentPhase, PaymentRecord


def record_to_journal_entry(record: PaymentRecord) -> dict[str, Any]:
    """Serialize a confirmed/refunded record for restart recovery."""
    return {
        "ref": str(record.ref),
        "payer": str(record.payer),
        "payee": str(record.payee),
        "amount": record.amount.amount,
        "currency": record.amount.currency,
        "status": record.status.value,
        "phase": record.phase.value,
        "session_id": record.session_id,
        "order_id": record.order_id,
        "txn_ref_id": record.txn_ref_id,
        "created_at": record.created_at,
    }


def journal_entry_to_record(entry: dict[str, Any]) -> PaymentRecord:
    """Deserialize a journal entry back into a PaymentRecord."""
    status = PaymentStatus(entry["status"])
    phase = PaymentPhase(entry.get("phase", status.value))
    return PaymentRecord(
        ref=PaymentRef(str(entry["ref"])),
        payer=AgentId(str(entry["payer"])),
        payee=AgentId(str(entry["payee"])),
        amount=Money(amount=int(entry["amount"]), currency=str(entry.get("currency", "credits"))),
        phase=phase,
        status=status,
        session_id=entry.get("session_id"),
        order_id=entry.get("order_id"),
        txn_ref_id=entry.get("txn_ref_id"),
        created_at=float(entry.get("created_at") or 0.0),
        locked_credits=0,
    )


def hydrate_from_journal(
    journal: dict[str, dict[str, Any]],
    records: dict[PaymentRef, PaymentRecord],
    payments: dict[PaymentRef, Any],
) -> None:
    """Load durable entries into the in-memory ledger sidecars."""
    for raw_ref, entry in journal.items():
        ref = PaymentRef(raw_ref)
        record = journal_entry_to_record(entry)
        records[ref] = record
        if record.status is PaymentStatus.CONFIRMED:
            payments[ref] = record.to_receipt()


def persist_record(journal: dict[str, dict[str, Any]] | None, record: PaymentRecord) -> None:
    """Persist terminal states that must survive restart."""
    if journal is None:
        return
    if record.status in {PaymentStatus.CONFIRMED, PaymentStatus.REFUNDED, PaymentStatus.FAILED}:
        journal[str(record.ref)] = record_to_journal_entry(record)
