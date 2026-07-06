# SPDX-License-Identifier: Apache-2.0
"""Iteration-5 (outcome_verified_settlement_b5) property + integration tests.

Two checks beyond the per-tick unit tests of earlier buckets:

* a Hypothesis **property** that pins the invariant ``billed <= rate *
  verified_ticks`` directly against its enforcer,
  ``validate_outcome_verified_settlement_no_overbill_on_failed_verification``:
  over random ``(rate, verdict-sequence, overbill)`` triples the validator passes
  *iff* the closed stream drained no more than ``rate * (#pass verdicts)`` -- i.e.
  it never false-positives on a correctly-billed stream and always catches an
  over-bill;
* an **integration** check that a content-gated trace runs through exactly the
  three registered validators and all pass.

Traces are built in the colon-delimited grammar the driver emits (``stream-open``
/ ``tick`` / ``ack`` / ``gate`` / ``stream-close``); no mocks, no driver patching
-- the real validators read real trace events.
"""

from __future__ import annotations

import hashlib
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from nest_core.validators import (
    validate_events,
    validate_outcome_verified_settlement_no_overbill_on_failed_verification,
)

type Event = dict[str, Any]


def _send(agent: str, to: str, msg: str, ts: float = 1.0) -> Event:
    """Build a send event in the trace's event-dict shape."""
    return {"ts": ts, "agent": agent, "kind": "send", "to": to, "msg": msg}


def _recv(agent: str, frm: str, msg: str, ts: float = 1.0) -> Event:
    """Build a receive event (delivered ack) in the trace's event-dict shape."""
    return {"ts": ts, "agent": agent, "kind": "receive", "from": frm, "msg": msg}


def _gated_trace(
    rate: int,
    verdicts: list[bool],
    drained: int,
    *,
    ref: str = "buyer-0-stream",
) -> list[Event]:
    """A closed content-gated stream emitting one ``gate:`` verdict per delivered tick.

    Each entry in *verdicts* is one delivered unit (``True`` = pass, ``False`` =
    fail); every unit is delivered with an HONEST checksum (real sha256 of a real
    chunk, matching the driver's actual content-gate grammar -- not a placeholder
    hex pair) and carries a ``gate:`` verdict. *drained* is written verbatim into
    the ``stream-close`` line so a caller can inject an over-bill independent of
    the pass count. The close tick equals the unit count, so no tick is timed
    after close (keeps ``no_drain_after_close`` satisfied). Honest checksums mean
    this fixture also passes ``verdicts_match_committed_criterion`` when run
    through the full registry, as a real trace would.
    """
    events: list[Event] = [
        _send("buyer-0", "seller-0", f"stream-open:{ref}:buyer-0:seller-0:{rate}:20:0"),
    ]
    for seq, verdict in enumerate(verdicts):
        now = seq + 1
        events.append(_send("buyer-0", "seller-0", f"tick:{ref}:{seq}:{rate}:{now}", ts=now))
        chunk = f"{ref}#{seq}".encode()
        declared = hashlib.sha256(chunk).hexdigest()
        events.append(
            _recv("buyer-0", "seller-0", f"ack:{ref}:{seq}:{chunk.hex()}:{declared}", ts=now)
        )
        outcome = "pass" if verdict else "fail"
        events.append(_send("buyer-0", "seller-0", f"gate:{ref}:{seq}:{outcome}", ts=now))
    n = len(verdicts)
    events.append(
        _send("buyer-0", "seller-0", f"stream-close:{ref}:{n}:{drained}:{n}:degrade", ts=n)
    )
    return events


@settings(max_examples=200, deadline=None)
@given(
    rate=st.integers(min_value=1, max_value=5),
    verdicts=st.lists(st.booleans(), min_size=1, max_size=20),
    overbill=st.integers(min_value=0, max_value=10),
)
def test_outcome_verified_settlement_b5_property_billed_le_rate_x_verified(
    rate: int,
    verdicts: list[bool],
    overbill: int,
) -> None:
    """Validator passes iff drained <= rate * (#pass verdicts), over random sequences.

    ``overbill == 0`` means the stream billed exactly its verified prefix (correct,
    must PASS); ``overbill > 0`` means it billed past the pass verdicts (the
    ``bill_regardless`` over-bill, must FAIL). The biconditional holds for every
    generated ``(rate, verdict-sequence, overbill)``.
    """
    pass_count = sum(verdicts)
    drained = rate * pass_count + overbill
    events = _gated_trace(rate, verdicts, drained)
    results = validate_outcome_verified_settlement_no_overbill_on_failed_verification(events)
    assert len(results) == 1
    assert results[0].passed == (overbill == 0)


def test_outcome_verified_settlement_b5_three_validators_run() -> None:
    """A content-gated degrade trace runs exactly the four validators, all PASS."""
    # 2 pass + 1 fail, drained == 2 == rate * passes: a correctly-degrading stream.
    events = _gated_trace(rate=1, verdicts=[True, True, False], drained=2)
    results = validate_events(events, "outcome_verified_settlement")
    assert len(results) == 4
    assert all(r.passed for r in results), [(r.name, r.detail) for r in results if not r.passed]
