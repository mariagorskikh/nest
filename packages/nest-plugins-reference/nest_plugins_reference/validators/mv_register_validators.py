# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for the multi-value register (MV-Register) plugin.

The failure mode this targets is **silent loss of a concurrent write**. When
two replicas write different payloads to the same key without having seen each
other, both writes are live data. A register that resolves the conflict by
picking one winner -- the ``lww_register`` plugin, by design -- discards the
other with no error. ``validate_mv_no_concurrent_loss`` reproduces exactly that
race and asserts every concurrently-written value survives on every replica
after gossip.

By construction:

* against the **mv_register** plugin, all ``N`` concurrent writes are kept as
  siblings on every replica, so the check passes;
* against the **lww_register** plugin, each replica collapses the ``N`` writes
  to a single winner, so ``N - 1`` values are lost and the check fails -- the
  validator literally cannot be satisfied by the last-writer-wins register,
  which is the charter's bar for "adversarial".

The check is capability-based, mirroring
:func:`nest_core.validators.validate_crdt_convergence`: gossip is delivered
through ``export`` / ``merge`` when the plugin is a CvRDT, and the surviving
values are read through ``values`` when the plugin exposes the multi-value
surface, falling back to the single ``read`` otherwise. That fallback is what
makes ``lww_register`` fail honestly rather than erroring.

Example::

    from nest_plugins_reference.memory.mv_register import MvRegisterMemory
    report = await validate_mv_no_concurrent_loss(
        MvRegisterMemory, [b"from-a", b"from-b", b"from-c"]
    )
    assert report.passed, report.detail
"""

from __future__ import annotations

from typing import Any

from nest_plugins_reference.validators.gossip_validators import ValidatorReport


class ConcurrentWriteLossError(AssertionError):
    """Raised when a concurrently-written value is lost after gossip.

    Example::

        raise ConcurrentWriteLossError("replica node-0 kept 1 of 3 writes")
    """


async def _surviving_values(replica: Any, key: str) -> list[bytes]:  # noqa: ANN401
    """Return the values a replica holds for ``key``, multi-value aware.

    Uses the plugin's ``values`` method when present (the MV-Register surface),
    otherwise falls back to the single ``read`` -- so a last-writer-wins
    register reports the one value it kept, exposing the loss instead of hiding
    behind a missing method.

    Example::

        kept = await _surviving_values(mem, "k")
    """
    if hasattr(replica, "values"):
        return list(await replica.values(key))
    single = await replica.read(key)
    return [] if single is None else [single]


async def validate_mv_no_concurrent_loss(
    make_replica: Any,  # noqa: ANN401
    values: list[bytes],
    *,
    key: str = "k",
) -> ValidatorReport:
    """Assert no concurrent write is lost after all-to-all gossip.

    Drives ``len(values)`` replicas through one concurrent write each (every
    replica writes before it has merged anyone else, so the writes are pairwise
    concurrent), gossips every replica's state to every other, then checks that
    each replica ends up holding **all** of the written values.

    Args:
        make_replica: factory ``node_id -> plugin instance``.
        values: one distinct payload per replica, all written to ``key``.
        key: the shared key every replica writes.

    Returns ``passed=True`` iff every replica's surviving value set equals the
    full set of written values; otherwise ``passed=False`` with
    ``evidence["lost"]`` naming the dropped payloads per replica.

    Example::

        report = await validate_mv_no_concurrent_loss(MvRegisterMemory, [b"a", b"b"])
        assert report.passed, report.detail
    """
    if len(values) < 2:
        msg = "need at least two concurrent writes to test for loss"
        raise ValueError(msg)
    if len(set(values)) != len(values):
        msg = "values must be distinct so a lost write is detectable"
        raise ValueError(msg)

    replica_count = len(values)
    replicas = [make_replica(f"node-{i}") for i in range(replica_count)]
    has_crdt = all(hasattr(r, "export") and hasattr(r, "merge") for r in replicas)

    # Phase 1: each replica writes its own value with no prior merge -- concurrent.
    gossip: list[bytes] = []
    for idx, payload in enumerate(values):
        await replicas[idx].write(key, payload)
        if has_crdt:
            state = replicas[idx].export(key)
            gossip.append(state if state is not None else payload)
        else:
            gossip.append(payload)

    # Phase 2: all-to-all gossip. One round suffices for a state-based CRDT, but
    # a second round costs nothing and proves the merge is idempotent under it.
    for _round in range(2):
        for r_idx in range(replica_count):
            for w_idx in range(replica_count):
                if w_idx == r_idx:
                    continue
                if has_crdt:
                    await replicas[r_idx].merge(key, gossip[w_idx])
                else:
                    await replicas[r_idx].write(key, gossip[w_idx])

    expected = set(values)
    lost: dict[str, list[str]] = {}
    for idx in range(replica_count):
        kept = set(await _surviving_values(replicas[idx], key))
        missing = expected - kept
        if missing:
            lost[f"node-{idx}"] = sorted(repr(v) for v in missing)

    if lost:
        dropped = sorted({v for vals in lost.values() for v in vals})
        return ValidatorReport(
            passed=False,
            detail=(
                f"{len(lost)} of {replica_count} replicas lost concurrent writes; "
                f"dropped values: {', '.join(dropped)}"
            ),
            evidence={"lost": lost},
        )
    return ValidatorReport(
        passed=True,
        detail=(
            f"all {replica_count} replicas kept all {replica_count} concurrent writes as siblings"
        ),
    )
