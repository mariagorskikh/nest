# SPDX-License-Identifier: Apache-2.0
"""Pre-action permit gate: every request yields a signed, chained envelope.

``AAEPermitGate`` is a trust-layer plugin that decides *before* an action runs
whether the acting agent may proceed, and signs a permit envelope
(:mod:`nest_plugins_reference.trust.aae_envelope`) for **every** evaluation —
authorized, denied, and conditional alike. A denial is a first-class signed
receipt: "we refused this request at this point in the history" is later
provable from the envelope chain alone.

Policy model: the gate is **deny-by-default** — with no matching entry the
outcome is ``default_effect`` (``"denied"`` unless overridden). That is the
honest posture: an unlisted action was never decided, and silence must not
read as consent. Entries are evaluated in declaration order, first match
wins. Each names a subject (``"agent"``: fnmatch pattern, or ``"role"``:
exact role name looked up in ``roles``), a ``"verb"`` pattern, a
``"resource"`` pattern, and an ``"effect"``. Matching is case-sensitive
(``fnmatch.fnmatchcase``) so results never vary by platform.

``"conditional"`` is **not** permission: it means "authorized subject to the
caller honoring the stated condition params". :func:`permits` returns ``True``
only for ``"authorized"``.

Trace-line protocol
-------------------

Scenarios emit one line per evaluation, derived from the returned envelope::

    permit:<agent>:<verb>:<resource>:<outcome>:<envelope_hash_prefix8>

where ``envelope_hash_prefix8`` is the first 8 hex characters of
``envelope_hash(envelope)``. Because envelopes are byte-deterministic, these
lines are stable across replays of the same scenario.

Determinism: no wall clock (``now`` is caller-supplied), no unseeded
randomness (the signing key comes from ``signing_key`` or is derived from
``key_seed``), and all reported numbers are rounded to 6 decimals.

Example::

    gate = AAEPermitGate(policy=[{"agent": "a*", "verb": "read", "resource": "*",
                                  "effect": "authorized"}], key_seed=b"demo")
    env = await gate.evaluate(AgentId("a1"), "read", "doc/1", {},
                              now="2026-01-01T00:00:00+00:00")
    assert permits(env)
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib
import logging
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nest_core.types import AgentId, Attestation, Claim, Evidence, ReputationScore, Signature

from nest_plugins_reference.trust.aae_envelope import (
    OUTCOMES,
    Envelope,
    envelope_hash,
    issue_envelope,
    order_chain,
    verify_envelope,
)

logger = logging.getLogger(__name__)

_RULE_KEYS = frozenset({"agent", "role", "verb", "resource", "effect"})

# (kind, subject, verb, resource, effect) — kind is "agent" or "role".
_Rule = tuple[str, str, str, str, str]


def permits(envelope: Envelope) -> bool:
    """Return whether *envelope* grants unconditional permission to act.

    ``True`` only for a **valid** envelope whose outcome is ``"authorized"``.
    ``"conditional"`` is not permission (the caller still owes the condition
    params); ``"denied"`` and anything malformed or tampered are ``False``.

    Example::

        if permits(env):
            ...  # dispatch the action
    """
    return verify_envelope(envelope) and envelope["outcome"] == "authorized"


def _validate_rule(index: int, rule: object) -> _Rule:
    """Validate one policy entry, returning its normalized tuple form."""
    if not isinstance(rule, dict):
        msg = f"policy[{index}] must be a dict, got {type(rule).__name__}"
        raise ValueError(msg)
    entry = cast("dict[str, Any]", rule)
    if unknown := set(entry) - _RULE_KEYS:
        msg = f"policy[{index}] has unknown keys {sorted(unknown)}"
        raise ValueError(msg)
    subjects = [k for k in ("agent", "role") if k in entry]
    if len(subjects) != 1:
        msg = f"policy[{index}] must name exactly one of 'agent' or 'role'"
        raise ValueError(msg)
    kind = subjects[0]
    for key in (kind, "verb", "resource", "effect"):
        if not isinstance(entry.get(key), str):
            msg = f"policy[{index}][{key!r}] must be a string"
            raise ValueError(msg)
    if entry["effect"] not in OUTCOMES:
        msg = f"policy[{index}]['effect'] must be one of {sorted(OUTCOMES)}"
        raise ValueError(msg)
    return (kind, entry[kind], entry["verb"], entry["resource"], entry["effect"])


def _validate_policy(policy: object) -> list[_Rule]:
    """Validate the whole ``policy`` constructor argument."""
    if policy is None:
        return []
    if not isinstance(policy, list):
        msg = "policy must be a list of rule dicts"
        raise ValueError(msg)
    return [_validate_rule(i, r) for i, r in enumerate(cast("list[object]", policy))]


def _validate_roles(roles: object) -> dict[str, str]:
    """Validate the ``roles`` constructor argument."""
    if roles is None:
        return {}
    if not isinstance(roles, dict) or any(
        not isinstance(k, str) or not isinstance(v, str)
        for k, v in cast("dict[object, object]", roles).items()
    ):
        msg = "roles must map agent_id strings to role-name strings"
        raise ValueError(msg)
    return dict(cast("dict[str, str]", roles))


class AAEPermitGate:
    """Deny-by-default permit gate implementing the ``Trust`` Protocol.

    Constructor: ``policy`` (ordered rule dicts, module docstring), ``roles``
    (``agent_id -> role`` for ``"role"`` entries), ``default_effect``
    (outcome when nothing matches), ``signing_key`` (hex 32-byte Ed25519
    private key) **or** ``key_seed`` (bytes; the key is its SHA-256, so runs
    are reproducible — for determinism the gate never invents a key, and
    omitting both raises ``ValueError``), and ``anchor`` / ``ledger`` for
    opt-in capsule anchoring (:meth:`_anchor_envelope`).

    Example::

        gate = AAEPermitGate(policy=[], key_seed=b"seed")
        env = await gate.evaluate(AgentId("a1"), "write", "db", {},
                                  now="2026-01-01T00:00:00+00:00")
        assert env["outcome"] == "denied"
    """

    _SYSTEM_AGENT = AgentId("trust:aae_permit_gate")

    def __init__(
        self,
        policy: list[dict[str, Any]] | None = None,
        roles: dict[str, str] | None = None,
        default_effect: str = "denied",
        signing_key: str | None = None,
        key_seed: bytes | None = None,
        anchor: bool = False,
        ledger: str = "capsule_ledger.jsonl",
    ) -> None:
        if default_effect not in OUTCOMES:
            msg = f"default_effect must be one of {sorted(OUTCOMES)}, got {default_effect!r}"
            raise ValueError(msg)
        self._rules: list[_Rule] = _validate_policy(policy)
        self._roles: dict[str, str] = _validate_roles(roles)
        self._default_effect = default_effect
        if signing_key is not None:
            try:
                key_ok = len(bytes.fromhex(signing_key)) == 32
            except ValueError:
                key_ok = False
            if not key_ok:
                msg = "signing_key must be the hex of a 32-byte Ed25519 private key"
                raise ValueError(msg)
            self._signing_key = signing_key
        elif key_seed is not None:
            self._signing_key = hashlib.sha256(key_seed).hexdigest()
        else:
            msg = "supply signing_key (hex) or key_seed (bytes); the gate never invents a key"
            raise ValueError(msg)
        self._anchor = anchor
        self._ledger = ledger
        self._anchor_unavailable_logged = False
        self._chains: dict[str, list[Envelope]] = {}
        self._capsule_ids: dict[str, str] = {}  # envelope_hash -> capsule_id
        self._evidence_log: dict[str, list[Evidence]] = {}
        self._stakes: dict[str, int] = {}

    def _match(self, agent: str, verb: str, resource: str) -> tuple[str, str]:
        """First-match-wins policy lookup; returns ``(outcome, policy_id)``."""
        for i, (kind, subject, verb_pat, res_pat, effect) in enumerate(self._rules):
            if kind == "agent":
                if not fnmatch.fnmatchcase(agent, subject):
                    continue
            elif self._roles.get(agent) != subject:
                continue
            if fnmatch.fnmatchcase(verb, verb_pat) and fnmatch.fnmatchcase(resource, res_pat):
                return effect, f"rule:{i}"
        return self._default_effect, "default"

    async def evaluate(
        self, agent: AgentId, verb: str, resource: str, params: dict[str, Any], *, now: str
    ) -> dict[str, Any]:
        """Decide a proposed action and return its signed permit envelope.

        Every call — grant or refusal — extends the agent's envelope chain
        (``prev_hash`` links to the previous evaluation for the same agent).
        ``now`` is the scenario's virtual clock (RFC 3339); the gate never
        reads a wall clock. For ``"conditional"`` outcomes, ``params`` in the
        envelope are the condition params the caller must honor.

        Example::

            env = await gate.evaluate(AgentId("a1"), "read", "doc/1", {},
                                      now="2026-01-01T00:00:00+00:00")
        """
        outcome, policy_id = self._match(str(agent), verb, resource)
        chain = self._chains.setdefault(str(agent), [])
        env = issue_envelope(
            self._signing_key,
            agent_id=str(agent),
            verb=verb,
            resource=resource,
            params=params,
            policy_id=policy_id,
            outcome=outcome,
            prev_hash=envelope_hash(chain[-1]) if chain else None,
            issued_at=now,
        )
        chain.append(env)
        self._anchor_envelope(env)
        return env

    def chain(self, agent: AgentId | str) -> list[Envelope]:
        """Return the agent's envelopes in issue order (a copy).

        Example::

            history = gate.chain(AgentId("a1"))
        """
        return list(self._chains.get(str(agent), []))

    def verify_chain(self, agent: AgentId | str) -> bool:
        """Return whether the agent's stored history is one intact, valid chain.

        Example::

            assert gate.verify_chain(AgentId("a1"))
        """
        return order_chain(self._chains.get(str(agent), [])) is not None

    def _anchor_envelope(self, env: Envelope) -> None:
        """Optionally seal a permit envelope into a capsule ledger.

        Only active with ``anchor=True`` **and** the optional ``capsule_emit``
        package importable; otherwise a one-time debug log and a no-op (zero
        hard dependency). An anchored permit is evidence a **decision was
        made, not evidence the action ran** — so the capsule's ``action`` is a
        permit-namespaced token (``permit.granted`` / ``permit.denied`` /
        ``permit.conditional``), never the underlying verb (which stays inside
        the envelope, i.e. the capsule's input), and the output carries only
        the decision. ``capsule_emit.emit`` has no external-reference field
        for the *current* capsule (its ``confirms=`` names a parent capsule id
        and belongs on a later execution capsule), so the ``envelope_hash`` in
        the output object is the correlation handle; the returned capsule id
        is kept per envelope hash so a future execution capsule can chain to
        this permit via ``confirms=``.
        """
        if not self._anchor:
            return
        try:
            capsule_emit = importlib.import_module("capsule_emit")
        except ImportError:
            if not self._anchor_unavailable_logged:
                logger.debug("anchor=True but capsule_emit is not installed; anchoring disabled")
                self._anchor_unavailable_logged = True
            return
        digest = envelope_hash(env)
        outcome = str(env["outcome"])
        token = {"authorized": "permit.granted", "denied": "permit.denied"}.get(
            outcome, "permit.conditional"
        )
        result = capsule_emit.emit(
            action=token,
            operator=str(env["agent_id"]),
            developer=str(self._SYSTEM_AGENT),
            agent_input=env,
            agent_output={
                "decision": outcome,
                "policy_id": env["policy_id"],
                "envelope_hash": digest,
            },
            anchor=True,
            ledger=self._ledger,
        )
        self._capsule_ids[digest] = str(result.capsule_id)

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation as the agent's authorization rate at this gate.

        ``score`` = authorized evaluations / total evaluations (0.0 with no
        history — deny-by-default extends to reputation), ``confidence`` =
        ``min(1.0, total / 10)``, ``sample_count`` = total. Both floats are
        rounded to 6 decimals so traces are byte-stable across platforms.

        Example::

            rep = await gate.score(AgentId("a1"))
        """
        history = self._chains.get(str(agent), [])
        total = len(history)
        if total == 0:
            return ReputationScore(agent_id=agent, score=0.0, confidence=0.0, sample_count=0)
        granted = sum(1 for e in history if e["outcome"] == "authorized")
        return ReputationScore(
            agent_id=agent,
            score=round(granted / total, 6),
            confidence=round(min(1.0, total / 10), 6),
            sample_count=total,
        )

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Sign *claim* with the gate's own Ed25519 key.

        The signature covers ``claim.model_dump_json()`` — the same key that
        signs permit envelopes, so one public key verifies both.

        Example::

            att = await gate.attest(AgentId("a1"), claim)
        """
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self._signing_key))
        sig = Signature(
            signer=self._SYSTEM_AGENT,
            value=key.sign(claim.model_dump_json().encode()),
            algorithm="ed25519",
        )
        return Attestation(issuer=self._SYSTEM_AGENT, claim=claim, signature=sig)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Record evidence about an agent (storage only, by design).

        The evidence log is kept so future policy revisions MAY consult it;
        today it does **not** alter matching, scores, or envelopes — no
        pretend enforcement.

        Example::

            await gate.report(AgentId("a1"), evidence)
        """
        self._evidence_log.setdefault(str(agent), []).append(evidence)

    async def stake(self, agent: AgentId, amount: int) -> None:
        """Stake on an agent (Protocol-parity no-op; amount recorded only).

        Example::

            await gate.stake(AgentId("a1"), 100)
        """
        self._stakes[str(agent)] = self._stakes.get(str(agent), 0) + amount
