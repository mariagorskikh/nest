# SPDX-License-Identifier: Apache-2.0
"""Wire encoding/decoding for the HotStuff BFT coordination protocol.

All HotStuff messages are colon-delimited UTF-8 text ending in a
``|sig:<hex>`` signature suffix, matching the convention already used by
``nest_core.scenarios_builtin.marketplace`` and read by
``nest_core.validators._message_body``. A Quorum Certificate (a set of
signed votes) is embedded inline using a ``;``/``,``/``=`` sub-grammar so it
nests inside the outer ``:``-delimited message without ambiguity.

Every ``decode_*`` function returns ``None`` on malformed input instead of
raising -- callers (the simulator's byzantine fault injection XOR-garbles
payload bytes) must never crash or miscount a vote when handed garbage.

Example::

    body = encode_vote("prepare", view=3, block_hash_hex=block_hash(3, "42"))
    msg = decode_vote(body.decode())
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

_PHASES = ("prepare", "commit")


@dataclass(frozen=True)
class VoteRecord:
    """A single signed vote inside a Quorum Certificate.

    Example::

        record = VoteRecord(voter="replica-0", signature_hex="a1b2")
    """

    voter: str
    signature_hex: str


@dataclass(frozen=True)
class QuorumCert:
    """A Quorum Certificate: >=2f+1 signed votes for one (phase, view, block).

    Example::

        qc = QuorumCert(phase="prepare", view=3, block_hash="abcd", votes=())
    """

    phase: str
    view: int
    block_hash: str
    votes: tuple[VoteRecord, ...]

    def encode_inline(self) -> str:
        """Encode this QC for embedding inside a PREPARE/NEW-VIEW message.

        Example::

            field = qc.encode_inline()
        """
        votes_str = ",".join(f"{v.voter}={v.signature_hex}" for v in self.votes)
        return f"{self.phase};{self.view};{self.block_hash};{votes_str}"


@dataclass(frozen=True)
class PrepareMessage:
    """A decoded PREPARE proposal.

    Example::

        msg = decode_prepare("prepare:3:abcd:42:none")
    """

    view: int
    block_hash: str
    value: str
    justify_qc: QuorumCert | None


@dataclass(frozen=True)
class VoteMessage:
    """A decoded VOTE.

    Example::

        msg = decode_vote("vote:prepare:3:abcd")
    """

    phase: str
    view: int
    block_hash: str


@dataclass(frozen=True)
class QcBroadcastMessage:
    """A decoded QC broadcast (leader announcing a formed quorum).

    Example::

        msg = decode_qc_broadcast("qc:prepare:3:abcd:2:r0=ab,r2=cd,r4=ef")
    """

    phase: str
    view: int
    block_hash: str
    f: int
    votes: tuple[VoteRecord, ...]


@dataclass(frozen=True)
class NewViewMessage:
    """A decoded NEW-VIEW (view-change) message.

    Example::

        msg = decode_new_view("new-view:4:none")
    """

    view: int
    highest_qc: QuorumCert | None


def block_hash(view: int, value: str) -> str:
    """Deterministic block identity for a (view, value) pair.

    Example::

        h = block_hash(3, "42")
    """
    return hashlib.sha256(f"{view}:{value}".encode()).hexdigest()


def with_signature(body: bytes, signature_hex: str) -> bytes:
    """Append the ``|sig:<hex>`` suffix used by every HotStuff wire message.

    Example::

        wire_bytes = with_signature(b"vote:prepare:3:abcd", "a1b2")
    """
    return body + f"|sig:{signature_hex}".encode()


def split_signature(text: str) -> tuple[str, bytes | None]:
    """Split ``body|sig:<hex>`` into the signed body and decoded signature.

    Returns ``(text, None)`` when the suffix is missing or not valid hex --
    callers must treat a ``None`` signature as unverifiable.

    Example::

        body, sig_bytes = split_signature("vote:prepare:3:abcd|sig:a1b2")
    """
    body, sep, sig_hex = text.rpartition("|sig:")
    if not sep:
        return text, None
    try:
        return body, bytes.fromhex(sig_hex)
    except ValueError:
        return body, None


def _decode_votes(votes_str: str) -> tuple[VoteRecord, ...] | None:
    if not votes_str:
        return ()
    records: list[VoteRecord] = []
    for entry in votes_str.split(","):
        voter, sep, sig_hex = entry.partition("=")
        if not sep or not voter or not sig_hex:
            return None
        records.append(VoteRecord(voter=voter, signature_hex=sig_hex))
    return tuple(records)


def decode_inline_qc(field: str) -> QuorumCert | None:
    """Decode the ``phase;view;block_hash;voter=sig,...`` inline QC grammar.

    Example::

        qc = decode_inline_qc("prepare;3;abcd;r0=ab,r2=cd")
    """
    parts = field.split(";", 3)
    if len(parts) != 4:
        return None
    phase, view_str, block_hash_hex, votes_str = parts
    if phase not in _PHASES:
        return None
    try:
        view = int(view_str)
    except ValueError:
        return None
    votes = _decode_votes(votes_str)
    if votes is None:
        return None
    return QuorumCert(phase=phase, view=view, block_hash=block_hash_hex, votes=votes)


def encode_prepare(view: int, value: str, justify_qc: QuorumCert | None) -> bytes:
    """Encode a PREPARE proposal body (without the trailing signature).

    Example::

        body = encode_prepare(3, "42", None)
    """
    h = block_hash(view, value)
    qc_field = justify_qc.encode_inline() if justify_qc is not None else "none"
    return f"prepare:{view}:{h}:{value}:{qc_field}".encode()


def decode_prepare(body: str) -> PrepareMessage | None:
    """Decode a PREPARE message body (text after stripping ``|sig:``).

    Example::

        msg = decode_prepare("prepare:3:abcd:42:none")
    """
    parts = body.split(":", 4)
    if len(parts) != 5 or parts[0] != "prepare":
        return None
    try:
        view = int(parts[1])
    except ValueError:
        return None
    block_hash_hex, value, qc_field = parts[2], parts[3], parts[4]
    justify_qc: QuorumCert | None = None
    if qc_field != "none":
        justify_qc = decode_inline_qc(qc_field)
        if justify_qc is None:
            return None
    return PrepareMessage(view=view, block_hash=block_hash_hex, value=value, justify_qc=justify_qc)


def encode_vote(phase: str, view: int, block_hash_hex: str) -> bytes:
    """Encode a VOTE message body -- also the exact payload a voter signs.

    Example::

        body = encode_vote("prepare", 3, "abcd")
    """
    return f"vote:{phase}:{view}:{block_hash_hex}".encode()


def decode_vote(body: str) -> VoteMessage | None:
    """Decode a VOTE message body.

    Example::

        msg = decode_vote("vote:prepare:3:abcd")
    """
    parts = body.split(":")
    if len(parts) != 4 or parts[0] != "vote":
        return None
    phase = parts[1]
    if phase not in _PHASES:
        return None
    try:
        view = int(parts[2])
    except ValueError:
        return None
    return VoteMessage(phase=phase, view=view, block_hash=parts[3])


def encode_qc_broadcast(
    phase: str, view: int, block_hash_hex: str, f: int, votes: Sequence[VoteRecord]
) -> bytes:
    """Encode a QC broadcast body (leader -> all replicas), no trailing signature.

    Example::

        body = encode_qc_broadcast("prepare", 3, "abcd", 2, [])
    """
    votes_str = ",".join(f"{v.voter}={v.signature_hex}" for v in votes)
    return f"qc:{phase}:{view}:{block_hash_hex}:{f}:{votes_str}".encode()


def decode_qc_broadcast(body: str) -> QcBroadcastMessage | None:
    """Decode a QC broadcast message body.

    Example::

        msg = decode_qc_broadcast("qc:prepare:3:abcd:2:r0=ab,r2=cd,r4=ef")
    """
    parts = body.split(":", 5)
    if len(parts) != 6 or parts[0] != "qc":
        return None
    phase = parts[1]
    if phase not in _PHASES:
        return None
    try:
        view = int(parts[2])
        f_value = int(parts[4])
    except ValueError:
        return None
    votes = _decode_votes(parts[5])
    if votes is None:
        return None
    return QcBroadcastMessage(phase=phase, view=view, block_hash=parts[3], f=f_value, votes=votes)


def encode_new_view(view: int, highest_qc: QuorumCert | None) -> bytes:
    """Encode a NEW-VIEW (view-change) body, without the trailing signature.

    Example::

        body = encode_new_view(4, None)
    """
    qc_field = highest_qc.encode_inline() if highest_qc is not None else "none"
    return f"new-view:{view}:{qc_field}".encode()


def decode_new_view(body: str) -> NewViewMessage | None:
    """Decode a NEW-VIEW message body.

    Example::

        msg = decode_new_view("new-view:4:none")
    """
    parts = body.split(":", 2)
    if len(parts) != 3 or parts[0] != "new-view":
        return None
    try:
        view = int(parts[1])
    except ValueError:
        return None
    qc_field = parts[2]
    highest_qc: QuorumCert | None = None
    if qc_field != "none":
        highest_qc = decode_inline_qc(qc_field)
        if highest_qc is None:
            return None
    return NewViewMessage(view=view, highest_qc=highest_qc)


def encode_result(view: int, block_hash_hex: str, accepts: int, total: int, value: str) -> bytes:
    """Encode the trace/metrics-friendly commit summary line.

    ``block_hash_hex`` -- not ``value`` -- is the safety-critical field: it
    comes straight from the commit QC, so every honest replica reports the
    same hash for a given view regardless of whether it happens to know the
    plaintext ``value`` locally (e.g. a replica that only saw the commit QC,
    not the original PREPARE, after being partitioned away).

    Example::

        body = encode_result(3, "abcd", 5, 7, "42")
    """
    return f"result:{view}:committed:{accepts}/{total}:{block_hash_hex}:{value}".encode()
