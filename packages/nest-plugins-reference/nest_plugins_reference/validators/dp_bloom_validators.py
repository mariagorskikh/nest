# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for the ``dp_bloom`` registry.

The attack the default ``in_memory`` registry allows is membership inference. An
adversary reads the registry's observable membership surface and decides, for a
target agent, whether that agent registered. Against a plain registry the task is
a lookup rather than an attack. The observable surface is the member set, so the
adversary is always right. Bounding that leak is what ``dp_bloom`` is built for.
The framing follows the adversarial Bloom filter literature cited in
:mod:`nest_plugins_reference.registry.dp_bloom`.

The game

For a fixed target agent the validator compares two neighboring worlds. In the
present world the registry holds a background set and the target. In the absent
world the registry holds only the background set. An oracle plays one world under
one seed and returns the single bit the adversary observes, namely whether the
target looks registered. Sweeping the seed bank estimates
``p1 = Pr[reported present | present]`` and ``p0 = Pr[reported present | absent]``.
The adversary's distinguishing power is the larger log-likelihood ratio across
the two possible reports, which is an empirical epsilon.

    ``eps_hat = max( |ln(p1/p0)|, |ln((1-p1)/(1-p0))| )``

The membership query reads only an epsilon-DP published index, so by the
post-processing property of differential privacy the query is itself epsilon-DP.
A correctly calibrated ``dp_bloom`` therefore yields ``eps_hat`` at or below its
claimed budget, allowing for finite-sample slack. A registry that answers
membership exactly yields ``p1 = 1`` and ``p0 = 0`` and an unbounded ``eps_hat``.
The exact registry cannot satisfy any finite budget, which is the charter's bar
for an adversarial validator that the reference plugin must fail.

The validator Jeffreys-smooths the probabilities by adding ``0.5`` to each count,
so a deterministic leaker maps to a large but finite ``eps_hat`` rather than a raw
division by zero, and the report stays a clean numeric comparison.

Example::

    report = check_membership_inference_bounded(oracle, claimed_epsilon=3.0)
    assert report.passed, report.detail
"""

from __future__ import annotations

import math
from collections.abc import Callable

from nest_plugins_reference.validators.gossip_validators import ValidatorReport

MembershipOracle = Callable[[int, bool], bool]
"""Plays the game under one seed. ``oracle(seed, include_target)`` builds the
registry with the background set, adds the target when ``include_target`` is true,
seeds the mechanism with ``seed``, and returns the membership bit an adversary
observes for the target."""

_DEFAULT_SEEDS = 400
"""Seed-bank size. The bank is large enough to estimate
``p0 = Pr[present | absent]``, which is roughly ``p**k``, from several hits, and
small enough that the validator runs in well under a second on the tiny filters
scenarios use."""

_DEFAULT_SLACK = 1.0
"""Additive tolerance on the epsilon bound. The slack absorbs finite-sample
variance and Jeffreys-smoothing bias. A calibrated ``dp_bloom`` sits near the
budget while an exact registry sits in the 6 to 7 range for this bank, so the
slack separates the two comfortably."""


def _smoothed(hits: int, total: int) -> float:
    """Jeffreys-smoothed probability of the observed outcome."""
    return (hits + 0.5) / (total + 1.0)


def empirical_epsilon(hits_present: int, n_present: int, hits_absent: int, n_absent: int) -> float:
    """Return the empirical epsilon of a membership-inference game's counts.

    ``hits_present`` and ``hits_absent`` count the seeds under which the adversary
    saw a reported-present outcome. ``n_present`` and ``n_absent`` are the seed
    totals for each world.

    Example::

        eps = empirical_epsilon(hits_present=200, n_present=400, hits_absent=8, n_absent=400)
        assert eps > 0
    """
    p1 = _smoothed(hits_present, n_present)
    p0 = _smoothed(hits_absent, n_absent)
    ratio_present = abs(math.log(p1) - math.log(p0))
    ratio_absent = abs(math.log(1.0 - p1) - math.log(1.0 - p0))
    return max(ratio_present, ratio_absent)


def check_membership_inference_bounded(
    oracle: MembershipOracle,
    claimed_epsilon: float,
    *,
    num_seeds: int = _DEFAULT_SEEDS,
    slack: float = _DEFAULT_SLACK,
) -> ValidatorReport:
    """Assert a registry's membership surface leaks no more than ``claimed_epsilon``.

    The check runs the two-world game over seeds ``0`` to ``num_seeds - 1``. The
    sweep is deterministic, so the report replays byte-identically. The check
    passes when the empirical epsilon is within ``claimed_epsilon + slack``.

    A ``dp_bloom`` calibrated to ``claimed_epsilon`` holds the bound because the
    membership query is post-processing of an epsilon-DP index, so it passes. The
    exact ``in_memory`` registry reports the target present exactly when it is
    registered, which gives an unbounded empirical epsilon, so it fails. The exact
    reference registry cannot satisfy the check.

    Example::

        report = check_membership_inference_bounded(dp_bloom_oracle, 3.0)
        assert report.passed, report.detail
    """
    hits_present = sum(1 for seed in range(num_seeds) if oracle(seed, True))
    hits_absent = sum(1 for seed in range(num_seeds) if oracle(seed, False))
    eps_hat = empirical_epsilon(hits_present, num_seeds, hits_absent, num_seeds)
    threshold = claimed_epsilon + slack
    evidence: dict[str, object] = {
        "empirical_epsilon": eps_hat,
        "claimed_epsilon": claimed_epsilon,
        "threshold": threshold,
        "hits_present": hits_present,
        "hits_absent": hits_absent,
        "num_seeds": num_seeds,
    }
    if eps_hat > threshold:
        return ValidatorReport(
            passed=False,
            detail=(
                f"membership inference leaks eps_hat={eps_hat:.2f} > "
                f"claimed {claimed_epsilon:.2f} + slack {slack:.2f}"
            ),
            evidence=evidence,
        )
    return ValidatorReport(
        passed=True,
        detail=f"membership inference bounded: eps_hat={eps_hat:.2f} <= {threshold:.2f}",
        evidence=evidence,
    )
