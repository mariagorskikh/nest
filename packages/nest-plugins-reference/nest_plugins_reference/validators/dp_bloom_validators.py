# SPDX-License-Identifier: Apache-2.0
"""Adversarial validator for the ``dp_bloom`` registry: membership inference.

The attack the default ``in_memory`` registry silently allows is **membership
inference**: an adversary who can read the registry's observable membership
surface decides, for a target agent, whether that agent is registered. Against a
plain registry this is not an attack so much as a lookup — the surface *is* the
member set, so the adversary is always right. That is the leak ``dp_bloom`` is
built to bound.

The game (a standard DP membership-inference experiment)
--------------------------------------------------------

For a fixed target agent, compare two neighboring worlds:

* **present** — the registry holds a background set *plus* the target;
* **absent**  — the registry holds only the background set.

An oracle plays one world under one seed and returns the single bit the
adversary observes: *does the target look registered?* Sweeping the seed bank
estimates ``p1 = Pr[reported present | present]`` and
``p0 = Pr[reported present | absent]``. The adversary's distinguishing power is
the larger log-likelihood ratio across the two possible reports, which is
exactly an empirical epsilon:

    ``eps_hat = max( |ln(p1/p0)|, |ln((1-p1)/(1-p0))| )``

By the post-processing property of differential privacy, any function of an
``epsilon``-DP published index — and :meth:`DPBloomRegistry.membership_query` is
one — is itself ``epsilon``-DP, so a correctly calibrated ``dp_bloom`` yields
``eps_hat`` at or below its claimed budget (up to finite-sample slack). A registry
that answers membership exactly yields ``p1 = 1, p0 = 0`` and an unbounded
``eps_hat`` — it cannot satisfy any finite budget, which is the charter's bar for
an adversarial validator that the reference plugin must fail.

Probabilities are Jeffreys-smoothed (add ``0.5``) so a deterministic leaker maps
to a large-but-finite ``eps_hat`` rather than a raw division by zero, keeping the
report a clean numeric comparison.

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
registry (background set, plus the target iff ``include_target``) seeded by
``seed`` and returns the membership bit an adversary observes for the target."""

_DEFAULT_SEEDS = 400
"""Seed-bank size. Large enough that ``p0 = Pr[present | absent]`` (roughly
``p**k``) is estimated from several hits, small enough that the validator runs in
well under a second on the tiny filters used in scenarios."""

_DEFAULT_SLACK = 1.0
"""Additive tolerance on the epsilon bound, absorbing finite-sample variance and
Jeffreys-smoothing bias. Comfortably separates a calibrated ``dp_bloom``
(``eps_hat`` near the budget) from an exact registry (``eps_hat`` in the 6-7 range
for this bank)."""


def _smoothed(hits: int, total: int) -> float:
    """Jeffreys-smoothed probability of the observed outcome."""
    return (hits + 0.5) / (total + 1.0)


def empirical_epsilon(hits_present: int, n_present: int, hits_absent: int, n_absent: int) -> float:
    """Return the empirical epsilon of a membership-inference game's counts.

    ``hits_*`` count seeds under which the adversary saw *reported present*;
    ``n_*`` are the seed totals for each world.

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

    Runs the two-world game over seeds ``0 .. num_seeds - 1`` (deterministic, so
    the report replays byte-identically) and passes iff the empirical epsilon is
    within ``claimed_epsilon + slack``.

    * Against ``dp_bloom`` calibrated to ``claimed_epsilon`` the bound holds
      (post-processing of an epsilon-DP index), so it **passes**.
    * Against ``in_memory`` the target is reported present iff it is registered,
      giving an unbounded empirical epsilon, so it **fails** — the validator
      cannot be satisfied by the exact reference registry.

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
