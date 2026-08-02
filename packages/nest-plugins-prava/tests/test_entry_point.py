# SPDX-License-Identifier: Apache-2.0
"""Entry-point / registry discovery for the prava plugin."""

from __future__ import annotations

import pytest
from nest_core.plugins import PluginRegistry
from nest_plugins_prava import PravaPayments
from nest_plugins_prava.plugin import reset_ledger_sidecars
from nest_sdk import AgentId, Payments


@pytest.fixture(autouse=True)
def _clean_sidecars() -> None:  # pyright: ignore[reportUnusedFunction]
    reset_ledger_sidecars()


def test_isinstance_protocol() -> None:
    pay = PravaPayments(AgentId("a1"), initial_balance=10)
    assert isinstance(pay, Payments)


def test_registry_resolves_prava_when_installed() -> None:
    reg = PluginRegistry()
    try:
        cls = reg.resolve("payments", "prava")
    except KeyError:
        pytest.skip("prava entry point not installed in this environment")
    assert cls is PravaPayments or cls.__name__ == "PravaPayments"
