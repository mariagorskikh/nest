# SPDX-License-Identifier: Apache-2.0
"""Prava payments plugin for NANDA Town.

Example::

    from nest_plugin_prava import PravaPayments

    payments = PravaPayments(AgentId("agent_a"), console_url="http://localhost:3000")
"""

from __future__ import annotations

from nest_plugin_prava.errors import PravaPaymentError
from nest_plugin_prava.plugin import PravaPayments

__all__ = ["PravaPaymentError", "PravaPayments"]
