# SPDX-License-Identifier: Apache-2.0
"""HTTP transport plugin — re-export from nest_core network runner.
The implementation lives in ``nest_core.sim.network_runner`` so worker bridges
and the reference plugin share one HTTP delivery format.
Example::
    from nest_plugins_reference.transport.http_transport import HttpTransport, HttpNetwork
    network = HttpNetwork()
    transport = HttpTransport(AgentId("a1"), network)
"""

from __future__ import annotations

from nest_core.sim.network_runner import HttpNetwork, HttpTransport

__all__ = ["HttpNetwork", "HttpTransport"]
