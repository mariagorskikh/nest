# SPDX-License-Identifier: Apache-2.0
"""Transport-neutral agent driver protocol and safe typed failures."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from .models import DriverReadiness, DriverRequest, DriverResponse
from .profiles import ResolvedTestProfile


class DriverFailureDisposition(StrEnum):
    """Policy-relevant meanings without coupling the driver to CLI exit codes."""

    CONFIGURATION = "configuration"
    COMPATIBILITY = "compatibility"
    TOWN = "town"
    CONTRACT = "driver_contract"
    INCOMPLETE = "incomplete"


class AgentDriverError(RuntimeError):
    """A safe local error containing no remote text or transport exception."""

    disposition: DriverFailureDisposition

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DriverConfigurationError(AgentDriverError):
    disposition = DriverFailureDisposition.CONFIGURATION


class DriverCompatibilityError(AgentDriverError):
    disposition = DriverFailureDisposition.COMPATIBILITY


class TownDriverError(AgentDriverError):
    disposition = DriverFailureDisposition.TOWN


class DriverContractError(AgentDriverError):
    disposition = DriverFailureDisposition.CONTRACT


class DriverIncompleteError(AgentDriverError):
    disposition = DriverFailureDisposition.INCOMPLETE


@runtime_checkable
class AgentDriver(Protocol):
    """HTTP-free observation-to-intent boundary."""

    async def ready(self, profile: ResolvedTestProfile) -> DriverReadiness:
        """Validate compatibility and return effective adapter readiness."""
        ...

    async def decide(self, request: DriverRequest) -> DriverResponse:
        """Return one validated intent for a validated observation envelope."""
        ...

    async def close(self) -> None:
        """Release transport resources on a best-effort basis."""
        ...
