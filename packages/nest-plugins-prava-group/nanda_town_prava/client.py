# SPDX-License-Identifier: Apache-2.0
"""A thin, typed HTTP client for the GMP/1 group-mandate engine.

Stdlib only (``urllib``), so installing this plugin cannot pull an HTTP
stack into a Nanda Town run. Blocking calls are pushed onto a worker
thread, which is what lets the async ``Payments`` methods stay honest
about not blocking the simulator's event loop.

Two rules this module exists to enforce:

1. The bearer token is held in one place, written to one header, and is
   never a member of any structure that leaves this class.
2. Every response body and every error body is passed through
   :func:`~nanda_town_prava._redaction.redact` before anything else can
   see it — see ``_redaction.py`` for why keys are dropped, not masked.

Example::

    client = GmpHttpClient("http://localhost:4100", token="dev-token")
    group = await client.create_group({"title": "…", "members": [...]})
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol, runtime_checkable

from ._redaction import redact, scrub_text

# ``urllib`` exposes exception reasons as object-like values across Python
# implementations; the runtime narrowing below is deliberately defensive.
# pyright: reportUnnecessaryIsInstance=false

DEFAULT_BASE_URL = "http://localhost:4100"
DEFAULT_TIMEOUT = 10.0

JsonDict = dict[str, Any]


class EngineError(RuntimeError):
    """Base class for every failure this client reports.

    The message is always scrubbed. Callers may print it.

    Example::

        raise EngineError("charge refused")
    """

    def __init__(self, message: str) -> None:
        super().__init__(scrub_text(message))


class EngineTransportError(EngineError):
    """The engine could not be reached, so the request outcome is unknown.

    GMP/1 §4.2 is emphatic that unknown is not failed: a transport error
    after a charge call may mean the charge landed. Callers must reconcile,
    never assume.

    Example::

        raise EngineTransportError("connection refused")
    """


class EngineHTTPError(EngineError):
    """The engine answered with a 4xx/5xx. A definitive, replay-safe refusal.

    Example::

        raise EngineHTTPError(401, "missing or invalid bearer token")
    """

    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = scrub_text(detail)
        super().__init__(f"engine returned HTTP {status}: {self.detail}")


@runtime_checkable
class EngineTransport(Protocol):
    """The slice of the GMP/1 REST surface this plugin needs.

    Implemented twice: by :class:`GmpHttpClient` against a running engine,
    and by ``_simulator.SimulatedEngine`` in process. The plugin cannot
    tell them apart, which is the entire point of the ``live`` /
    ``simulated`` switch.

    Example::

        transport: EngineTransport = GmpHttpClient(base_url, token=tok)
    """

    async def create_group(self, body: JsonDict) -> JsonDict: ...

    async def get_group(self, group_id: str) -> JsonDict: ...

    async def cancel_group(self, group_id: str) -> JsonDict: ...

    async def get_receipt(self, group_id: str) -> JsonDict | None: ...

    async def open_member(self, member_id: str) -> JsonDict: ...

    async def get_member(self, member_id: str) -> JsonDict: ...

    async def approve_member(self, member_id: str) -> bool:
        """Stand in for a human passkey tap. Only ever possible off a real rail."""
        ...


class GmpHttpClient:
    """Talks to a running GMP/1 engine over HTTP.

    Reads ``GMP_API`` and ``ENGINE_API_TOKEN`` from the environment when
    not given explicitly, matching the engine's own defaults.

    Example::

        client = GmpHttpClient.from_env()
        state = await client.get_group("g_123")
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        token: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        opener: Any = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        # The one and only copy. Never serialised, never in a repr, never in
        # an exception, never in a returned dict.
        self.__token = token
        self._timeout = timeout
        self._opener = opener or urllib.request.urlopen

    @classmethod
    def from_env(cls, *, timeout: float = DEFAULT_TIMEOUT) -> GmpHttpClient:
        """Build a client from ``GMP_API`` / ``ENGINE_API_TOKEN``.

        Example::

            client = GmpHttpClient.from_env()
        """
        return cls(
            os.environ.get("GMP_API", DEFAULT_BASE_URL),
            token=os.environ.get("ENGINE_API_TOKEN", ""),
            timeout=timeout,
        )

    @property
    def base_url(self) -> str:
        return self._base_url

    def __repr__(self) -> str:  # pragma: no cover - trivial, but load-bearing
        return f"GmpHttpClient(base_url={self._base_url!r}, token=<withheld>)"

    # -- transport ----------------------------------------------------------

    def _request_sync(
        self,
        method: str,
        path: str,
        body: JsonDict | None,
        *,
        authenticated: bool,
    ) -> JsonDict:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"content-type": "application/json", "accept": "application/json"}
        if authenticated and self.__token:
            headers["authorization"] = f"Bearer {self.__token}"

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener(request, timeout=self._timeout) as response:
                raw = response.read().decode("utf-8") or "{}"
        except urllib.error.HTTPError as exc:  # definitive answer
            detail = ""
            try:
                detail = exc.read().decode("utf-8")[:400]
            except Exception:  # noqa: BLE001 - a body we cannot read is not a crash
                detail = exc.reason if isinstance(exc.reason, str) else ""
            raise EngineHTTPError(exc.code, detail) from None
        except urllib.error.URLError as exc:  # unknown outcome
            reason = exc.reason if isinstance(exc.reason, str) else type(exc.reason).__name__
            raise EngineTransportError(f"{method} {path} did not complete: {reason}") from None
        except (TimeoutError, OSError) as exc:
            raise EngineTransportError(f"{method} {path} did not complete: {exc}") from None

        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            raise EngineHTTPError(200, f"non-JSON body from {path}") from None
        if not isinstance(parsed, dict):
            raise EngineHTTPError(200, f"expected a JSON object from {path}")
        return redact(parsed)

    async def _request(
        self,
        method: str,
        path: str,
        body: JsonDict | None = None,
        *,
        authenticated: bool = False,
    ) -> JsonDict:
        return await asyncio.to_thread(
            self._request_sync, method, path, body, authenticated=authenticated
        )

    # -- GMP/1 surface ------------------------------------------------------

    async def create_group(self, body: JsonDict) -> JsonDict:
        """``POST /v1/groups`` — the only authenticated call in the flow."""
        return await self._request("POST", "/v1/groups", body, authenticated=True)

    async def get_group(self, group_id: str) -> JsonDict:
        """``GET /v1/groups/{id}``."""
        return await self._request("GET", f"/v1/groups/{group_id}")

    async def cancel_group(self, group_id: str) -> JsonDict:
        """``POST /v1/groups/{id}/cancel`` — pre-commit only."""
        return await self._request("POST", f"/v1/groups/{group_id}/cancel", {})

    async def get_receipt(self, group_id: str) -> JsonDict | None:
        """``GET /v1/groups/{id}/receipt`` — the signed artifact, or ``None``.

        404 here is normal: a group that has not reached a terminal state
        has no receipt yet.
        """
        try:
            return await self._request("GET", f"/v1/groups/{group_id}/receipt")
        except EngineHTTPError as exc:
            if exc.status == 404:
                return None
            raise

    async def open_member(self, member_id: str) -> JsonDict:
        """``POST /v1/members/{id}/open`` — mints that member's mandate session."""
        return await self._request("POST", f"/v1/members/{member_id}/open", {})

    async def get_member(self, member_id: str) -> JsonDict:
        """``GET /v1/members/{id}``."""
        return await self._request("GET", f"/v1/members/{member_id}")

    async def approve_member(self, member_id: str) -> bool:
        """Drive the *mock* hosted ceremony to completion.

        This exists so CI can run an end-to-end group commit against an
        engine started with ``PRAVA_ENV=mock``. It is structurally
        impossible against a real rail: ``/mock/pay/...`` is registered
        only when the engine's adapter is ``MockPrava``, so this 404s —
        and returns ``False`` — the moment a real Prava key is in play.
        There is no code path in this package that approves a real
        mandate. A human's passkey is the only thing that can.
        """
        member = await self.get_member(member_id)
        approval_url = str(member.get("approval_url") or "")
        marker = "/mock/pay/"
        if marker not in approval_url:
            return False
        session_id = approval_url.rsplit(marker, 1)[1].split("/")[0]
        try:
            result = await self._request("POST", f"/mock/pay/{session_id}/approve", {})
        except EngineError:
            return False
        return bool(result.get("ok"))
