# SPDX-License-Identifier: Apache-2.0
"""Prava HTTP + mock clients used by the payments adapter.

Example::

    from nest_plugins_prava.client import MockPravaClient, build_client
    client = build_client(mode="mock")
"""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, cast, runtime_checkable

import httpx

from nest_plugins_prava.errors import (
    PravaApiError,
    PravaAuthError,
    PravaSessionExpiredError,
    PravaTimeoutError,
    PravaValidationError,
)
from nest_plugins_prava.secrets import REDACTED, redact

DEFAULT_BASE_URL = "https://sandbox.api.prava.space"
PravaMode = Literal["mock", "live", "hybrid"]


@dataclass(frozen=True)
class SessionResult:
    """Create-session response (secrets redacted in repr helpers)."""

    session_id: str
    order_id: str | None
    expires_at: str | None
    response_id: str | None = None
    # Kept off public_view; only for live SDK hand-off if needed.
    session_token: str | None = field(default=None, repr=False)

    def public_view(self) -> dict[str, Any]:
        """Return a log-safe view of the session."""
        return {
            "session_id": self.session_id,
            "order_id": self.order_id,
            "expires_at": self.expires_at,
            "response_id": self.response_id,
            "session_token": REDACTED if self.session_token else None,
        }


@dataclass(frozen=True)
class PaymentResultView:
    """Normalized payment-result poll response."""

    session_id: str
    status: str
    order_id: str | None
    txn_ref_id: str | None
    response_id: str | None = None
    raw: dict[str, Any] = field(default_factory=lambda: {}, repr=False)

    def public_view(self) -> dict[str, Any]:
        """Return a log-safe view (credentials scrubbed)."""
        return {
            "session_id": self.session_id,
            "status": self.status,
            "order_id": self.order_id,
            "txn_ref_id": self.txn_ref_id,
            "response_id": self.response_id,
            "raw": redact(self.raw),
        }


@dataclass(frozen=True)
class ReportResult:
    """Report-status response."""

    status: str
    txn_ref_id: str
    txn_status: str
    response_id: str | None = None


@runtime_checkable
class PravaClient(Protocol):
    """Minimal Prava surface used by the adapter."""

    async def create_session(self, body: dict[str, Any]) -> SessionResult: ...

    async def get_payment_result(self, session_id: str) -> PaymentResultView: ...

    async def report_status(
        self,
        session_id: str,
        *,
        txn_ref_id: str,
        txn_status: str,
        authorization_code: str = "OK123",
        response_code: str = "00",
    ) -> ReportResult: ...

    async def revoke_session(self, session_id: str) -> None: ...

    @property
    def call_count(self) -> int: ...


def _is_retryable_api_error(exc: PravaApiError, status_code: int | None = None) -> bool:
    """Return True for transient upstream failures that may be retried."""
    code = exc.code or ""
    if status_code is not None and status_code >= 500:
        return True
    if code.startswith("HTTP_5"):
        return True
    return code.endswith("_ERROR") or code in {
        "MERCHANT_LOOKUP_ERROR",
        "SESSION_CREATE_ERROR",
        "REPORT_STATUS_ERROR",
        "VISA_CONFIRMATION_FAILED",
    }


def _map_http_error(
    status_code: int, payload: dict[str, Any], response_id: str | None
) -> Exception:
    error_obj = payload.get("error")
    err: dict[str, Any] = cast("dict[str, Any]", error_obj) if isinstance(error_obj, dict) else {}
    code = str(err.get("code") or payload.get("code") or f"HTTP_{status_code}")
    message = str(err.get("message") or payload.get("message") or f"HTTP {status_code}")
    if status_code in (401, 403) or code.startswith("AUTH_"):
        if code in {"AUTH_1003", "AUTH_1004"}:
            return PravaSessionExpiredError(message, code=code, response_id=response_id)
        return PravaAuthError(message, code=code, response_id=response_id)
    if (
        status_code == 400
        or code.startswith("VAL_")
        or code
        in {
            "INVALID_REQUEST",
            "INVALID_STATE",
            "CARD_NOT_FOUND",
            "CARD_INACTIVE",
            "NOT_FOUND",
        }
    ):
        return PravaValidationError(message, code=code, response_id=response_id)
    if status_code >= 500:
        return PravaApiError(message, code=code, response_id=response_id)
    return PravaApiError(message, code=code, response_id=response_id)


def _require_session_payload(payload: dict[str, Any], response_id: str | None) -> SessionResult:
    """Validate create-session success payload; reject unexpected shapes."""
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise PravaValidationError(
            f"Invalid create-session response: missing session_id in {sorted(payload.keys())}",
            code="VAL_SCHEMA",
            response_id=response_id,
        )
    order_id = payload.get("order_id")
    return SessionResult(
        session_id=session_id,
        order_id=str(order_id) if order_id is not None else None,
        expires_at=payload.get("expires_at")
        if isinstance(payload.get("expires_at"), str)
        else None,
        response_id=response_id,
        session_token=payload.get("session_token")
        if isinstance(payload.get("session_token"), str)
        else None,
    )


class MockPravaClient:
    """Deterministic in-process Prava stand-in for CI and scenario runs.

    Example::

        client = MockPravaClient(fail_on_create=False, decline_report=False)
    """

    def __init__(
        self,
        *,
        fail_on_create: bool = False,
        create_error: Exception | None = None,
        timeout_on: str | None = None,
        decline_report: bool = False,
        poll_statuses: list[str] | None = None,
        latency_s: float = 0.0,
    ) -> None:
        self.fail_on_create = fail_on_create
        self.create_error = create_error
        self.timeout_on = timeout_on
        self.decline_report = decline_report
        self.poll_statuses = list(poll_statuses or ["completed"])
        self.latency_s = latency_s
        self._sessions: dict[str, dict[str, Any]] = {}
        self._poll_idx: dict[str, int] = {}
        self._calls = 0

    @property
    def call_count(self) -> int:
        """Number of API methods invoked."""
        return self._calls

    async def _maybe_latency(self) -> None:
        if self.latency_s > 0:
            await asyncio.sleep(self.latency_s)

    async def create_session(self, body: dict[str, Any]) -> SessionResult:
        """Create a mock session."""
        self._calls += 1
        await self._maybe_latency()
        if self.timeout_on == "create_session":
            raise PravaTimeoutError("mock timeout on create_session", code="TIMEOUT")
        if self.create_error is not None:
            raise self.create_error
        if self.fail_on_create:
            raise PravaApiError("mock create failure", code="SESSION_CREATE_ERROR")
        session_id = f"sess_mock_{uuid.uuid4().hex[:12]}"
        order_id = f"ord_mock_{uuid.uuid4().hex[:8]}"
        self._sessions[session_id] = {
            "body": body,
            "order_id": order_id,
            "status": "pending",
            "txn_ref_id": f"tli_{uuid.uuid4().hex[:8]}",
        }
        self._poll_idx[session_id] = 0
        return SessionResult(
            session_id=session_id,
            order_id=order_id,
            expires_at=None,
            response_id=f"resp_mock_{uuid.uuid4().hex[:8]}",
            session_token=f"tok_mock_{uuid.uuid4().hex}",
        )

    async def get_payment_result(self, session_id: str) -> PaymentResultView:
        """Poll mock payment result, advancing through configured statuses."""
        self._calls += 1
        await self._maybe_latency()
        if self.timeout_on == "get_payment_result":
            raise PravaTimeoutError("mock timeout on get_payment_result", code="TIMEOUT")
        session = self._sessions.get(session_id)
        if session is None:
            raise PravaValidationError("session not found", code="NOT_FOUND")
        idx = self._poll_idx.get(session_id, 0)
        status = self.poll_statuses[min(idx, len(self.poll_statuses) - 1)]
        self._poll_idx[session_id] = idx + 1
        session["status"] = status
        return PaymentResultView(
            session_id=session_id,
            status=status,
            order_id=session["order_id"],
            txn_ref_id=session["txn_ref_id"],
            response_id=f"resp_mock_{uuid.uuid4().hex[:8]}",
            raw={"status": status, "token": "4111111111111111", "dynamic_cvv": "123"},
        )

    async def report_status(
        self,
        session_id: str,
        *,
        txn_ref_id: str,
        txn_status: str,
        authorization_code: str = "OK123",
        response_code: str = "00",
    ) -> ReportResult:
        """Report mock checkout outcome."""
        self._calls += 1
        await self._maybe_latency()
        if self.timeout_on == "report_status":
            raise PravaTimeoutError("mock timeout on report_status", code="TIMEOUT")
        if session_id not in self._sessions:
            raise PravaValidationError("session not found", code="NOT_FOUND")
        final = "DECLINED" if self.decline_report else txn_status
        return ReportResult(
            status="confirmed",
            txn_ref_id=txn_ref_id,
            txn_status=final,
            response_id=f"resp_mock_{uuid.uuid4().hex[:8]}",
        )

    async def revoke_session(self, session_id: str) -> None:
        """Revoke a mock session."""
        self._calls += 1
        self._sessions.pop(session_id, None)


class HttpPravaClient:
    """Live Prava sandbox/production HTTP client.

    Example::

        client = HttpPravaClient(api_key="sk_test_...", base_url=DEFAULT_BASE_URL)
    """

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 15.0,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key:
            msg = "PRAVA_API_KEY / api_key is required for live mode"
            raise PravaAuthError(msg, code="AUTH_1002")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._transport = transport
        self._calls = 0

    @property
    def call_count(self) -> int:
        """Number of HTTP attempts (including retries)."""
        return self._calls

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str | None]:
        url = f"{self._base_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            self._calls += 1
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout_s,
                    transport=self._transport,
                ) as client:
                    response = await client.request(
                        method,
                        url,
                        headers=self._headers(),
                        json=json_body,
                    )
                response_id = response.headers.get("X-Response-ID")
                try:
                    parsed: Any = response.json() if response.content else {}
                except ValueError:
                    parsed = {"message": response.text}
                payload: dict[str, Any] = (
                    cast("dict[str, Any]", parsed) if isinstance(parsed, dict) else {"data": parsed}
                )
                if response.status_code >= 400:
                    mapped = _map_http_error(response.status_code, payload, response_id)
                    # Attach status for retry classification without changing public API.
                    if isinstance(mapped, PravaApiError):
                        mapped.status_code = response.status_code  # type: ignore[attr-defined]
                    raise mapped
                return payload, response_id
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt >= self._max_retries:
                    break
                await asyncio.sleep(0.05 * (2**attempt))
                continue
            except PravaAuthError:
                # Never retry auth failures.
                raise
            except PravaSessionExpiredError:
                raise
            except PravaValidationError:
                # Never retry validation / schema / 4xx business errors.
                raise
            except PravaApiError as exc:
                last_exc = exc
                status_code = getattr(exc, "status_code", None)
                if not _is_retryable_api_error(exc, status_code) or attempt >= self._max_retries:
                    raise
                await asyncio.sleep(0.05 * (2**attempt))
                continue
        if isinstance(last_exc, PravaApiError):
            raise last_exc
        raise PravaTimeoutError(
            f"Prava request failed after retries: {last_exc}",
            code="TIMEOUT",
        ) from last_exc

    async def create_session(self, body: dict[str, Any]) -> SessionResult:
        """POST /v1/sessions."""
        payload, response_id = await self._request("POST", "/v1/sessions", json_body=body)
        return _require_session_payload(payload, response_id)

    async def get_payment_result(self, session_id: str) -> PaymentResultView:
        """GET /v1/sessions/{id}/payment-result."""
        payload, response_id = await self._request(
            "GET", f"/v1/sessions/{session_id}/payment-result"
        )
        txn_ref_id: str | None = None
        transactions_raw = payload.get("transactions")
        if isinstance(transactions_raw, list) and transactions_raw:
            transactions = cast("list[Any]", transactions_raw)
            first_any = transactions[0]
            if isinstance(first_any, dict):
                first = cast("dict[str, Any]", first_any)
                candidate = first.get("txn_ref_id") or first.get("id")
                if candidate is not None:
                    txn_ref_id = str(candidate)
        order_id_raw = payload.get("order_id")
        return PaymentResultView(
            session_id=str(payload.get("session_id") or session_id),
            status=str(payload.get("status") or "pending"),
            order_id=str(order_id_raw) if order_id_raw is not None else None,
            txn_ref_id=txn_ref_id,
            response_id=response_id,
            raw=payload,
        )

    async def report_status(
        self,
        session_id: str,
        *,
        txn_ref_id: str,
        txn_status: str,
        authorization_code: str = "OK123",
        response_code: str = "00",
    ) -> ReportResult:
        """POST /v1/sessions/{id}/report-status."""
        body = {
            "txn_ref_id": txn_ref_id,
            "txn_status": txn_status,
            "authorization_code": authorization_code,
            "response_code": response_code,
        }
        payload, response_id = await self._request(
            "POST",
            f"/v1/sessions/{session_id}/report-status",
            json_body=body,
        )
        return ReportResult(
            status=str(payload.get("status") or "confirmed"),
            txn_ref_id=str(payload.get("txn_ref_id") or txn_ref_id),
            txn_status=str(payload.get("txn_status") or txn_status),
            response_id=response_id,
        )

    async def revoke_session(self, session_id: str) -> None:
        """POST /v1/sessions/{id}/revoke."""
        await self._request("POST", f"/v1/sessions/{session_id}/revoke", json_body={})


class HybridPravaClient:
    """Live create-session + headless completion for agent simulations.

    Creates a real sandbox session (evidence), then completes the remaining
    payment-result/report steps via an embedded mock so headless agents can
    finish quote→pay→verify without a browser passkey.

    Example::

        client = HybridPravaClient(api_key="sk_test_...")
    """

    def __init__(self, http: HttpPravaClient, mock: MockPravaClient | None = None) -> None:
        self._http = http
        self._mock = mock or MockPravaClient()
        self._session_map: dict[str, str] = {}
        self._calls = 0

    @property
    def call_count(self) -> int:
        """Combined live + mock call count."""
        return self._calls + self._http.call_count + self._mock.call_count

    async def create_session(self, body: dict[str, Any]) -> SessionResult:
        """Create a real sandbox session, then bind a mock completion lane."""
        live = await self._http.create_session(body)
        mock = await self._mock.create_session(body)
        self._session_map[live.session_id] = mock.session_id
        self._calls += 1
        # Preserve live session_id as evidence; completion uses mock lane.
        return SessionResult(
            session_id=live.session_id,
            order_id=live.order_id or mock.order_id,
            expires_at=live.expires_at,
            response_id=live.response_id,
            session_token=live.session_token,
        )

    def _mock_id(self, session_id: str) -> str:
        return self._session_map.get(session_id, session_id)

    async def get_payment_result(self, session_id: str) -> PaymentResultView:
        """Headless poll against the mock lane, tagged with live session id."""
        view = await self._mock.get_payment_result(self._mock_id(session_id))
        return PaymentResultView(
            session_id=session_id,
            status=view.status,
            order_id=view.order_id,
            txn_ref_id=view.txn_ref_id,
            response_id=view.response_id,
            raw=view.raw,
        )

    async def report_status(
        self,
        session_id: str,
        *,
        txn_ref_id: str,
        txn_status: str,
        authorization_code: str = "OK123",
        response_code: str = "00",
    ) -> ReportResult:
        """Headless report-status against the mock lane."""
        return await self._mock.report_status(
            self._mock_id(session_id),
            txn_ref_id=txn_ref_id,
            txn_status=txn_status,
            authorization_code=authorization_code,
            response_code=response_code,
        )

    async def revoke_session(self, session_id: str) -> None:
        """Best-effort revoke on live, always drop mock lane."""
        try:
            await self._http.revoke_session(session_id)
        finally:
            mock_id = self._session_map.pop(session_id, None)
            if mock_id is not None:
                await self._mock.revoke_session(mock_id)


def resolve_mode(mode: str | None = None) -> PravaMode:
    """Resolve adapter mode from argument or ``PRAVA_MODE`` env."""
    raw = (mode or os.environ.get("PRAVA_MODE") or "mock").strip().lower()
    if raw not in {"mock", "live", "hybrid"}:
        msg = f"Invalid PRAVA_MODE={raw!r}; expected mock|live|hybrid"
        raise PravaValidationError(msg, code="VAL_MODE")
    return raw  # type: ignore[return-value]


def build_client(
    *,
    mode: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    mock: MockPravaClient | None = None,
) -> PravaClient:
    """Factory for mock / live / hybrid clients.

    Example::

        client = build_client(mode="mock")
    """
    resolved = resolve_mode(mode)
    if resolved == "mock":
        return mock or MockPravaClient()
    key = api_key if api_key is not None else os.environ.get("PRAVA_API_KEY", "")
    url = base_url or os.environ.get("PRAVA_BASE_URL", DEFAULT_BASE_URL)
    http = HttpPravaClient(api_key=key, base_url=url)
    if resolved == "live":
        return http
    return HybridPravaClient(http, mock or MockPravaClient())


def default_service_price(service_name: str) -> int:
    """Deterministic per-service quote used when no catalog override exists."""
    # Stable hash → 10..100 credits
    digest = sum(ord(ch) for ch in service_name) % 91
    return 10 + digest
