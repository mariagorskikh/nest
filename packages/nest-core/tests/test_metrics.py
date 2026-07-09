# SPDX-License-Identifier: Apache-2.0
"""Tests for metrics computation and HTML report generation."""

from __future__ import annotations

import html
import json
import math
from pathlib import Path

import pytest
from nest_core.metrics import (
    ALL_METRICS,
    compute_metrics,
    generate_html_report,
)
from nest_core.runner import ScenarioRunner
from nest_core.scenario import ScenarioConfig


class TestComputeMetrics:
    def _write_trace(self, path: Path) -> None:
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 0.0, "agent": "a2", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "size": 10, "corr": "c-1"},
            {"ts": 3.0, "agent": "a2", "kind": "receive", "from": "a1", "size": 10, "corr": "c-1"},
            {"ts": 2.0, "agent": "a2", "kind": "send", "to": "a1", "size": 8, "corr": "c-2"},
            {"ts": 4.0, "agent": "a1", "kind": "receive", "from": "a2", "size": 8, "corr": "c-2"},
            {"ts": 3.0, "agent": "a1", "kind": "send", "to": "a2", "size": 5, "corr": "c-3"},
            {"ts": 3.0, "agent": "a2", "kind": "dropped", "from": "a1", "size": 5, "corr": "c-3"},
            {"ts": 5.0, "agent": "a1", "kind": "stop"},
            {"ts": 5.0, "agent": "a2", "kind": "stop"},
        ]
        path.write_text("\n".join(json.dumps(e) for e in events))

    def test_delivery_rate(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["delivery_rate"])
        assert abs(results["delivery_rate"] - 2.0 / 3.0) < 0.01

    def test_success_rate_backward_compat(self, tmp_path: Path) -> None:
        """Old 'success_rate' name still works as an alias for delivery_rate."""
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["success_rate"])
        assert abs(results["success_rate"] - 2.0 / 3.0) < 0.01

    def test_message_count(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["message_count"])
        assert results["message_count"] == 5.0

    def test_mean_latency(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["mean_latency"])
        assert results["mean_latency"] == pytest.approx(2.0)

    def test_p95_latency(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "corr": "c-1"},
            {"ts": 2.0, "agent": "a2", "kind": "receive", "from": "a1", "corr": "c-1"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "corr": "c-2"},
            {"ts": 5.0, "agent": "a2", "kind": "receive", "from": "a1", "corr": "c-2"},
            {"ts": 6.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))
        results = compute_metrics(trace, ["p95_latency"])
        assert results["p95_latency"] == pytest.approx(4.0)

    def test_empty_trace_returns_zeros(self, tmp_path: Path) -> None:
        trace = tmp_path / "empty.jsonl"
        trace.write_text("")
        results = compute_metrics(
            trace,
            ["delivery_rate", "message_count", "mean_latency", "duration", "agent_count"],
        )
        assert results["delivery_rate"] == 0.0
        assert results["message_count"] == 0.0
        assert results["mean_latency"] == 0.0
        assert results["duration"] == 0.0
        assert results["agent_count"] == 0.0

    def test_throughput_zero_duration(self, tmp_path: Path) -> None:
        trace = tmp_path / "instant.jsonl"
        events = [
            {"ts": 1.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "corr": "c-1"},
            {"ts": 1.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))
        results = compute_metrics(trace, ["throughput"])
        assert results["throughput"] == 0.0

    def test_non_finite_timestamps_do_not_crash(self, tmp_path: Path) -> None:
        trace = tmp_path / "nan.jsonl"
        events = [
            {"ts": float("nan"), "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "corr": "c-1"},
            {"ts": float("inf"), "agent": "a2", "kind": "receive", "from": "a1", "corr": "c-1"},
            {"ts": 2.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))
        results = compute_metrics(trace, ["duration", "mean_latency", "throughput"])
        assert all(math.isfinite(v) for v in results.values())

    def test_dropped_count(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["dropped_count"])
        assert results["dropped_count"] == 1.0

    def test_agent_count(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["agent_count"])
        assert results["agent_count"] == 2.0

    def test_duration(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["duration"])
        assert results["duration"] == 5.0

    def test_all_metrics(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ALL_METRICS)
        assert len(results) == len(ALL_METRICS)

    def test_unknown_metric_ignored(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["nonexistent", "message_count"])
        assert "message_count" in results
        assert "nonexistent" not in results

    def test_unique_pairs(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_trace(trace)
        results = compute_metrics(trace, ["unique_pairs"])
        # a1 <-> a2 is the only pair
        assert results["unique_pairs"] == 1.0


class TestMarketplaceMetrics:
    """Tests for marketplace-specific metrics: deal_rate, rejection_rate, mean_rounds_to_deal."""

    def _write_marketplace_trace(self, path: Path) -> None:
        events = [
            {"ts": 0.0, "agent": "buyer-0", "kind": "start"},
            {"ts": 0.0, "agent": "seller-0", "kind": "start"},
            # Round 1: buyer-0 buys, seller rejects
            {
                "ts": 1.0,
                "agent": "buyer-0",
                "kind": "send",
                "to": "seller-0",
                "msg": "buy:laptop:400",
                "corr": "c-1",
            },
            {
                "ts": 1.0,
                "agent": "seller-0",
                "kind": "receive",
                "from": "buyer-0",
                "msg": "buy:laptop:400",
                "corr": "c-1",
            },
            {
                "ts": 2.0,
                "agent": "seller-0",
                "kind": "send",
                "to": "buyer-0",
                "msg": "reject:laptop:500",
                "corr": "c-2",
            },
            {
                "ts": 2.0,
                "agent": "buyer-0",
                "kind": "receive",
                "from": "seller-0",
                "msg": "reject:laptop:500",
                "corr": "c-2",
            },
            # Round 2: buyer-0 buys again, seller accepts
            {
                "ts": 3.0,
                "agent": "buyer-0",
                "kind": "send",
                "to": "seller-0",
                "msg": "buy:laptop:480",
                "corr": "c-3",
            },
            {
                "ts": 3.0,
                "agent": "seller-0",
                "kind": "receive",
                "from": "buyer-0",
                "msg": "buy:laptop:480",
                "corr": "c-3",
            },
            {
                "ts": 4.0,
                "agent": "seller-0",
                "kind": "send",
                "to": "buyer-0",
                "msg": "sold:laptop:480",
                "corr": "c-4",
            },
            {
                "ts": 4.0,
                "agent": "buyer-0",
                "kind": "receive",
                "from": "seller-0",
                "msg": "sold:laptop:480",
                "corr": "c-4",
            },
            # Another buyer, immediate deal
            {
                "ts": 5.0,
                "agent": "buyer-1",
                "kind": "send",
                "to": "seller-0",
                "msg": "buy:keyboard:50",
                "corr": "c-5",
            },
            {
                "ts": 5.0,
                "agent": "seller-0",
                "kind": "receive",
                "from": "buyer-1",
                "msg": "buy:keyboard:50",
                "corr": "c-5",
            },
            {
                "ts": 6.0,
                "agent": "seller-0",
                "kind": "send",
                "to": "buyer-1",
                "msg": "sold:keyboard:50",
                "corr": "c-6",
            },
            {
                "ts": 6.0,
                "agent": "buyer-1",
                "kind": "receive",
                "from": "seller-0",
                "msg": "sold:keyboard:50",
                "corr": "c-6",
            },
            {"ts": 7.0, "agent": "buyer-0", "kind": "stop"},
            {"ts": 7.0, "agent": "buyer-1", "kind": "stop"},
            {"ts": 7.0, "agent": "seller-0", "kind": "stop"},
        ]
        path.write_text("\n".join(json.dumps(e) for e in events))

    def test_deal_rate(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_marketplace_trace(trace)
        results = compute_metrics(trace, ["deal_rate"])
        # 3 buy requests, 2 sold responses -> 2/3
        assert abs(results["deal_rate"] - 2.0 / 3.0) < 0.01

    def test_rejection_rate(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_marketplace_trace(trace)
        results = compute_metrics(trace, ["rejection_rate"])
        # 3 buy requests, 1 reject -> 1/3
        assert abs(results["rejection_rate"] - 1.0 / 3.0) < 0.01

    def test_mean_rounds_to_deal(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        self._write_marketplace_trace(trace)
        results = compute_metrics(trace, ["mean_rounds_to_deal"])
        # First deal: 2 buy + 1 reject = 3 rounds; second deal: 1 buy = 1 round
        # Mean = (3 + 1) / 2 = 2.0
        assert abs(results["mean_rounds_to_deal"] - 2.0) < 0.01

    def test_deal_rate_no_buys(self, tmp_path: Path) -> None:
        """deal_rate returns 0.0 when there are no buy requests."""
        trace = tmp_path / "t.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "msg": "hello"},
            {"ts": 2.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))
        results = compute_metrics(trace, ["deal_rate", "rejection_rate", "mean_rounds_to_deal"])
        assert results["deal_rate"] == 0.0
        assert results["rejection_rate"] == 0.0
        assert results["mean_rounds_to_deal"] == 0.0


class TestHtmlReport:
    def test_generates_html(self, tmp_path: Path) -> None:
        trace = tmp_path / "t.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "size": 10, "corr": "c-1"},
            {"ts": 1.0, "agent": "a2", "kind": "receive", "from": "a1", "size": 10, "corr": "c-1"},
            {"ts": 2.0, "agent": "a1", "kind": "stop"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))

        metrics = {"delivery_rate": 1.0, "message_count": 2.0}
        report_path = tmp_path / "report.html"
        result = generate_html_report(trace, metrics, report_path)

        assert result.exists()
        content = result.read_text()
        assert "Nanda Town Trace Report" in content
        assert "delivery_rate" in content
        assert "Delivery Rate" in content
        assert "message_count" in content
        assert "<table>" in content

    def test_html_report_backward_compat(self, tmp_path: Path) -> None:
        """HTML report works when passed old 'success_rate' key."""
        trace = tmp_path / "t.jsonl"
        events = [
            {"ts": 0.0, "agent": "a1", "kind": "start"},
            {"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2", "size": 10, "corr": "c-1"},
            {"ts": 1.0, "agent": "a2", "kind": "receive", "from": "a1", "size": 10, "corr": "c-1"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))

        metrics = {"success_rate": 1.0, "message_count": 2.0}
        report_path = tmp_path / "report.html"
        result = generate_html_report(trace, metrics, report_path)

        assert result.exists()
        content = result.read_text()
        assert "Delivery Rate" in content

    def test_html_report_escapes_agent_names(self, tmp_path: Path) -> None:
        evil_name = "<script>alert(1)</script>"
        trace = tmp_path / "trace.jsonl"
        events = [
            {"ts": 0.0, "agent": evil_name, "kind": "start"},
            {"ts": 1.0, "agent": evil_name, "kind": "send", "to": "a2"},
        ]
        trace.write_text("\n".join(json.dumps(e) for e in events))

        metrics = {"message_count": 1.0}
        report_path = tmp_path / "report.html"
        generate_html_report(trace, metrics, report_path)

        content = report_path.read_text()
        assert evil_name not in content
        assert html.escape(evil_name) in content


class TestRunnerMetrics:
    @pytest.mark.asyncio
    async def test_runner_computes_metrics(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "m.jsonl"
        report_file = tmp_path / "report.html"
        config = ScenarioConfig.from_dict(
            {
                "name": "metrics-test",
                "seed": 42,
                "agents": {
                    "count": 10,
                    "roles": [
                        {"name": "buyer", "count": 5},
                        {"name": "seller", "count": 5},
                    ],
                },
                "task": {"type": "marketplace", "config": {"rounds": 3}},
                "duration": "ticks: 2000",
                "metrics": ["success_rate", "message_count", "agent_count"],
                "output": {"trace": str(trace_file), "report": str(report_file)},
            }
        )

        runner = ScenarioRunner(config)
        await runner.run()

        assert runner.metrics["success_rate"] > 0
        assert runner.metrics["message_count"] > 0
        assert runner.metrics["agent_count"] == 10.0
        assert report_file.exists()
        assert "Nanda Town Trace Report" in report_file.read_text()
