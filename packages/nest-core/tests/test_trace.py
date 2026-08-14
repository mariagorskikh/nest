# SPDX-License-Identifier: Apache-2.0
"""Trace writer lifecycle tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from nest_core.sim.trace import TraceWriter


class _InspectableTraceWriter(TraceWriter):
    @property
    def underlying_file_closed(self) -> bool:
        return self._file.closed

    def close_underlying_file(self) -> None:
        self._file.close()


def test_close_attempts_file_close_when_flush_fails_and_preserves_flush_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flush failure remains primary without leaking the underlying file handle."""
    writer = _InspectableTraceWriter(tmp_path / "flush-failure.jsonl")
    flush_failure = RuntimeError("flush failed")

    def fail_flush() -> None:
        raise flush_failure

    monkeypatch.setattr(writer, "flush", fail_flush)
    try:
        with pytest.raises(RuntimeError) as caught:
            writer.close()

        assert caught.value is flush_failure
        assert writer.underlying_file_closed
    finally:
        if not writer.underlying_file_closed:
            writer.close_underlying_file()
