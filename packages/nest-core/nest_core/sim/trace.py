# SPDX-License-Identifier: Apache-2.0
"""Trace writer for recording simulation events as JSONL.

Example::

    writer = TraceWriter("trace.jsonl")
    writer.record({"ts": 1.0, "agent": "a1", "kind": "send"})
    writer.flush()
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _private_file_opener(path: str, flags: int) -> int:
    return os.open(path, flags, 0o600)


class TraceWriter:
    """Buffered JSONL trace writer.

    Example::

        writer = TraceWriter("output.jsonl")
        writer.record({"ts": 0.0, "agent": "a1", "kind": "start"})
        writer.close()
    """

    def __init__(self, path: str | Path, buffer_size: int = 1000) -> None:
        self._path = Path(path)
        self._buffer: list[dict[str, Any]] = []
        self._buffer_size = buffer_size
        # TraceWriter owns this stream across record() calls and closes it in close().
        self._file = open(self._path, "w", opener=_private_file_opener)  # noqa: SIM115

    def record(self, event: dict[str, Any]) -> None:
        """Record an event to the trace buffer.

        Example::

            writer.record({"ts": 1.0, "agent": "a1", "kind": "send", "to": "a2"})
        """
        self._buffer.append(event)
        if len(self._buffer) >= self._buffer_size:
            self.flush()

    def flush(self) -> None:
        """Flush the buffer to disk.

        Example::

            writer.flush()
        """
        for event in self._buffer:
            self._file.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        self._buffer.clear()
        self._file.flush()

    def close(self) -> None:
        """Flush remaining events and close the file.

        Example::

            writer.close()
        """
        flush_error: BaseException | None = None
        try:
            try:
                self.flush()
            except BaseException as exc:
                flush_error = exc
                raise
        finally:
            try:
                self._file.close()
            except BaseException:
                if flush_error is None:
                    raise

    def __enter__(self) -> TraceWriter:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
