# SPDX-License-Identifier: Apache-2.0
"""Optional structured logging for Nanda Town (enabled via NEST_LOG env var).
Example::
    export NEST_LOG=debug
    nest run marketplace
"""

from __future__ import annotations

import logging
import os
from typing import Any

_configured = False


def configure_logging() -> None:
    """Configure structlog once based on ``NEST_LOG`` (default: warnings only)."""
    global _configured  # noqa: PLW0603
    if _configured:
        return
    _configured = True
    level_name = os.environ.get("NEST_LOG", "").strip().lower()
    if not level_name:
        logging.basicConfig(level=logging.WARNING)
        return
    level = getattr(logging, level_name.upper(), logging.INFO)
    try:
        import structlog

        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    except ImportError:
        logging.basicConfig(level=level)


def reset_logging_for_tests() -> None:
    """Reset logging configuration (tests only)."""
    global _configured  # noqa: PLW0603
    _configured = False
    try:
        import structlog

        structlog.reset_defaults()
    except ImportError:
        pass


def get_logger(name: str) -> Any:
    """Return a structlog logger when ``NEST_LOG`` is set, else stdlib logging."""
    configure_logging()
    level_name = os.environ.get("NEST_LOG", "").strip().lower()
    if not level_name:
        return logging.getLogger(name)
    try:
        import structlog

        return structlog.get_logger(name)
    except ImportError:
        return logging.getLogger(name)


class LazyLogger:
    """Resolve the active logger on each call so ``NEST_LOG`` changes apply."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, item: str) -> Any:
        return getattr(get_logger(self._name), item)
