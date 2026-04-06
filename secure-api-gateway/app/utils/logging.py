"""
Structured JSON logging for security events.

Why structured logging?
- Machine-parseable: feeds directly into SIEM/ELK/Splunk.
- Consistent schema: every log entry has timestamp, level, event, and optional fields.
- No regex needed: JSON keys are queryable out of the box.

In production, ship these logs to a centralized system and set up alerts
for events like "login_failed" spikes or "rate_limit_exceeded" bursts.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
            "logger": record.name,
        }
        # Merge any extra fields passed via security_logger helper
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)
        return json.dumps(log_entry, default=str)


class SecurityLogger:
    """
    Convenience wrapper that attaches arbitrary key-value pairs to log records.

    Usage:
        security_logger.warning("login_failed", username="alice", ip="1.2.3.4")
    """

    def __init__(self, name: str = "security") -> None:
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(JSONFormatter())
            self._logger.addHandler(handler)

    def _log(self, level: int, event: str, **kwargs: Any) -> None:
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=event,
            args=(),
            exc_info=None,
        )
        record.extra_fields = kwargs  # type: ignore[attr-defined]
        self._logger.handle(record)

    def info(self, event: str, **kwargs: Any) -> None:
        self._log(logging.INFO, event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, event, **kwargs)


# Module-level singleton
security_logger = SecurityLogger()
