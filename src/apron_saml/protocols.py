"""Protocols for caller-provided replay storage and time."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class AssertionStore(Protocol):
    """Caller-provided store used to detect replayed assertions.

    Implementations record consumed assertion IDs and report whether one has been seen before.
    NOTE: implementations own expiry — entries should be pruned at or after their ``expires_at``.
    """

    def add(self, assertion_id: str, expires_at: datetime) -> None:
        """Record ``assertion_id`` as consumed until ``expires_at``."""
        ...

    def contains(self, assertion_id: str) -> bool:
        """Report whether ``assertion_id`` has already been consumed."""
        ...


@runtime_checkable
class Clock(Protocol):
    """Source of the current time, injectable so time-based validation is deterministic in tests."""

    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        ...
