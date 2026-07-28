"""Reference in-memory implementation of the AssertionStore protocol."""

from __future__ import annotations

from datetime import datetime


class MemoryAssertionStore:
    """Non-persistent AssertionStore reference implementation.

    Intended for tests and single-process use: entries are retained for the lifetime of the store
    with no expiry or bound on growth, so durable or long-running consumers should provide their
    own AssertionStore.
    """

    def __init__(self) -> None:
        """Create an empty store."""
        self._seen: dict[str, datetime] = {}

    def add(self, assertion_id: str, expires_at: datetime) -> None:
        """Record ``assertion_id`` as consumed until ``expires_at``."""
        self._seen[assertion_id] = expires_at

    def contains(self, assertion_id: str) -> bool:
        """Report whether ``assertion_id`` has already been consumed."""
        return assertion_id in self._seen
