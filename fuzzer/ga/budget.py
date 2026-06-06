from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RequestBudget:
    """Bounds the total number of GraphQL requests a run may issue.

    ``total=None`` means unbounded. The same budget instance is shared across the
    surface probe, all chromosome executions, prerequisite fills, and replays so
    the cap is global to the run.
    """

    total: int | None = None
    spent: int = 0

    @property
    def exhausted(self) -> bool:
        return self.total is not None and self.spent >= self.total

    def can_spend(self, n: int = 1) -> bool:
        if self.total is None:
            return True
        return self.spent + n <= self.total

    def spend(self, n: int = 1) -> None:
        self.spent += n

    def remaining(self) -> float:
        if self.total is None:
            return float("inf")
        return max(0, self.total - self.spent)
