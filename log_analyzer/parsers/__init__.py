"""Parser modules for different log formats."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Protocol

import polars as pl


@dataclass(slots=True)
class ParseStats:
    """Statistics about parsing operations."""
    total_lines: int = 0
    parsed: int = 0
    rejected: dict[str, int] = field(default_factory=dict)

    def note_success(self) -> None:
        self.total_lines += 1
        self.parsed += 1

    def note_failure(self, reason: str) -> None:
        self.total_lines += 1
        if reason not in self.rejected:
            self.rejected[reason] = 0
        self.rejected[reason] += 1


class LogParser(ABC):
    """Base class for log parsers."""

    @abstractmethod
    def parse(
        self,
        path: Path,
        stats: ParseStats,
        advance_progress: Callable[[int], None] | None = None,
    ) -> Iterable[dict[str, str | None]]:
        """Parse log file and yield records."""
        pass

    @abstractmethod
    def load_dataframe(
        self,
        path: Path,
        show_progress: bool = True
    ) -> tuple[pl.DataFrame, ParseStats]:
        """Load log file into a Polars DataFrame with transformations."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the parser name."""
        pass
