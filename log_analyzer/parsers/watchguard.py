"""WatchGuard firewall log parser."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

import polars as pl
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TimeRemainingColumn

from . import LogParser, ParseStats

console = Console()

# WatchGuard syslog format:
# Nov  4 01:00:03 83.206.233.205 801304C6AA57D St-EgreveM370 (2025-11-04T00:00:03) loggerd[2545]: msg_id="3D01-0003" Message...
WATCHGUARD_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<device_id>\S+)\s+"
    r"(?P<device_name>\S+)\s+"
    r"\((?P<timestamp>[^)]+)\)\s+"
    r"(?P<process>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r'(?:msg_id="(?P<msg_id>[^"]+)"\s+)?'
    r"(?P<message>.*)$"
)


def _infer_log_level_from_msg_id(msg_id: str | None, message: str) -> str:
    """Infer log level from message ID and content."""
    if msg_id:
        # WatchGuard message ID format: category-severity
        # Higher first digit generally means more important
        if msg_id.startswith(('3001-', '0207-', '020B-')):  # Firewall blocks, VPN issues
            return "warning"
        elif msg_id.startswith(('4001-', '7600-')):  # Critical events
            return "error"

    # Check message content
    message_lower = message.lower()
    if any(word in message_lower for word in ["error", "failed", "failure", "critical", "fatal", "down"]):
        return "error"
    elif any(word in message_lower for word in ["warning", "block", "deny", "reject", "unknown"]):
        return "warning"
    else:
        return "info"


def _categorize_process(process: str) -> str:
    """Categorize WatchGuard process into broader categories."""
    process_lower = process.strip().lower()

    if process_lower == "firewall":
        return "firewall"
    elif process_lower in ["iked", "sslvpn"]:
        return "vpn"
    elif process_lower == "dhcpd":
        return "network-services"
    elif process_lower == "sessiond":
        return "session-management"
    elif process_lower in ["loggerd", "admd"]:
        return "system"
    elif process_lower == "sigd":
        return "security"
    elif process_lower in ["portald", "gwcd"]:
        return "gateway"
    elif process_lower in ["certd", "link-mon"]:
        return "monitoring"
    else:
        return "other"


class WatchGuardParser(LogParser):
    """Parser for WatchGuard firewall logs."""

    @property
    def name(self) -> str:
        return "WatchGuard"

    def parse(
        self,
        path: Path,
        stats: ParseStats,
        advance_progress: Callable[[int], None] | None = None,
    ) -> Iterable[dict[str, str | None]]:
        """Parse WatchGuard syslog format."""
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                if advance_progress is not None:
                    advance_progress(len(raw_line))

                line = raw_line.rstrip("\n")
                if not line:
                    stats.note_failure("empty")
                    continue

                match = WATCHGUARD_PATTERN.match(line)
                if not match:
                    stats.note_failure("format-mismatch")
                    continue

                message = match["message"]
                process = match["process"]
                msg_id = match["msg_id"]

                record: dict[str, str | None] = {
                    "syslog_month": match["month"],
                    "syslog_day": match["day"],
                    "syslog_time": match["time"],
                    "host_ip": match["host"],
                    "device_id": match["device_id"],
                    "device_name": match["device_name"],
                    "iso_timestamp": match["timestamp"],
                    "process": process,
                    "pid": match["pid"],
                    "msg_id": msg_id,
                    "message": message,
                    "log_level": _infer_log_level_from_msg_id(msg_id, message),
                    "category": _categorize_process(process),
                }

                stats.note_success()
                yield record

    def load_dataframe(
        self,
        path: Path,
        show_progress: bool = True
    ) -> tuple[pl.DataFrame, ParseStats]:
        """Load WatchGuard log into DataFrame with transformations."""
        stats = ParseStats()

        if show_progress and console.is_terminal:
            total_bytes = path.stat().st_size
            if total_bytes > 0:
                with Progress(
                    "{task.description}",
                    BarColumn(bar_width=None),
                    TaskProgressColumn(),
                    TimeRemainingColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task_id = progress.add_task("Parsing", total=total_bytes)

                    def advance(amount: int) -> None:
                        progress.advance(task_id, amount)

                    rows = list(self.parse(path, stats, advance))
                    progress.update(task_id, completed=total_bytes)
            else:
                rows = list(self.parse(path, stats))
        else:
            rows = list(self.parse(path, stats))

        if not rows:
            return pl.DataFrame(schema={}), stats

        # Define schema
        schema = {
            "syslog_month": pl.Utf8,
            "syslog_day": pl.Utf8,
            "syslog_time": pl.Utf8,
            "host_ip": pl.Utf8,
            "device_id": pl.Utf8,
            "device_name": pl.Utf8,
            "iso_timestamp": pl.Utf8,
            "process": pl.Utf8,
            "pid": pl.Utf8,
            "msg_id": pl.Utf8,
            "message": pl.Utf8,
            "log_level": pl.Utf8,
            "category": pl.Utf8,
        }

        frame = pl.DataFrame(rows, schema=schema, strict=False)

        # Parse ISO timestamp
        frame = frame.with_columns([
            pl.col("iso_timestamp")
            .str.strptime(pl.Datetime, format="%Y-%m-%dT%H:%M:%S", strict=False)
            .alias("timestamp")
        ])

        # Add minute bucket for trend analysis
        if "timestamp" in frame.columns:
            frame = frame.with_columns([
                pl.col("timestamp").dt.truncate("1m").alias("minute_bucket")
            ])

        # Convert PID to integer if present
        if "pid" in frame.columns:
            frame = frame.with_columns([
                pl.col("pid").cast(pl.Int32, strict=False).alias("pid")
            ])

        # Add message length
        frame = frame.with_columns([
            pl.col("message").str.len_chars().alias("message_length")
        ])

        return frame, stats
