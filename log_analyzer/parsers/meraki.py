"""Meraki network device log parser."""

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

# Meraki syslog format:
# Nov  5 00:00:04 90.102.85.18 1 1762300804.143040390 ROUTER ip_flow_end src=10.10.0.102 dst=35.153.85.208 ...
MERAKI_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<timestamp>[\d.]+)\s+"
    r"(?P<device_type>\S+)\s+"
    r"(?P<event_type>\S+)\s+"
    r"(?P<message>.*)$"
)


def _parse_key_value_pairs(text: str) -> dict[str, str]:
    """Parse key=value pairs from Meraki log messages."""
    pairs = {}
    # Pattern for key=value or key: value
    pattern = re.compile(r'(\w+)[:=]([^\s]+)')
    for match in pattern.finditer(text):
        key, value = match.groups()
        pairs[key] = value
    return pairs


def _infer_log_level(event_type: str, message: str) -> str:
    """Infer log level from event type and message content."""
    if event_type == "firewall":
        if "deny" in message.lower() or "block" in message.lower():
            return "warning"
        return "info"
    elif event_type == "events":
        if "error" in message.lower() or "fail" in message.lower():
            return "error"
        return "info"
    elif event_type in ["ip_flow_start", "ip_flow_end"]:
        return "info"
    elif event_type == "urls":
        return "info"
    else:
        return "info"


def _categorize_event(event_type: str, message: str) -> str:
    """Categorize Meraki event into broader categories."""
    if event_type in ["ip_flow_start", "ip_flow_end"]:
        return "network-flow"
    elif event_type == "urls":
        return "web-security"
    elif event_type == "firewall":
        return "firewall"
    elif event_type == "events":
        if "dhcp" in message.lower():
            return "dhcp"
        return "system-events"
    else:
        return "other"


class MerakiParser(LogParser):
    """Parser for Meraki network device logs."""

    @property
    def name(self) -> str:
        return "Meraki"

    def parse(
        self,
        path: Path,
        stats: ParseStats,
        advance_progress: Callable[[int], None] | None = None,
    ) -> Iterable[dict[str, str | None]]:
        """Parse Meraki syslog format."""
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                if advance_progress is not None:
                    advance_progress(len(raw_line))

                line = raw_line.rstrip("\n")
                if not line:
                    stats.note_failure("empty")
                    continue

                match = MERAKI_PATTERN.match(line)
                if not match:
                    stats.note_failure("format-mismatch")
                    continue

                event_type = match["event_type"]
                message = match["message"]

                # Parse key-value pairs from message
                kv_pairs = _parse_key_value_pairs(message)

                record: dict[str, str | None] = {
                    "syslog_month": match["month"],
                    "syslog_day": match["day"],
                    "syslog_time": match["time"],
                    "host_ip": match["host"],
                    "priority": match["priority"],
                    "epoch_timestamp": match["timestamp"],
                    "device_type": match["device_type"],
                    "event_type": event_type,
                    "message": message,
                    "log_level": _infer_log_level(event_type, message),
                    "category": _categorize_event(event_type, message),
                }

                # Add common key-value pairs
                for key in ["src", "dst", "protocol", "sport", "dport", "mac",
                           "translated_src_ip", "translated_port", "pattern"]:
                    record[key] = kv_pairs.get(key)

                stats.note_success()
                yield record

    def load_dataframe(
        self,
        path: Path,
        show_progress: bool = True
    ) -> tuple[pl.DataFrame, ParseStats]:
        """Load Meraki log into DataFrame with transformations."""
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
            "priority": pl.Utf8,
            "epoch_timestamp": pl.Utf8,
            "device_type": pl.Utf8,
            "event_type": pl.Utf8,
            "message": pl.Utf8,
            "log_level": pl.Utf8,
            "category": pl.Utf8,
            "src": pl.Utf8,
            "dst": pl.Utf8,
            "protocol": pl.Utf8,
            "sport": pl.Utf8,
            "dport": pl.Utf8,
            "mac": pl.Utf8,
            "translated_src_ip": pl.Utf8,
            "translated_port": pl.Utf8,
            "pattern": pl.Utf8,
        }

        frame = pl.DataFrame(rows, schema=schema, strict=False)

        # Parse epoch timestamp to datetime
        frame = frame.with_columns([
            pl.col("epoch_timestamp")
            .cast(pl.Float64, strict=False)
            .cast(pl.Int64)  # Convert to microseconds
            .mul(1_000_000)
            .cast(pl.Datetime("us"), strict=False)
            .alias("timestamp")
        ])

        # Add minute bucket for trend analysis
        if "timestamp" in frame.columns:
            frame = frame.with_columns([
                pl.col("timestamp").dt.truncate("1m").alias("minute_bucket")
            ])

        # Convert ports to integers
        for port_col in ["sport", "dport", "translated_port"]:
            if port_col in frame.columns:
                frame = frame.with_columns([
                    pl.col(port_col).cast(pl.Int32, strict=False).alias(port_col)
                ])

        # Add message length
        frame = frame.with_columns([
            pl.col("message").str.len_chars().alias("message_length")
        ])

        return frame, stats
