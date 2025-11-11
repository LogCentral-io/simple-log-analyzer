"""UniFi device log parser."""

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

# UniFi syslog format: Month Day Time Host Hostname Process[PID][PID]...: Message
# Handles various formats:
# - Standard: "UniFi-Express-Gonzague systemd[1]: message"
# - AP format: "84784804e1c0,U7-IW-8.2.17+17828: syswrapper[29735][6648]: message"
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<hostname>\S+?):?\s+"  # Hostname may end with colon
    r"(?P<process>[^\[\]:]+?)(?:\[(?P<pid>\d+)\])*:\s+"  # Multiple PIDs possible
    r"(?P<message>.*)$"
)

# CEF (Common Event Format) pattern for UniFi security events
# Format: Month Day Time Host CEF:version|vendor|product|version|eventId|name|severity|extensions
CEF_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"CEF:(?P<cef_version>\d+)\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<product_version>[^|]+)\|"
    r"(?P<event_id>[^|]+)\|(?P<event_name>[^|]+)\|(?P<severity>[^|]+)\|"
    r"(?P<extensions>.*)$"
)


def _infer_log_level(message: str) -> str:
    """Infer log level from message content."""
    message_lower = message.lower()
    if any(word in message_lower for word in ["error", "failed", "failure", "critical", "fatal"]):
        return "error"
    elif any(word in message_lower for word in ["warn", "warning"]):
        return "warning"
    elif any(word in message_lower for word in ["starting", "started", "stopping", "stopped", "finished", "succeeded"]):
        return "info"
    elif "debug" in message_lower:
        return "debug"
    else:
        return "info"


def _categorize_process(process: str) -> str:
    """Categorize process into broader categories."""
    process_lower = process.lower()

    if process_lower == "unifi-security":
        return "unifi-security"
    elif "systemd" in process_lower:
        return "system"
    elif any(x in process_lower for x in ["kernel", "dmesg"]):
        return "kernel"
    elif any(x in process_lower for x in ["mcad", "stamgr", "wevent", "ubios"]):
        return "unifi-controller"
    elif any(x in process_lower for x in ["hostapd", "wpa"]):
        return "wifi"
    elif any(x in process_lower for x in ["dhcp", "dns", "named"]):
        return "network-services"
    elif any(x in process_lower for x in ["ssh", "sshd", "login"]):
        return "auth"
    else:
        return "other"


class UniFiParser(LogParser):
    """Parser for UniFi device logs."""

    @property
    def name(self) -> str:
        return "UniFi"

    def parse(
        self,
        path: Path,
        stats: ParseStats,
        advance_progress: Callable[[int], None] | None = None,
    ) -> Iterable[dict[str, str | None]]:
        """Parse UniFi syslog format."""
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                if advance_progress is not None:
                    advance_progress(len(raw_line))

                line = raw_line.rstrip("\n")
                if not line:
                    stats.note_failure("empty")
                    continue

                # Check if line is JSON data (common in UniFi logs)
                stripped = line.lstrip()
                if stripped.startswith(("{", "}", '"', "]", "[")):
                    stats.note_failure("json-data")
                    continue

                # Try CEF format first (security events)
                cef_match = CEF_PATTERN.match(line)
                if cef_match:
                    record: dict[str, str | None] = {
                        "syslog_month": cef_match["month"],
                        "syslog_day": cef_match["day"],
                        "syslog_time": cef_match["time"],
                        "host_ip": cef_match["host"],
                        "hostname": "CEF",
                        "process": "unifi-security",
                        "pid": None,
                        "message": f"{cef_match['event_name']} (severity={cef_match['severity']})",
                        "log_level": "warning" if int(cef_match["severity"]) >= 5 else "info",
                        "category": "unifi-security",
                    }
                    stats.note_success()
                    yield record
                    continue

                # Try standard syslog format
                match = SYSLOG_PATTERN.match(line)
                if not match:
                    stats.note_failure("format-mismatch")
                    continue

                message = match["message"]
                process = match["process"]

                record: dict[str, str | None] = {
                    "syslog_month": match["month"],
                    "syslog_day": match["day"],
                    "syslog_time": match["time"],
                    "host_ip": match["host"],
                    "hostname": match["hostname"],
                    "process": process,
                    "pid": match["pid"],
                    "message": message,
                    "log_level": _infer_log_level(message),
                    "category": _categorize_process(process),
                }

                stats.note_success()
                yield record

    def load_dataframe(self, path: Path, show_progress: bool = True) -> tuple[pl.DataFrame, ParseStats]:
        """Load UniFi log into DataFrame with transformations."""
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
            "hostname": pl.Utf8,
            "process": pl.Utf8,
            "pid": pl.Utf8,
            "message": pl.Utf8,
            "log_level": pl.Utf8,
            "category": pl.Utf8,
        }

        frame = pl.DataFrame(rows, schema=schema, strict=False)

        # Add timestamp parsing - assume current year for syslog timestamps
        # Since syslog doesn't include year, we'll use the file's modification time
        current_year = datetime.fromtimestamp(path.stat().st_mtime).year

        frame = frame.with_columns(
            [
                # Create timestamp string with year
                (
                    pl.lit(str(current_year))
                    + "-"
                    + pl.col("syslog_month")
                    + "-"
                    + pl.col("syslog_day")
                    + " "
                    + pl.col("syslog_time")
                ).alias("timestamp_str")
            ]
        )

        # Parse the timestamp
        frame = frame.with_columns(
            [
                pl.col("timestamp_str")
                .str.strptime(pl.Datetime, format="%Y-%b-%d %H:%M:%S", strict=False)
                .alias("timestamp")
            ]
        )

        # Add minute bucket for trend analysis
        if "timestamp" in frame.columns:
            frame = frame.with_columns([pl.col("timestamp").dt.truncate("1m").alias("minute_bucket")])

        # Convert PID to integer if present
        if "pid" in frame.columns:
            frame = frame.with_columns([pl.col("pid").cast(pl.Int32, strict=False).alias("pid")])

        # Add message length
        frame = frame.with_columns([pl.col("message").str.len_chars().alias("message_length")])

        return frame, stats
