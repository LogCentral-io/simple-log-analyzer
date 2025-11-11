"""Palo Alto Networks log parser."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Callable, Iterable

import polars as pl
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TimeRemainingColumn

from . import LogParser, ParseStats

console = Console()

SYSLOG_PREFIX = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+")

FIELD_ALIASES: dict[int, str] = {
    0: "future_use",
    1: "receive_time",
    2: "serial_number",
    3: "log_type",
    4: "log_subtype",
    5: "config_version",
    6: "generated_time",
    7: "src_ip",
    8: "dst_ip",
    9: "nat_src_ip",
    10: "nat_dst_ip",
    11: "rule_name",
    12: "src_user",
    13: "dst_user",
    14: "application",
    15: "vsys",
    16: "src_zone",
    17: "dst_zone",
    18: "inbound_interface",
    19: "outbound_interface",
    20: "log_action",
    21: "logged_time",
    22: "session_id",
    23: "repeat_count",
    24: "src_port",
    25: "dst_port",
    26: "nat_src_port",
    27: "nat_dst_port",
    28: "flags",
    29: "protocol",
    30: "action",
    31: "bytes_total",
    32: "bytes_sent",
    33: "bytes_received",
    34: "packets",
    35: "session_start_time",
    36: "elapsed_time",
    37: "category",
    38: "padding",
    39: "seqno",
    40: "action_flags",
    41: "src_country",
    42: "dst_country",
    44: "packets_sent",
    45: "packets_received",
    46: "session_end_reason",
    47: "device_group",
    52: "device_name",
    53: "policy_type",
    55: "monitor_tag",
    56: "parent_session_id",
    57: "parent_start_time",
    60: "http2_connection_id",
    65: "rule_uuid",
    102: "generated_timestamp",
    105: "app_family",
    106: "app_technology",
    107: "app_risk_level",
    108: "app_risk_score",
    109: "app_characteristics",
    110: "app_subcategory",
    111: "app_identifier",
    112: "app_tunneled",
    113: "app_is_saas",
    114: "app_risk_category",
    115: "app_tunnel_category",
}


def _normalise_field(value: str) -> str | None:
    value = value.strip()
    return value or None


class PaloAltoParser(LogParser):
    """Parser for Palo Alto Networks traffic logs."""

    @property
    def name(self) -> str:
        return "Palo Alto Networks"

    def parse(
        self,
        path: Path,
        stats: ParseStats,
        advance_progress: Callable[[int], None] | None = None,
    ) -> Iterable[dict[str, str | None]]:
        """Parse Palo Alto Networks syslog format."""
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                if advance_progress is not None:
                    advance_progress(len(raw_line))

                line = raw_line.rstrip("\n")
                if not line:
                    stats.note_failure("empty")
                    continue

                prefix = SYSLOG_PREFIX.match(line)
                if not prefix:
                    stats.note_failure("missing-prefix")
                    continue

                rest = line[prefix.end() :]
                try:
                    fields = next(csv.reader([rest]))
                except csv.Error as exc:
                    stats.note_failure(f"csv-error: {exc}")
                    continue

                record: dict[str, str | None] = {
                    "syslog_host": prefix["host"],
                    "syslog_month": prefix["month"],
                    "syslog_day": prefix["day"],
                    "syslog_time": prefix["time"],
                }

                for index, alias in FIELD_ALIASES.items():
                    if index < len(fields):
                        record[alias] = _normalise_field(fields[index])

                stats.note_success()
                yield record

    def load_dataframe(self, path: Path, show_progress: bool = True) -> tuple[pl.DataFrame, ParseStats]:
        """Load Palo Alto log into DataFrame with transformations."""
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

        base_columns = [
            "syslog_host",
            "syslog_month",
            "syslog_day",
            "syslog_time",
        ]
        base_columns.extend(dict.fromkeys(FIELD_ALIASES.values()))

        seen = set(base_columns)
        ordered_columns: list[str] = [col for col in base_columns if col is not None]
        for row in rows:
            for key in row.keys():
                if key not in seen:
                    ordered_columns.append(key)
                    seen.add(key)

        schema = {column: pl.Utf8 for column in ordered_columns}
        frame = pl.DataFrame(rows, schema=schema, strict=False)

        transformations = []
        if "receive_time" in frame.columns:
            transformations.append(
                pl.col("receive_time")
                .str.strptime(pl.Datetime, format="%Y/%m/%d %H:%M:%S", strict=False)
                .alias("receive_time_ts")
            )
        if "generated_time" in frame.columns:
            transformations.append(
                pl.col("generated_time")
                .str.strptime(pl.Datetime, format="%Y/%m/%d %H:%M:%S", strict=False)
                .alias("generated_time_ts")
            )
        if "session_start_time" in frame.columns:
            transformations.append(
                pl.col("session_start_time")
                .str.strptime(pl.Datetime, format="%Y/%m/%d %H:%M:%S", strict=False)
                .alias("session_start_ts")
            )
        if "generated_timestamp" in frame.columns:
            transformations.append(
                pl.col("generated_timestamp")
                .str.to_datetime(time_zone="UTC", strict=False)
                .alias("generated_timestamp_ts")
            )

        numeric_columns = [
            "bytes_total",
            "bytes_sent",
            "bytes_received",
            "packets",
            "packets_sent",
            "packets_received",
            "elapsed_time",
            "app_risk_score",
        ]

        for column in numeric_columns:
            if column in frame.columns:
                transformations.append(
                    pl.col(column)
                    .cast(pl.Utf8)
                    .str.replace_all(",", "")
                    .str.strip_chars()
                    .replace("", None)
                    .cast(pl.Int64, strict=False)
                    .alias(column)
                )

        if transformations:
            frame = frame.with_columns(transformations)

        if "receive_time_ts" in frame.columns:
            frame = frame.with_columns(pl.col("receive_time_ts").dt.truncate("1m").alias("minute_bucket"))

        return frame, stats
