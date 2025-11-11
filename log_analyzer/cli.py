from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

import polars as pl
import typer
from rich.console import Console
from rich.table import Table

from .parsers import ParseStats
from .parsers.palo_alto import PaloAltoParser
from .parsers.unifi import UniFiParser
from .parsers.watchguard import WatchGuardParser
from .parsers.meraki import MerakiParser

console = Console()
app = typer.Typer(help="Multi-format log analyzer supporting various network device logs")


def format_bytes(value: int | None) -> str:
    if value is None or value < 0:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


def to_table(title: str, columns: Sequence[str], rows: Sequence[Sequence[str]]) -> Table:
    table = Table(title=title, title_style="bold", show_lines=False, expand=True)
    for name in columns:
        justify = "left"
        if name.lower().endswith(("count", "bytes", "events", "score", "length")):
            justify = "right"
        table.add_column(name, justify=justify, overflow="fold")
    for row in rows:
        table.add_row(*row)
    return table


def format_trend(frame: pl.DataFrame, top: int) -> None:
    if "minute_bucket" not in frame.columns:
        return
    trend = (
        frame.filter(pl.col("minute_bucket").is_not_null())
        .group_by("minute_bucket")
        .agg(pl.len().alias("events"))
        .sort("minute_bucket")
    )
    if not len(trend):
        return

    rows = [[bucket.strftime("%Y-%m-%d %H:%M"), f"{count}"] for bucket, count in trend.iter_rows()]
    console.print(to_table("Volume per minute", ["Minute", "Events"], rows[:top]))


def render_top_counts(
    frame: pl.DataFrame,
    column: str,
    bytes_column: str = "bytes_total",
    top: int = 5,
    title: str | None = None,
) -> None:
    if column not in frame.columns:
        return

    aggregations: list[pl.Expr] = [pl.len().alias("events")]
    if bytes_column in frame.columns:
        aggregations.append(pl.col(bytes_column).sum().alias("bytes"))

    aggregation = frame.group_by(column).agg(aggregations)

    sort_keys: list[str] = ["events"]
    descending: list[bool] = [True]
    if "bytes" in aggregation.columns:
        sort_keys.append("bytes")
        descending.append(True)
    sort_keys.append(column)
    descending.append(False)

    aggregation = aggregation.sort(sort_keys, descending=descending).head(top)

    rows = []
    for values in aggregation.iter_rows(named=True):
        bytes_val = values.get("bytes")
        rows.append(
            [
                str(values[column] or "<missing>"),
                f"{values['events']}",
                format_bytes(bytes_val) if "bytes" in aggregation.columns else "",
            ]
        )

    cols = [column.replace("_", " ").title(), "Events"]
    if "bytes" in aggregation.columns:
        cols.append("Approx. Bytes")

    console.print(to_table(title or f"Top {top} by {column}", cols, rows))


def render_noise_candidates(
    frame: pl.DataFrame,
    column: str,
    threshold: float,
) -> None:
    if threshold <= 0:
        return
    if column not in frame.columns:
        return

    total_events = frame.height
    if total_events == 0:
        return

    cutoff = total_events * (threshold / 100.0)
    aggregation = (
        frame.group_by(column)
        .agg(pl.len().alias("events"))
        .with_columns((pl.col("events") / total_events * 100.0).alias("share"))
        .filter(pl.col("events") >= cutoff)
        .sort(["share", "events"], descending=[True, True])
    )

    if aggregation.is_empty():
        return

    rows = [
        [
            str(values[column] or "<missing>"),
            f"{values['events']}",
            f"{values['share']:.1f}%",
        ]
        for values in aggregation.iter_rows(named=True)
    ]

    console.print(
        to_table(
            f"Noise candidates · {column.replace('_', ' ').title()}",
            [column.replace("_", " ").title(), "Events", "Traffic Share"],
            rows,
        )
    )


@dataclass
class ReportData:
    """Collected data for analysis report."""

    source_path: Path
    generated_at: datetime
    stats: ParseStats
    parser_name: str
    sections: list[dict] = field(default_factory=list)


def collect_top_counts(
    frame: pl.DataFrame,
    column: str,
    bytes_column: str = "bytes_total",
    top: int = 5,
    title: str | None = None,
) -> dict | None:
    """Collect top counts data without rendering."""
    if column not in frame.columns:
        return None

    aggregations: list[pl.Expr] = [pl.len().alias("events")]
    if bytes_column in frame.columns:
        aggregations.append(pl.col(bytes_column).sum().alias("bytes"))

    aggregation = frame.group_by(column).agg(aggregations)

    sort_keys: list[str] = ["events"]
    descending: list[bool] = [True]
    if "bytes" in aggregation.columns:
        sort_keys.append("bytes")
        descending.append(True)
    sort_keys.append(column)
    descending.append(False)

    aggregation = aggregation.sort(sort_keys, descending=descending).head(top)

    rows = []
    for values in aggregation.iter_rows(named=True):
        bytes_val = values.get("bytes")
        row_data = {
            column: str(values[column] or "<missing>"),
            "events": values["events"],
        }
        if "bytes" in aggregation.columns:
            row_data["bytes"] = bytes_val
            row_data["bytes_formatted"] = format_bytes(bytes_val)
        rows.append(row_data)

    cols = [column.replace("_", " ").title(), "Events"]
    if "bytes" in aggregation.columns:
        cols.append("Approx. Bytes")

    return {
        "title": title or f"Top {top} by {column}",
        "columns": cols,
        "rows": rows,
    }


def collect_trend(frame: pl.DataFrame, top: int) -> dict | None:
    """Collect trend data without rendering."""
    if "minute_bucket" not in frame.columns:
        return None
    trend = (
        frame.filter(pl.col("minute_bucket").is_not_null())
        .group_by("minute_bucket")
        .agg(pl.len().alias("events"))
        .sort("minute_bucket")
    )
    if not len(trend):
        return None

    rows = [{"minute": bucket.strftime("%Y-%m-%d %H:%M"), "events": count} for bucket, count in trend.iter_rows()]
    return {
        "title": "Volume per minute",
        "columns": ["Minute", "Events"],
        "rows": rows[:top],
    }


def collect_noise_candidates(
    frame: pl.DataFrame,
    column: str,
    threshold: float,
) -> dict | None:
    """Collect noise candidates data without rendering."""
    if threshold <= 0:
        return None
    if column not in frame.columns:
        return None

    total_events = frame.height
    if total_events == 0:
        return None

    cutoff = total_events * (threshold / 100.0)
    aggregation = (
        frame.group_by(column)
        .agg(pl.len().alias("events"))
        .with_columns((pl.col("events") / total_events * 100.0).alias("share"))
        .filter(pl.col("events") >= cutoff)
        .sort(["share", "events"], descending=[True, True])
    )

    if aggregation.is_empty():
        return None

    rows = [
        {
            column: str(values[column] or "<missing>"),
            "events": values["events"],
            "share": values["share"],
        }
        for values in aggregation.iter_rows(named=True)
    ]

    return {
        "title": f"Noise candidates · {column.replace('_', ' ').title()}",
        "columns": [column.replace("_", " ").title(), "Events", "Traffic Share"],
        "rows": rows,
    }


def print_report(report: ReportData) -> None:
    """Print report to console."""
    console.print(f"[bold]Parser:[/bold] {report.parser_name}")
    console.print(f"Parsed {report.stats.parsed} records (from {report.stats.total_lines} lines).")
    if report.stats.rejected:
        rejection_details = ", ".join(f"{reason}={count}" for reason, count in report.stats.rejected.items())
        console.print(f"Skipped lines: {rejection_details}", style="yellow")

        # Add helpful note for UniFi logs with JSON data
        if "json-data" in report.stats.rejected and report.parser_name == "UniFi":
            console.print(
                "  [dim]Note: UniFi logs often include JSON configuration data (this is normal)[/dim]", style="yellow"
            )

    for section in report.sections:
        # Convert section data to table format for printing
        table_rows = []
        for row in section["rows"]:
            formatted_row = []
            for col in section["columns"]:
                col_key = col.lower().replace(" ", "_").replace(".", "")
                # Try to find the matching key in the row
                value = None
                for key in row.keys():
                    if key == col_key or key.replace("_", "") == col_key.replace("_", ""):
                        value = row[key]
                        break

                if value is None:
                    # Try alternate matching
                    if col == "Events":
                        value = row.get("events", "")
                    elif "Bytes" in col:
                        value = row.get("bytes_formatted", format_bytes(row.get("bytes")))
                    elif "Share" in col:
                        value = f"{row.get('share', 0):.1f}%"
                    elif "Length" in col:
                        value = row.get("message_length", row.get("length", ""))
                    else:
                        # Get first non-standard key
                        for k, v in row.items():
                            if k not in ["events", "bytes", "bytes_formatted", "share", "message_length", "length"]:
                                value = v
                                break

                formatted_row.append(str(value) if value is not None else "")
            table_rows.append(formatted_row)

        console.print(to_table(section["title"], section["columns"], table_rows))


def export_to_html(report: ReportData, path: Path) -> None:
    """Export report as HTML."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.parser_name} Log Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 30px; font-size: 14px; }}
        .meta strong {{ color: #333; }}
        h2 {{ color: #4CAF50; margin-top: 40px; margin-bottom: 15px; font-size: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        thead {{ background-color: #4CAF50; color: white; }}
        th {{ padding: 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #e0e0e0; }}
        tbody tr:hover {{ background-color: #f5f5f5; }}
        tbody tr:nth-child(even) {{ background-color: #fafafa; }}
        .numeric {{ text-align: right; }}
        .warning {{ background-color: #fff3cd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report.parser_name} Log Analysis Report</h1>
        <div class="meta">
            <p><strong>Source:</strong> {report.source_path.name}</p>
            <p><strong>Parser:</strong> {report.parser_name}</p>
            <p><strong>Generated:</strong> {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Records Parsed:</strong> {report.stats.parsed:,} / {report.stats.total_lines:,} total lines</p>
"""

    if report.stats.rejected:
        rejection_details = ", ".join(f"{reason}={count}" for reason, count in report.stats.rejected.items())
        html += f"            <p class='warning'><strong>Skipped Lines:</strong> {rejection_details}</p>\n"

    html += "        </div>\n"

    for section in report.sections:
        html += f"        <h2>{section['title']}</h2>\n"
        html += "        <table>\n"
        html += "            <thead><tr>"

        for col in section["columns"]:
            align_class = " class='numeric'" if any(x in col for x in ["Events", "Bytes", "Share"]) else ""
            html += f"<th{align_class}>{col}</th>"

        html += "</tr></thead>\n            <tbody>\n"

        for row in section["rows"]:
            html += "                <tr>"
            for col in section["columns"]:
                # Find matching value in row
                value = None
                numeric = any(x in col for x in ["Events", "Bytes", "Share"])

                if col == "Events":
                    value = f"{row['events']:,}"
                elif "Bytes" in col:
                    value = row.get("bytes_formatted", format_bytes(row.get("bytes")))
                elif "Share" in col:
                    value = f"{row['share']:.1f}%"
                else:
                    for k, v in row.items():
                        if k not in ["events", "bytes", "bytes_formatted", "share"]:
                            value = v
                            break

                align_class = " class='numeric'" if numeric else ""
                html += f"<td{align_class}>{value if value is not None else ''}</td>"

            html += "</tr>\n"

        html += "            </tbody>\n        </table>\n"

    html += """    </div>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")


def export_to_markdown(report: ReportData, path: Path) -> None:
    """Export report as Markdown."""
    md = f"""# {report.parser_name} Log Analysis Report

**Source:** {report.source_path.name}
**Parser:** {report.parser_name}
**Generated:** {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}
**Records Parsed:** {report.stats.parsed:,} / {report.stats.total_lines:,} total lines

"""

    if report.stats.rejected:
        rejection_details = ", ".join(f"{reason}={count}" for reason, count in report.stats.rejected.items())
        md += f"**Skipped Lines:** {rejection_details}\n\n"

    for section in report.sections:
        md += f"## {section['title']}\n\n"

        # Create table header
        md += "| " + " | ".join(section["columns"]) + " |\n"
        md += (
            "|"
            + "|".join(
                [
                    " ---: " if any(x in col for x in ["Events", "Bytes", "Share"]) else " --- "
                    for col in section["columns"]
                ]
            )
            + "|\n"
        )

        # Create table rows
        for row in section["rows"]:
            row_values = []
            for col in section["columns"]:
                if col == "Events":
                    value = f"{row['events']:,}"
                elif "Bytes" in col:
                    value = row.get("bytes_formatted", format_bytes(row.get("bytes")))
                elif "Share" in col:
                    value = f"{row['share']:.1f}%"
                else:
                    value = None
                    for k, v in row.items():
                        if k not in ["events", "bytes", "bytes_formatted", "share"]:
                            value = v
                            break
                row_values.append(str(value) if value is not None else "")

            md += "| " + " | ".join(row_values) + " |\n"

        md += "\n"

    path.write_text(md, encoding="utf-8")


def export_to_json(report: ReportData, path: Path) -> None:
    """Export report as JSON."""
    data = {
        "source": str(report.source_path),
        "parser": report.parser_name,
        "generated_at": report.generated_at.isoformat(),
        "stats": {
            "total_lines": report.stats.total_lines,
            "parsed": report.stats.parsed,
            "rejected": report.stats.rejected,
        },
        "sections": report.sections,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def export_report(report: ReportData, path: Path) -> None:
    """Export report in the appropriate format based on file extension."""
    suffix = path.suffix.lower()

    if suffix == ".html":
        export_to_html(report, path)
    elif suffix == ".md":
        export_to_markdown(report, path)
    elif suffix == ".json":
        export_to_json(report, path)
    else:
        raise typer.BadParameter(f"Unsupported export format: {suffix}. Use .html, .md, or .json")


def run_palo_analysis(
    path: Path,
    top: int,
    noise_threshold: float,
    progress: bool,
    export_path: Path | None = None,
) -> None:
    """Run analysis for Palo Alto Networks logs."""
    parser = PaloAltoParser()
    frame, stats = parser.load_dataframe(path, show_progress=progress)

    if stats.parsed == 0:
        typer.echo(f"No records parsed from {path} (checked {stats.total_lines} lines).", err=True)
        raise typer.Exit(code=1)

    # Collect all report data
    report = ReportData(
        source_path=path,
        generated_at=datetime.now(),
        stats=stats,
        parser_name=parser.name,
    )

    # Collect sections
    sections = [
        collect_top_counts(frame, "log_type", top=top, title="Log types by volume"),
        collect_top_counts(frame, "log_subtype", top=top, title="Log subtypes by volume"),
        collect_top_counts(frame, "application", top=top, title="Applications with highest event count"),
        collect_top_counts(frame, "rule_name", top=top, title="Policies generating most entries"),
        collect_top_counts(frame, "action", top=top, title="Policy actions"),
        collect_top_counts(frame, "session_end_reason", top=top, title="Session end reasons"),
        collect_top_counts(frame, "src_ip", top=top, title="Noisiest source IPs"),
        collect_top_counts(frame, "dst_ip", top=top, title="Most targeted destination IPs"),
        collect_trend(frame, top=top),
        collect_noise_candidates(frame, "rule_name", noise_threshold),
        collect_noise_candidates(frame, "src_ip", noise_threshold),
        collect_noise_candidates(frame, "dst_ip", noise_threshold),
    ]

    # Add app characteristics if available
    if "app_characteristics" in frame.columns:
        exploded = (
            frame.lazy()
            .with_columns(pl.col("app_characteristics").str.split(","))
            .explode("app_characteristics")
            .with_columns(pl.col("app_characteristics").str.strip_chars())
            .filter(pl.col("app_characteristics") != "")
            .group_by("app_characteristics")
            .agg(pl.len().alias("events"))
            .sort("events", descending=True)
            .head(top)
            .collect()
        )
        rows = [{"characteristic": value or "<blank>", "events": events} for value, events in exploded.iter_rows()]
        sections.append(
            {
                "title": "Frequent application characteristics",
                "columns": ["Characteristic", "Events"],
                "rows": rows,
            }
        )

    report.sections = [s for s in sections if s is not None]

    # Export or print
    if export_path:
        export_report(report, export_path)
        console.print(f"[green]Report exported to {export_path}[/green]")
    else:
        print_report(report)


def run_unifi_analysis(
    path: Path,
    top: int,
    noise_threshold: float,
    progress: bool,
    export_path: Path | None = None,
) -> None:
    """Run analysis for UniFi logs."""
    parser = UniFiParser()
    frame, stats = parser.load_dataframe(path, show_progress=progress)

    if stats.parsed == 0:
        typer.echo(f"No records parsed from {path} (checked {stats.total_lines} lines).", err=True)
        raise typer.Exit(code=1)

    # Collect all report data
    report = ReportData(
        source_path=path,
        generated_at=datetime.now(),
        stats=stats,
        parser_name=parser.name,
    )

    # Collect sections specific to UniFi logs
    sections = [
        collect_top_counts(frame, "log_level", top=top, title="Log levels"),
        collect_top_counts(frame, "category", top=top, title="Log categories"),
        collect_top_counts(frame, "process", top=top, title="Most active processes"),
        collect_top_counts(frame, "hostname", top=top, title="Hostnames"),
        collect_trend(frame, top=top),
        collect_noise_candidates(frame, "process", noise_threshold),
        collect_noise_candidates(frame, "category", noise_threshold),
    ]

    report.sections = [s for s in sections if s is not None]

    # Export or print
    if export_path:
        export_report(report, export_path)
        console.print(f"[green]Report exported to {export_path}[/green]")
    else:
        print_report(report)


@app.command("palo")
def palo_command(
    path: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to a Palo Alto syslog export"
    ),
    top: int = typer.Option(5, help="Number of rows to show in each summary table."),
    noise_threshold: float = typer.Option(
        5.0,
        min=0.0,
        help="Flag policies/IPs whose event count is at least this percentage of total volume.",
    ),
    progress: bool = typer.Option(
        True, "--progress/--no-progress", help="Display a progress bar while parsing the log."
    ),
    export: Path | None = typer.Option(None, "--export", "-o", help="Export report to file (.html, .md, or .json)"),
) -> None:
    """Analyse Palo Alto Networks syslog traffic logs."""
    run_palo_analysis(path, top, noise_threshold, progress, export)


@app.command("unifi")
def unifi_command(
    path: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to a UniFi device syslog export"
    ),
    top: int = typer.Option(10, help="Number of rows to show in each summary table."),
    noise_threshold: float = typer.Option(
        5.0,
        min=0.0,
        help="Flag processes/categories whose event count is at least this percentage of total volume.",
    ),
    progress: bool = typer.Option(
        True, "--progress/--no-progress", help="Display a progress bar while parsing the log."
    ),
    export: Path | None = typer.Option(None, "--export", "-o", help="Export report to file (.html, .md, or .json)"),
) -> None:
    """Analyse UniFi device syslog logs."""
    run_unifi_analysis(path, top, noise_threshold, progress, export)


def run_watchguard_analysis(
    path: Path,
    top: int,
    noise_threshold: float,
    progress: bool,
    export_path: Path | None = None,
) -> None:
    """Run analysis for WatchGuard logs."""
    parser = WatchGuardParser()
    frame, stats = parser.load_dataframe(path, show_progress=progress)

    if stats.parsed == 0:
        typer.echo(f"No records parsed from {path} (checked {stats.total_lines} lines).", err=True)
        raise typer.Exit(code=1)

    # Collect all report data
    report = ReportData(
        source_path=path,
        generated_at=datetime.now(),
        stats=stats,
        parser_name=parser.name,
    )

    # Collect sections specific to WatchGuard logs
    sections = [
        collect_top_counts(frame, "log_level", top=top, title="Log levels"),
        collect_top_counts(frame, "category", top=top, title="Log categories"),
        collect_top_counts(frame, "process", top=top, title="Most active processes"),
        collect_top_counts(frame, "msg_id", top=top, title="Most common message IDs"),
        collect_top_counts(frame, "device_name", top=top, title="Devices"),
        collect_trend(frame, top=top),
        collect_noise_candidates(frame, "process", noise_threshold),
        collect_noise_candidates(frame, "msg_id", noise_threshold),
        collect_noise_candidates(frame, "category", noise_threshold),
    ]

    report.sections = [s for s in sections if s is not None]

    # Export or print
    if export_path:
        export_report(report, export_path)
        console.print(f"[green]Report exported to {export_path}[/green]")
    else:
        print_report(report)


@app.command("watchguard")
def watchguard_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a WatchGuard firewall syslog export",
    ),
    top: int = typer.Option(10, help="Number of rows to show in each summary table."),
    noise_threshold: float = typer.Option(
        5.0,
        min=0.0,
        help="Flag processes/messages whose event count is at least this percentage of total volume.",
    ),
    progress: bool = typer.Option(
        True, "--progress/--no-progress", help="Display a progress bar while parsing the log."
    ),
    export: Path | None = typer.Option(None, "--export", "-o", help="Export report to file (.html, .md, or .json)"),
) -> None:
    """Analyse WatchGuard firewall syslog logs."""
    run_watchguard_analysis(path, top, noise_threshold, progress, export)


def run_meraki_analysis(
    path: Path,
    top: int,
    noise_threshold: float,
    progress: bool,
    export_path: Path | None = None,
) -> None:
    """Run analysis for Meraki logs."""
    parser = MerakiParser()
    frame, stats = parser.load_dataframe(path, show_progress=progress)

    if stats.parsed == 0:
        typer.echo(f"No records parsed from {path} (checked {stats.total_lines} lines).", err=True)
        raise typer.Exit(code=1)

    # Collect all report data
    report = ReportData(
        source_path=path,
        generated_at=datetime.now(),
        stats=stats,
        parser_name=parser.name,
    )

    # Collect sections specific to Meraki logs
    sections = [
        collect_top_counts(frame, "event_type", top=top, title="Event types"),
        collect_top_counts(frame, "category", top=top, title="Event categories"),
        collect_top_counts(frame, "log_level", top=top, title="Log levels"),
        collect_top_counts(frame, "protocol", top=top, title="Top protocols"),
        collect_top_counts(frame, "src", top=top, title="Top source IPs"),
        collect_top_counts(frame, "dst", top=top, title="Top destination IPs"),
        collect_top_counts(frame, "dport", top=top, title="Top destination ports"),
        collect_trend(frame, top=top),
        collect_noise_candidates(frame, "event_type", noise_threshold),
        collect_noise_candidates(frame, "src", noise_threshold),
        collect_noise_candidates(frame, "dst", noise_threshold),
    ]

    report.sections = [s for s in sections if s is not None]

    # Export or print
    if export_path:
        export_report(report, export_path)
        console.print(f"[green]Report exported to {export_path}[/green]")
    else:
        print_report(report)


@app.command("meraki")
def meraki_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a Meraki network device syslog export",
    ),
    top: int = typer.Option(10, help="Number of rows to show in each summary table."),
    noise_threshold: float = typer.Option(
        5.0,
        min=0.0,
        help="Flag event types/IPs whose count is at least this percentage of total volume.",
    ),
    progress: bool = typer.Option(
        True, "--progress/--no-progress", help="Display a progress bar while parsing the log."
    ),
    export: Path | None = typer.Option(None, "--export", "-o", help="Export report to file (.html, .md, or .json)"),
) -> None:
    """Analyse Meraki network device syslog logs."""
    run_meraki_analysis(path, top, noise_threshold, progress, export)


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
