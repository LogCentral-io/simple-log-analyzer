from __future__ import annotations

from datetime import datetime
from pathlib import Path

from log_analyzer.cli import ReportData, export_to_html, export_to_markdown
from log_analyzer.parsers import ParseStats


def _report(source_path: Path) -> ReportData:
    return ReportData(
        source_path=source_path,
        generated_at=datetime(2026, 6, 2, 12, 30, 0),
        stats=ParseStats(total_lines=2, parsed=1, rejected={"bad<reason>": 1}),
        parser_name="Parser <Name>",
        sections=[
            {
                "title": "Suspicious <section>",
                "columns": ["Message", "Events", "Traffic Share"],
                "rows": [
                    {
                        "message": '<script>alert("x")</script>|pipe\nnext',
                        "events": 1,
                        "share": 50.0,
                    }
                ],
            }
        ],
    )


def test_html_export_escapes_untrusted_report_values(tmp_path: Path) -> None:
    output_path = tmp_path / "report.html"

    export_to_html(_report(Path("source<file>.log")), output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "source&lt;file&gt;.log" in html
    assert "Parser &lt;Name&gt;" in html
    assert "Suspicious &lt;section&gt;" in html
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;|pipe" in html
    assert "bad&lt;reason&gt;=1" in html
    assert "<td class='numeric'>1</td>" in html
    assert "<td class='numeric'>50.0%</td>" in html


def test_markdown_export_escapes_table_content(tmp_path: Path) -> None:
    output_path = tmp_path / "report.md"

    export_to_markdown(_report(Path("source<file>.log")), output_path)

    markdown = output_path.read_text(encoding="utf-8")
    assert "<script>" not in markdown
    assert "**Source:** source&lt;file&gt;.log" in markdown
    assert "# Parser &lt;Name&gt; Log Analysis Report" in markdown
    assert "## Suspicious &lt;section&gt;" in markdown
    assert '&lt;script&gt;alert("x")&lt;/script&gt;\\|pipe<br>next' in markdown
    assert "bad&lt;reason&gt;=1" in markdown
    assert '| &lt;script&gt;alert("x")&lt;/script&gt;\\|pipe<br>next | 1 | 50.0% |' in markdown
