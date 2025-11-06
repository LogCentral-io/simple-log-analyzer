# Simple - Multi-Format - Log Analyzer

<img width="1536" height="1024" alt="image-log-analyzer" src="https://github.com/user-attachments/assets/2beb17c1-025e-4f13-bc85-7f402836d49b" />


A high-performance Python tool for analyzing syslog files from various network devices. Built with Polars for fast processing of large log files.

## Supported Log Formats

- **Palo Alto Networks** - Firewall traffic logs
- **UniFi** - Ubiquiti network device logs (including CEF security events)
- **WatchGuard** - Firewall and security appliance logs
- **Meraki** - Cisco Meraki network device logs (MX, MS, MR)
- **Extensible** - Easy to add new log format parsers

## Features

- **Fast parsing** - Process millions of log entries efficiently using Polars
- **Multi-format support** - Analyze logs from different vendors with format-specific parsers
- **Comprehensive analysis** - Automatic identification of:
  - Top traffic sources and destinations
  - Most active applications and policies
  - Session end reasons and patterns
  - Traffic volume trends over time
  - Noise candidates (high-volume sources/destinations/policies)
  - Process and category analysis (UniFi)
  - Application characteristics (Palo Alto)
- **Multiple export formats** - Generate reports in HTML, Markdown, or JSON
- **Progress tracking** - Visual progress bar for large files
- **Flexible filtering** - Configurable top-N results and noise thresholds

## Installation

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Using uv (recommended)

```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
uv sync
```

### Using pip

```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
pip install -e .
```

## Usage

The log analyzer uses subcommands for different log formats:

```bash
log-analyzer <format> [OPTIONS] <logfile>
```

Available formats:
- `palo` - Palo Alto Networks logs
- `unifi` - UniFi device logs
- `watchguard` - WatchGuard firewall logs
- `meraki` - Meraki network device logs

### Basic Analysis

**Palo Alto Networks:**
```bash
uv run log-analyzer palo path/to/palo-alto.log
```

**UniFi Devices:**
```bash
uv run log-analyzer unifi path/to/unifi.log
```

**WatchGuard Firewall:**
```bash
uv run log-analyzer watchguard path/to/watchguard.log
```

**Meraki Network Devices:**
```bash
uv run log-analyzer meraki path/to/meraki.log
```

### Export Reports

Export analysis to HTML (recommended for sharing):

```bash
uv run log-analyzer unifi path/to/unifi.log --export report.html
```

Export to Markdown:

```bash
uv run log-analyzer palo path/to/palo-alto.log --export report.md
```

Export to JSON (for programmatic access):

```bash
uv run log-analyzer unifi path/to/unifi.log --export report.json
```

### Advanced Options

```bash
uv run log-analyzer palo path/to/palo-alto.log \
  --top 20 \
  --noise-threshold 10.0 \
  --export report.html
```

## Command Line Options

### Common Options (all formats)

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--top` | | 5-10* | Number of rows to show in each summary table |
| `--noise-threshold` | | 5.0 | Flag entities whose event count is at least this percentage of total volume |
| `--progress` / `--no-progress` | | `--progress` | Display a progress bar while parsing |
| `--export` | `-o` | None | Export report to file (.html, .md, or .json) |

*Default is 5 for Palo Alto, 10 for UniFi

## Report Sections

### Palo Alto Networks Reports

1. **Log Types by Volume** - Distribution of traffic, system, and config logs
2. **Log Subtypes** - Breakdown of log subtypes (end, drop, deny, etc.)
3. **Top Applications** - Applications generating the most traffic
4. **Top Policies** - Firewall rules with the highest hit counts
5. **Policy Actions** - Distribution of allow/deny/reset actions
6. **Session End Reasons** - Why sessions terminated (aged-out, tcp-fin, etc.)
7. **Source IPs** - Noisiest traffic sources
8. **Destination IPs** - Most targeted destinations
9. **Volume Trends** - Events per minute over time
10. **Noise Candidates** - High-volume entities that may need filtering
11. **Application Characteristics** - Security attributes of applications

### UniFi Reports

1. **Log Levels** - Distribution of info, error, warning, debug messages
2. **Log Categories** - System, kernel, wifi, network-services, etc.
3. **Most Active Processes** - Processes generating the most log entries
4. **Hostnames** - Active UniFi devices in your network
5. **Volume Trends** - Events per minute over time
6. **Noise Candidates** - High-volume processes and categories

### WatchGuard Reports

1. **Log Levels** - Distribution of info, warning, error messages
2. **Log Categories** - Firewall, VPN, network-services, system, security, etc.
3. **Most Active Processes** - dhcpd, loggerd, sessiond, firewall, iked, etc.
4. **Message IDs** - Most common WatchGuard message identifiers
5. **Devices** - Active WatchGuard appliances
6. **Volume Trends** - Events per minute over time
7. **Noise Candidates** - High-volume processes, message IDs, and categories

### Meraki Reports

1. **Event Types** - ip_flow_start, ip_flow_end, urls, firewall, events
2. **Event Categories** - Network flows, web security, DHCP, firewall, system events
3. **Log Levels** - Distribution of info, warning, error messages
4. **Top Protocols** - TCP, UDP, ICMP traffic distribution
5. **Top Source/Destination IPs** - Most active internal and external hosts
6. **Top Destination Ports** - Most accessed services
7. **Volume Trends** - Events per minute over time
8. **Noise Candidates** - High-volume event types, source/destination IPs

## Log Formats

### Palo Alto Networks

Standard syslog-formatted traffic logs with the syslog prefix:

```
Nov 4 11:08:44 109.2.165.203 1,2025/11/04 11:08:44,026701019653,TRAFFIC,end,...
```

### UniFi

Standard syslog format from UniFi devices:

```
Nov 4 01:00:00 78.196.139.136 UniFi-Express-Gonzague systemd[1]: Starting service...
```

Also supports CEF (Common Event Format) security events:

```
Nov 4 01:22:08 78.196.139.136 CEF:0|Ubiquiti|UniFi Network|10.0.140|400|WiFi Client Connected|1|...
```

### WatchGuard

WatchGuard syslog format with device ID, name, ISO timestamp, and message ID:

```
Nov 4 01:00:03 83.206.233.205 801304C6AA57D St-EgreveM370 (2025-11-04T00:00:03) firewall: msg_id="3001-1001" Temporarily blocking host...
```

### Meraki

Meraki syslog format with epoch timestamp and key-value pairs:

```
Nov 5 00:00:04 90.102.85.18 1 1762300804.143040390 ROUTER ip_flow_end src=10.10.0.102 dst=35.153.85.208 protocol=udp sport=1043 dport=9930...
```

Supports event types:
- **ip_flow_start/end** - Network flow tracking
- **urls** - Web content filtering
- **firewall** - Firewall rule actions
- **events** - DHCP and system events

## Performance

- **1M+ records per minute** - Processed 1,044,470 Meraki records in ~60 seconds
- **Memory-efficient** - Streaming parser handles large files
- **Optimized** - Polars-based aggregations for speed
- **100% parse rates** - Meraki (1M+ lines), WatchGuard (43K lines), UniFi (7.6K lines, 99.3%)

## Examples

### Quick Analysis

```bash
# Analyze Palo Alto logs
uv run log-analyzer palo firewall.log

# Analyze UniFi logs
uv run log-analyzer unifi unifi-device.log
```

### Generate HTML Report

```bash
# Create a detailed HTML report with top 10 entries per section
uv run log-analyzer palo firewall.log --top 10 -o analysis-report.html

# Generate UniFi report
uv run log-analyzer unifi unifi-device.log --top 20 -o unifi-report.html
```

### Identify Major Traffic Sources

```bash
# Lower noise threshold to catch more potential issues (Palo Alto)
uv run log-analyzer palo firewall.log --noise-threshold 2.0 --top 15

# Find noisy processes in UniFi logs
uv run log-analyzer unifi unifi.log --noise-threshold 3.0 --top 20

# Analyze WatchGuard firewall blocks
uv run log-analyzer watchguard watchguard.log --noise-threshold 5.0
```

### Silent Processing

```bash
# Disable progress bar for scripting
uv run log-analyzer palo firewall.log --no-progress -o report.json
uv run log-analyzer unifi unifi.log --no-progress -o report.json
```

## Output Examples

### Console Output

```
Parsed 3,169,590 records (from 3,169,590 lines).

                              Log types by volume
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Log Type              ┃             Events ┃                   Approx. Bytes ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ TRAFFIC               │          3,165,105 │                         69.6 GB │
│ SYSTEM                │              4,467 │                           0.0 B │
│ CONFIG                │                 18 │                           0.0 B │
└───────────────────────┴────────────────────┴─────────────────────────────────┘
```

### HTML Report

The HTML export includes:
- Professional styling with responsive tables
- Color-coded sections
- Hover effects for better readability
- Summary statistics
- Mobile-friendly layout

## Development

### Project Structure

```
log-analyzer/
├── log_analyzer/
│   ├── __init__.py
│   ├── cli.py                    # Main CLI and analysis logic
│   └── parsers/
│       ├── __init__.py           # Base parser classes
│       ├── palo_alto.py          # Palo Alto parser
│       ├── unifi.py              # UniFi parser
│       ├── watchguard.py         # WatchGuard parser
│       └── meraki.py             # Meraki parser
├── pyproject.toml                # Project configuration
├── README.md
└── .gitignore
```

### Adding New Log Formats

To add support for a new log format:

1. Create a new parser in `log_analyzer/parsers/your_format.py`
2. Inherit from the `LogParser` base class
3. Implement the `parse()` and `load_dataframe()` methods
4. Add a new subcommand in `cli.py`
5. Create format-specific analysis sections

See existing parsers (`palo_alto.py`, `unifi.py`) for examples.

### Running Tests

```bash
# Install development dependencies
uv sync --all-extras

# Run tests (if available)
pytest
```

### Code Style

This project uses:
- Type hints throughout
- Dataclasses for structured data
- Polars for high-performance data processing
- Rich for beautiful console output
- Typer for CLI interface

## Troubleshooting

### "No records parsed" error

- **Wrong format?** - Make sure you're using the correct subcommand (`palo` vs `unifi`)
- **Verify log format** - Check that the file matches the expected format for the parser
- **Syslog prefix** - Ensure logs have the standard syslog prefix
- **File corruption** - Verify the file is not corrupted or empty

Try running with `--help` on the subcommand for format-specific details:
```bash
uv run log-analyzer palo --help
uv run log-analyzer unifi --help
```

### Many skipped lines

Some lines may be skipped if they don't match the expected format:
- Check the "Skipped lines" summary in the output
- `format-mismatch` - Lines that don't match the parser's expected pattern
- `empty` - Blank lines in the file
- `missing-prefix` - Lines without proper syslog prefix

A small number of skipped lines is normal, but if most lines are skipped, you may be using the wrong parser.

### Out of memory errors

- Process smaller log files or split large files
- Increase system memory
- Use `--no-progress` to reduce memory overhead

### Slow performance

- Ensure you're using Polars (not pandas)
- Check disk I/O performance
- Try running on files stored on SSD rather than network drives

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Polars](https://pola.rs/) for fast DataFrame operations
- Uses [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- CLI powered by [Typer](https://typer.tiangolo.com/)

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.
