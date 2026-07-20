# Mini IDS / Network Security Monitor

Mini IDS is a defensive, passive, educational network security monitor written in Python. The project is intended to analyze offline PCAP files, extract packet metadata, detect simple suspicious behavior, and produce structured alerts and reports as it grows.

This repository now has a configurable end-to-end offline analysis workflow. Its Typer CLI can read and parse a PCAP, run vertical TCP port-scan and connection-burst rules, render alerts and engine statistics with Rich, and optionally write packet and alert JSONL logs. YAML configuration can enable, disable, and tune the two implemented rules. DNS anomaly detection, aggregate reporting, and live capture have not been implemented yet.

## Project Vision

Build a small but serious network security project that is understandable to a Computer Science student, useful for learning defensive monitoring concepts, and suitable for a cybersecurity portfolio.

## Defensive Scope

Mini IDS is not an offensive tool. It is designed for passive analysis of traffic captures from systems and networks the user is authorized to inspect.

The project will not include:

- Packet injection
- Exploitation
- Brute-force tooling
- Credential extraction
- Malware behavior
- Payload stealing
- Automatic attack execution
- Firewall modification as a first-version feature
- Offensive scanning modules

## Planned MVP

The first functional MVP should include:

- Offline PCAP analysis
- Packet metadata model
- Alert model
- PCAP reader
- Packet parser
- Detection rule interface
- Detection engine
- Port scan detection
- Connection burst detection
- JSONL alert logging
- Human-readable terminal output
- Basic CLI command
- Basic unit tests

## Planned v1.0

The first complete version should add:

- DNS anomaly detection
- Traffic summaries
- JSON analysis reports
- Optional live capture mode
- Professional documentation
- Demo scenario
- GitHub Actions CI

## Repository Status

Current stage: Issue #17 YAML configuration support.

Implemented now:

- Initial repository structure
- README skeleton
- High-level architecture documentation
- Threat model placeholder
- Python package folder
- `PacketInfo` packet metadata model
- `Alert` structured alert model
- Offline PCAP reader for raw Scapy packets
- Packet parser for individual Scapy packets
- Mock `PacketInfo` fixtures and example packet metadata
- Abstract detection rule interface
- Detection engine orchestration and basic statistics
- Vertical TCP SYN port-scan detection
- TCP connection-burst detection by source IP
- Independent packet and alert JSONL persistence
- Rich terminal presentation for alerts and engine summaries
- Basic `analyze --pcap` CLI workflow
- Typed YAML configuration for current rule settings
- 261-case test suite with 99% statement coverage
- Standard project folders
- Python `.gitignore`
- Initial `requirements.txt`
- Basic package import smoke test
- MIT license

Not implemented yet:

- DNS anomaly detection
- Traffic summaries and aggregate reports
- Live capture

## Project Structure

```text
mini-ids-network-monitor/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── mini_ids/
├── docs/
├── tests/
├── examples/
├── pcaps/
├── logs/
└── reports/
```

## Setup

Python 3.11 or newer is recommended.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the initial development dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Verify that the package can be imported:

```bash
python -c "import mini_ids; print('ok')"
```

Run the current test suite:

```bash
python -m pytest
```

Run the suite with statement coverage:

```bash
python -m pytest --cov=mini_ids --cov-report=term-missing
```

The current snapshot contains 261 passing test cases with 99% statement coverage. It covers the implemented models, PCAP reader, packet parser, mock packet data, rule interface, detection engine, both detection rules, YAML configuration, JSONL persistence, console presentation, CLI workflow, and a public-API pipeline integration test. See [`docs/testing-report.md`](docs/testing-report.md) for module results and testing limitations.

## Usage

Show application or command help:

```bash
python3 -m mini_ids.cli --help
python3 -m mini_ids.cli analyze --help
```

Analyze an offline PCAP with the default port-scan and connection-burst rules:

```bash
python3 -m mini_ids.cli analyze --pcap /path/to/capture.pcap
```

Optionally write parsed packets and generated alerts as separate JSONL files:

```bash
python3 -m mini_ids.cli analyze \
  --pcap /path/to/capture.pcap \
  --packet-log logs/packets.jsonl \
  --alert-log logs/alerts.jsonl
```

Log files are created only when their option is supplied. Parent directories are created automatically, and each requested file is overwritten for the new analysis run rather than appended.

Configuration is optional. Without `--config`, both rules use their existing defaults. To load a YAML file:

```bash
python3 -m mini_ids.cli analyze \
  --pcap /path/to/capture.pcap \
  --config examples/config.example.yaml
```

Supported schema:

```yaml
rules:
  port_scan:
    enabled: true
    port_threshold: 10
    time_window_seconds: 60

  connection_burst:
    enabled: true
    connection_threshold: 50
    time_window_seconds: 60
```

Sections and fields may be omitted to retain defaults. A rule is disabled with `enabled: false`. Alert conditions are strictly greater than their thresholds: defaults alert on the 11th distinct destination port or the 51st initial connection attempt within 60 seconds. Unknown fields, unknown rules, malformed YAML, and invalid values fail clearly.

Only port-scan and connection-burst rules are configurable. DNS anomaly detection, traffic-summary or final-report generation, and live capture are not implemented.

## Documentation

- `docs/architecture.md` describes the high-level architecture.
- `docs/detection-rules.md` documents implemented detection semantics and limitations.
- `docs/testing-report.md` records current coverage and testing limitations.
- `docs/threat-model.md` defines the defensive and ethical scope.

## Responsible Use

Use this project only with traffic captures you own or are explicitly authorized to analyze. Do not use it to inspect third-party traffic without permission.
