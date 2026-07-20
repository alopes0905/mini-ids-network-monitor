# Mini IDS / Network Security Monitor

Mini IDS is a defensive, passive, educational network security monitor written in Python. The project is intended to analyze offline PCAP files, extract packet metadata, detect simple suspicious behavior, and produce structured alerts and reports as it grows.

This repository is in the early detection implementation stage. It can read raw packets from offline PCAP files, parse individual Scapy packets into `PacketInfo`, orchestrate rules through a detection engine, and detect vertical TCP port scans and high-volume TCP connection bursts in normalized packet metadata. DNS anomaly detection, CLI commands, configuration loading, logging, and full PCAP analysis have not been implemented yet.

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
- Basic CLI command
- Basic unit tests

## Planned v1.0

The first complete version should add:

- Configurable detection thresholds
- DNS anomaly detection
- Traffic summaries
- JSON analysis reports
- Optional live capture mode
- Professional documentation
- Demo scenario
- GitHub Actions CI

## Repository Status

Current stage: Issue #14 connection burst detection.

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
- Standard project folders
- Python `.gitignore`
- Initial `requirements.txt`
- Basic package import smoke test
- MIT license

Not implemented yet:

- Traffic analysis
- DNS anomaly detection
- CLI logic
- Configuration loading
- Logging
- Detection tests

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

At this stage, the test suite covers the implemented models, PCAP reader, packet parser, mock packet data, rule interface, detection engine, port-scan rule, and connection-burst rule.

## Usage

Usage commands will be added when the CLI issue is implemented. The project does not yet analyze PCAP files.

## Documentation

- `docs/architecture.md` describes the planned high-level architecture.
- `docs/detection-rules.md` documents implemented detection semantics and limitations.
- `docs/threat-model.md` defines the defensive and ethical scope.

## Responsible Use

Use this project only with traffic captures you own or are explicitly authorized to analyze. Do not use it to inspect third-party traffic without permission.
