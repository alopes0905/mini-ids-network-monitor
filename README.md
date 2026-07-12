# Mini IDS / Network Security Monitor

Mini IDS is a defensive, passive, educational network security monitor written in Python. The project is intended to analyze offline PCAP files, extract packet metadata, detect simple suspicious behavior, and produce structured alerts and reports as it grows.

This repository is at the initial scaffold stage. Packet parsing, detection logic, CLI commands, configuration loading, logging, and tests have not been implemented yet.

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

Current stage: Issue #0 and Issue #1 scaffold.

Implemented now:

- Initial repository structure
- README skeleton
- Architecture placeholder
- Threat model placeholder
- Python package folder
- Standard project folders
- Python `.gitignore`
- Initial `requirements.txt`
- MIT license

Not implemented yet:

- Packet parsing
- Detection rules
- CLI logic
- Configuration loading
- Logging
- Tests

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

Dependency installation will be finalized in the environment setup issue. The initial expected dependencies are listed in `requirements.txt`.

## Usage

Usage commands will be added when the CLI issue is implemented.

## Documentation

- `docs/architecture.md` describes the planned high-level architecture.
- `docs/threat-model.md` defines the defensive and ethical scope.

## Responsible Use

Use this project only with traffic captures you own or are explicitly authorized to analyze. Do not use it to inspect third-party traffic without permission.
