# Mini IDS / Network Security Monitor

Mini IDS is a lightweight defensive Python project for analyzing offline PCAP files. It converts raw packets into normalized metadata, runs stateful detection rules, produces structured alerts, and presents the result through Rich terminal output, JSONL event logs, traffic statistics, and a complete JSON analysis report.

The project is designed for network-security learning and portfolio demonstration. It favors explicit rule semantics, testable module boundaries, reproducible synthetic traffic, and measured claims over production IDS complexity.

| Project status | Current state |
| --- | --- |
| Development | Active, preparing for v1.0 |
| Primary mode | Offline PCAP analysis |
| Live capture | Not implemented |

## Key Features

- Offline PCAP ingestion with Scapy; no root privileges required
- Normalization of TCP, UDP, ICMP, DNS, and `OTHER` packets into `PacketInfo`
- Modular `DetectionRule` contract and stateful `DetectionEngine`
- Vertical TCP SYN port-scan detection
- TCP connection-attempt burst detection
- DNS query-burst, unique-domain, and long-domain anomaly checks
- Strict optional YAML configuration with per-rule enable/disable controls
- Rich terminal alerts, detection totals, and aggregate traffic summaries
- Independent packet and alert JSONL output
- Complete JSON analysis reports with UTC timestamps, summaries, and alerts
- Deterministic synthetic PCAPs for demonstrations and regression tests
- 465 automated tests with 99% statement coverage

## Detection Overview

All current rules inspect normalized metadata, not packet payloads. Default conditions are strictly greater than their configured thresholds.

| Rule | Default condition | Severity | MITRE ATT&CK |
| --- | --- | --- | --- |
| `PORT_SCAN_001` | More than 10 distinct TCP SYN destination ports for one source/destination pair within 60 seconds; the 11th alerts | `MEDIUM` | `T1046 - Network Service Discovery` |
| `CONNECTION_BURST_001` | More than 50 TCP SYN attempts without ACK from one source within 60 seconds; the 51st alerts | `MEDIUM` | None; connection volume alone is not specific enough |
| `DNS_ANOMALY_001` (`query_burst`) | More than 30 DNS queries from one source within 60 seconds; the 31st alerts | `MEDIUM` | `T1071.004 - Application Layer Protocol: DNS` |
| `DNS_ANOMALY_001` (`unique_domain_burst`) | More than 20 normalized domains from one source within 60 seconds; the 21st alerts | `MEDIUM` | `T1071.004 - Application Layer Protocol: DNS` |
| `DNS_ANOMALY_001` (`long_domain`) | Normalized queried-domain length greater than 70; length 71 alerts | `MEDIUM` | `T1071.004 - Application Layer Protocol: DNS` |

These detections are heuristics. Legitimate scanners, automated clients, service discovery, development tools, and high-volume workloads can produce false positives. The DNS mapping is contextual and does not prove command-and-control or tunneling. See [Detection Rules](docs/detection-rules.md) for rolling-window behavior, suppression, evidence, and limitations.

## Architecture

```text
PCAP
  -> Scapy packet reader
  -> PacketInfo normalization
  -> DetectionEngine
  -> configured detection rules
  -> structured Alerts
  -> Rich console / JSONL logs / TrafficSummary / JSON AnalysisReport
```

PCAP ingestion, parsing, detection, presentation, event persistence, aggregation, and report construction remain separate responsibilities. Rules receive `PacketInfo` objects and have no dependency on raw Scapy packets. See [Architecture](docs/architecture.md) for component contracts and data flow.

## Repository Structure

```text
mini-ids-network-monitor/
├── mini_ids/
│   ├── rules/          # DetectionRule and concrete stateful rules
│   ├── capture.py      # Offline PCAP ingestion
│   ├── parser.py       # Scapy packet normalization
│   ├── models.py       # PacketInfo and Alert
│   ├── engine.py       # Rule orchestration and detection statistics
│   ├── config.py       # Strict YAML configuration
│   ├── console.py      # Rich presentation
│   ├── logger.py       # Packet and alert JSONL persistence
│   ├── reporting.py    # TrafficSummary and AnalysisReport
│   └── cli.py          # Typer analyze command
├── tests/              # Unit and public-pipeline tests
├── docs/               # Technical references and reproducible demo
├── examples/           # Example configuration and mock metadata
├── pcaps/samples/      # Safe deterministic demonstration captures
├── scripts/            # Synthetic PCAP generator
├── logs/               # Runtime JSONL output; ignored by Git
└── reports/            # Runtime JSON reports; ignored by Git
```

## Requirements

- Python 3.11 or newer is recommended
- A standard Python virtual environment
- Dependencies listed in `requirements.txt`
- Scapy for offline PCAP reading and packet construction

The current suite is verified on macOS with Python 3.13. The supported offline workflow does not access interfaces, transmit traffic, or require root privileges. Broader platform support is not claimed until it is exercised through CI.

## Installation

```bash
git clone https://github.com/alopes0905/mini-ids-network-monitor.git
cd mini-ids-network-monitor

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with `.\.venv\Scripts\Activate.ps1`.

Verify the package import:

```bash
python3 -c "import mini_ids; print('ok')"
```

## Quick Start

Analyze the committed port-scan sample:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/port-scan.pcap
```

The command parses 11 TCP SYN packets, emits one `PORT_SCAN_001` alert at the default boundary, and prints separate detection and traffic summaries. It does not create output files unless an output path is explicitly supplied.

## Reproducible Demo

The [complete demo scenario](docs/demo-scenario.md) walks through all five safe synthetic PCAPs, each detection family, JSONL inspection, the complete JSON report, configuration, overwrite behavior, expected errors, and cleanup. It requires no live traffic, network-interface access, or root privileges.

## Full Analysis Example

Run all three default rule families and request every supported file output:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/mixed-alerts.pcap \
  --config examples/config.example.yaml \
  --packet-log logs/demo-packets.jsonl \
  --alert-log logs/demo-alerts.jsonl \
  --report reports/demo-analysis.json
```

This creates:

| Path | Format | Contents |
| --- | --- | --- |
| `logs/demo-packets.jsonl` | JSON Lines | One normalized `PacketInfo` record per line |
| `logs/demo-alerts.jsonl` | JSON Lines | One structured `Alert` record per line |
| `reports/demo-analysis.json` | JSON document | Analysis metadata, detection summary, traffic summary, and ordered alerts |

Parent directories are created automatically. Explicitly requested output files are overwritten for each CLI analysis rather than appended or automatically renamed.

## CLI Reference

Show application and command help:

```bash
python3 -m mini_ids.cli --help
python3 -m mini_ids.cli analyze --help
```

The implemented `analyze` options are:

| Option | Required | Purpose |
| --- | --- | --- |
| `--pcap PATH` | Yes | Offline PCAP file to analyze |
| `--config PATH` | No | YAML configuration for the implemented rules |
| `--packet-log PATH` | No | Parsed-packet JSONL destination |
| `--alert-log PATH` | No | Generated-alert JSONL destination |
| `--report PATH` | No | Complete JSON analysis-report destination |

There are no live-interface, BPF-filter, verbosity, quiet-mode, or alternate report-format options.

## Configuration

Configuration is optional. Without `--config`, all three rules are enabled with their constructor defaults.

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

  dns_anomaly:
    enabled: true
    query_threshold: 30
    unique_domain_threshold: 20
    long_domain_threshold: 70
    time_window_seconds: 60
```

Missing sections and fields retain defaults. Set `enabled: false` to omit a rule. Unknown fields, malformed YAML, invalid types, non-positive thresholds, and non-finite or non-positive windows are rejected with a clear error. Thresholds retain the greater-than semantics documented above.

See the annotated [example configuration](examples/config.example.yaml).

## Safe Sample PCAPs

All committed samples are synthetic. The generator constructs fixed packets in memory and writes them directly to PCAP files; it never sends packets, opens sockets, sniffs interfaces, contacts external hosts, or requires root privileges. Addresses come only from documentation ranges, and DNS names use reserved example domains.

| File | Packets | Expected default result | Purpose |
| --- | ---: | --- | --- |
| `normal-traffic.pcap` | 7 | No alerts | Benign TCP, UDP, ICMP, and DNS baseline |
| `port-scan.pcap` | 11 | One `PORT_SCAN_001` | Focused port-scan boundary |
| `connection-burst.pcap` | 51 | One `CONNECTION_BURST_001` | Repeated-target connection volume |
| `dns-anomaly.pcap` | 31 | One DNS `query_burst` | Repeated-domain DNS volume |
| `mixed-alerts.pcap` | 93 | Three alerts, one per rule family | Complete offline workflow demonstration |

Regenerate the samples deterministically:

```bash
python3 scripts/generate_sample_pcaps.py
```

The exact machine-readable contract is in the [sample manifest](pcaps/samples/manifest.json). See [PCAP Safety and Samples](pcaps/README.md) before working with other captures. Private or unauthorized captures must not be committed.

## Testing

Run the complete suite:

```bash
python3 -m pytest
```

Measure statement coverage:

```bash
python3 -m pytest --cov=mini_ids --cov-report=term-missing
```

Current verified result: **465 tests passed** with **99% statement coverage** (951 of 958 statements). Tests cover models, capture errors, protocol parsing, rule boundaries and state, strict configuration, logging, console output, aggregation, JSON reports, CLI behavior, and deterministic sample-PCAP contracts.

High statement coverage improves regression confidence; it does not prove production security, eliminate false positives, or establish suitability for every network. See the [Testing Report](docs/testing-report.md) for module results and known gaps.

## Documentation

- [Reproducible Demo](docs/demo-scenario.md)
- [Architecture](docs/architecture.md)
- [Detection Rules](docs/detection-rules.md)
- [Threat Model](docs/threat-model.md)
- [Testing Report](docs/testing-report.md)
- [PCAP Safety and Samples](pcaps/README.md)
- [Example YAML Configuration](examples/config.example.yaml)
- [Project Issues and Roadmap](https://github.com/alopes0905/mini-ids-network-monitor/issues)

## Limitations

- Analysis is offline-only; live capture is not implemented.
- Detections use packet metadata and threshold heuristics, not payload signatures.
- The project does not decrypt encrypted traffic.
- It does not block traffic, modify firewall rules, or automatically respond to alerts.
- It has no threat-intelligence, GeoIP, ASN, or reverse-DNS enrichment.
- Thresholds are educational defaults and may require tuning for a specific environment.
- False positives are possible, especially with scanners, automation, service discovery, and high-volume clients.
- No enterprise-scale throughput, memory, or long-running monitoring claims have been established.
- Mini IDS is not a replacement for mature IDS/NSM platforms such as Snort, Suricata, or Zeek.

These boundaries keep the project focused on understandable defensive engineering and reproducible offline analysis.

## Ethical Use

Use Mini IDS only with PCAP files you own or are explicitly authorized to inspect. Do not use it to analyze third-party traffic without permission. The project intentionally excludes packet injection, offensive scanning, exploitation, credential extraction, and automated attack behavior.

## Roadmap

Near-term work remains clearly separate from implemented functionality:

- Add GitHub Actions CI and a code-quality pass
- Evaluate optional live capture only after the offline workflow is stable
- Consider later HTML reporting, IPv6 improvements, and performance benchmarks

Progress is tracked through [GitHub Issues](https://github.com/alopes0905/mini-ids-network-monitor/issues).

## License

Mini IDS is available under the [MIT License](LICENSE).

## Portfolio Context

This project demonstrates Python engineering, network-protocol normalization, stateful defensive detection, structured output design, CLI orchestration, and systematic testing in a compact codebase.
