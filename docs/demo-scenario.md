# Reproducible Demo Scenario

## Demo Purpose

This guide demonstrates the complete Mini IDS offline workflow with the five deterministic PCAP files committed under `pcaps/samples/`. It covers normal traffic, each implemented detection family, optional JSONL logs, the complete JSON analysis report, configuration, expected errors, overwrite behavior, and cleanup.

The demo is passive and defensive:

- no packets are transmitted or replayed;
- no network interface is opened or captured;
- no external host is contacted;
- no root privileges are required;
- all packet data is synthetic; and
- all addresses and domains use documentation-only ranges and reserved example names.

Run every command from the repository root. Alerts are heuristic investigation leads, not confirmed incidents or attribution.

## Prerequisites

Python 3.11 or newer is recommended. Clone the repository, enter it, create a virtual environment, and install the declared dependencies:

```bash
git clone https://github.com/alopes0905/mini-ids-network-monitor.git
cd mini-ids-network-monitor

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with `.\.venv\Scripts\Activate.ps1` and use the available Python launcher in place of `python3` if necessary.

Confirm that the package imports from the repository root:

```bash
python3 -c "import mini_ids; print('ok')"
```

Expected output:

```text
ok
```

## Verify the Sample Data

List the committed samples:

```bash
ls -lh pcaps/samples/
```

The machine-readable contract is [the sample manifest](../pcaps/samples/manifest.json):

| File | Packets | Expected alerts | Purpose |
| --- | ---: | --- | --- |
| `normal-traffic.pcap` | 7 | 0 | Benign-looking TCP, UDP, ICMP, and DNS metadata below every threshold |
| `port-scan.pcap` | 11 | One `PORT_SCAN_001` | Exact default vertical port-scan boundary |
| `connection-burst.pcap` | 51 | One `CONNECTION_BURST_001` | Repeated-target connection-attempt volume |
| `dns-anomaly.pcap` | 31 | One `DNS_ANOMALY_001` with `query_burst` | Repeated `example.org` query volume |
| `mixed-alerts.pcap` | 93 | Three alerts, one per rule family | Complete workflow and all supported outputs |

Regenerate the same normalized sample scenarios when needed:

```bash
python3 scripts/generate_sample_pcaps.py
```

The generator constructs packets in memory and intentionally overwrites only the five synthetic PCAPs and their manifest under `pcaps/samples/`. It does not send or capture traffic. See [PCAP Safety and Samples](../pcaps/README.md) for generation details.

## Check the CLI

Inspect the application and command help:

```bash
python3 -m mini_ids.cli --help
python3 -m mini_ids.cli analyze --help
```

The `analyze` command supports only these analysis options:

| Option | Required | Purpose |
| --- | --- | --- |
| `--pcap PATH` | Yes | Offline PCAP input |
| `--config PATH` | No | Validated YAML rule configuration |
| `--packet-log PATH` | No | Normalized packet JSONL output |
| `--alert-log PATH` | No | Structured alert JSONL output |
| `--report PATH` | No | Complete JSON analysis report |

No live-capture, interface, filter, or alternate report-format option exists.

## Demo A: Normal Traffic

Run the benign synthetic baseline:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/normal-traffic.pcap
```

Expected result:

- 7 parsed packets;
- 0 generated alerts;
- the `No alerts generated.` message;
- detection totals of 7 packets and 0 alerts; and
- a traffic mix of 3 TCP, 2 DNS, 1 UDP, and 1 ICMP packet, with 2 DNS queries.

This demonstrates valid PCAP ingestion, normalization, empty-alert handling, and traffic aggregation without forcing a finding.

## Demo B: Port-Scan Detection

Run the focused vertical TCP SYN scan:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/port-scan.pcap
```

Expected result:

- 11 parsed TCP SYN packets;
- one `PORT_SCAN_001` alert with `MEDIUM` severity;
- source `192.0.2.50` and destination `198.51.100.50`;
- evidence containing 11 distinct destination ports and the configured threshold; and
- contextual MITRE ATT&CK mapping `T1046 - Network Service Discovery`.

The default rule alerts only when the active distinct-port count is greater than 10, so the 11th distinct port crosses the boundary. The mapping provides investigation context; it does not prove malicious reconnaissance.

## Demo C: Connection-Burst Detection

Run the repeated-target TCP connection-attempt sample:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/connection-burst.pcap
```

Expected result:

- 51 parsed qualifying TCP SYN packets;
- one `CONNECTION_BURST_001` alert with `MEDIUM` severity;
- evidence showing 51 attempts against the default threshold of 50;
- no `PORT_SCAN_001` alert because all attempts use destination port 443; and
- no MITRE ATT&CK mapping because connection volume alone is not sufficiently specific.

Repeated attempts count separately because this rule measures source-side attempt volume rather than distinct targets.

## Demo D: DNS Anomaly Detection

Run the repeated-domain DNS sample:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/dns-anomaly.pcap
```

Expected result:

- 31 parsed DNS query packets;
- one `DNS_ANOMALY_001` alert with `MEDIUM` severity;
- evidence containing `anomaly_type: query_burst` and an active query count of 31;
- no unique-domain or long-domain alert; and
- contextual MITRE ATT&CK mapping `T1071.004 - Application Layer Protocol: DNS`.

All queries use the short reserved name `example.org`, so only query volume crosses a threshold. The mapping does not prove DNS tunneling, command-and-control, or malicious intent.

## Demo E: Complete Mixed Workflow

Run all three default rules and request every supported file output:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/mixed-alerts.pcap \
  --config examples/config.example.yaml \
  --packet-log logs/demo-packets.jsonl \
  --alert-log logs/demo-alerts.jsonl \
  --report reports/demo-analysis.json
```

The writers create `logs/` and `reports/` parents when necessary. Expected result:

- 93 parsed packets: 62 TCP and 31 DNS;
- 3 `MEDIUM` alerts in deterministic order:
  1. `PORT_SCAN_001`
  2. `CONNECTION_BURST_001`
  3. `DNS_ANOMALY_001` with `anomaly_type: query_burst`
- detection and traffic summaries in the terminal;
- `logs/demo-packets.jsonl` with 93 packet records;
- `logs/demo-alerts.jsonl` with 3 alert records; and
- `reports/demo-analysis.json` as one complete JSON document.

The example configuration contains the same enabled rules and defaults used when `--config` is omitted.

## Inspect Packet JSONL

Check the record count and view a small sample:

```bash
wc -l logs/demo-packets.jsonl
head -n 3 logs/demo-packets.jsonl
```

The line count should be `93`. Validate every line with the Python standard library and display the first two records:

```bash
python3 - <<'PY'
import json
from pathlib import Path

path = Path("logs/demo-packets.jsonl")
records = [
    json.loads(line)
    for line in path.read_text(encoding="utf-8").splitlines()
]

print(f"packet records: {len(records)}")
print(json.dumps(records[:2], indent=2))
PY
```

Packet JSONL stores one normalized `PacketInfo` dictionary per line. It contains packet metadata such as addresses, ports, protocol, flags, DNS fields, timestamps, lengths, and summaries. It stores no raw Scapy objects, but metadata from user-supplied PCAPs may still be sensitive.

## Inspect Alert JSONL

Verify the line count:

```bash
wc -l logs/demo-alerts.jsonl
```

The line count should be `3`. Inspect the ordered findings without requiring `jq`:

```bash
python3 - <<'PY'
import json
from pathlib import Path

path = Path("logs/demo-alerts.jsonl")
alerts = [
    json.loads(line)
    for line in path.read_text(encoding="utf-8").splitlines()
]

print(f"alert records: {len(alerts)}")
for alert in alerts:
    print(json.dumps({
        "rule_id": alert["rule_id"],
        "severity": alert["severity"],
        "description": alert["description"],
        "evidence": alert["evidence"],
        "mitre_attack": alert["mitre_attack"],
    }, indent=2))
PY
```

Alert order follows deterministic configured rule order. The connection-burst alert has `mitre_attack: null`; the port-scan and DNS mappings are contextual.

## Inspect the JSON Analysis Report

Load the report as one JSON document and print its principal sections:

```bash
python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(
    Path("reports/demo-analysis.json").read_text(encoding="utf-8")
)

print(json.dumps({
    "pcap_file": report["pcap_file"],
    "analysis_started": report["analysis_started"],
    "analysis_finished": report["analysis_finished"],
    "detection_summary": report["detection_summary"],
    "traffic_summary": report["traffic_summary"],
    "alert_ids": [alert["rule_id"] for alert in report["alerts"]],
}, indent=2))
PY
```

The formats serve different purposes:

| Output | Structure | Purpose |
| --- | --- | --- |
| Packet JSONL | One normalized packet per line | Record-level packet metadata processing |
| Alert JSONL | One structured alert per line | Stream-like finding persistence |
| Analysis report | One complete JSON document | PCAP path, UTC analysis timestamps, detection totals, traffic aggregates, and ordered alerts |

The report does not contain the full packet-record collection.

## Demonstrate Configuration Safely

Create an ignored, repository-local temporary configuration that disables only port-scan detection. This does not modify the committed example:

```bash
cat > logs/demo-config.yaml <<'YAML'
rules:
  port_scan:
    enabled: false

  connection_burst:
    enabled: true

  dns_anomaly:
    enabled: true
YAML
```

Run the mixed capture with the temporary configuration:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/mixed-alerts.pcap \
  --config logs/demo-config.yaml
```

Expected result:

- 93 parsed packets and the same traffic summary;
- 2 alerts, `CONNECTION_BURST_001` followed by `DNS_ANOMALY_001`; and
- no `PORT_SCAN_001` alert.

Missing threshold fields retain constructor defaults. Remove `logs/demo-config.yaml` during cleanup.

## Expected Error Handling

Use a deliberately missing sample path:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/does-not-exist.pcap
```

The command exits non-zero and prints a concise message similar to:

```text
Error: PCAP file not found: pcaps/samples/does-not-exist.pcap
```

This anticipated input error does not produce a full traceback.

## Verify Overwrite Behavior

Run the complete mixed workflow command from Demo E a second time with the same output paths. Explicitly requested packet logs, alert logs, and reports are overwritten for each analysis run; they are not appended.

Then verify the counts:

```bash
wc -l logs/demo-packets.jsonl logs/demo-alerts.jsonl
```

The files should still contain 93 and 3 lines, not 186 and 6. Confirm that the report remains one valid JSON document:

```bash
python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(
    Path("reports/demo-analysis.json").read_text(encoding="utf-8")
)
assert report["detection_summary"]["packets_processed"] == 93
assert report["detection_summary"]["alerts_generated"] == 3
assert len(report["alerts"]) == 3
print("report is valid and contains one 93-packet analysis")
PY
```

Output files are written independently rather than as one transaction. If a later requested write fails, an earlier successful output may remain.

## Cleanup

Remove all generated demo artifacts:

```bash
rm -f \
  logs/demo-packets.jsonl \
  logs/demo-alerts.jsonl \
  logs/demo-config.yaml \
  reports/demo-analysis.json
```

The repository ignores runtime logs and reports, but ignored files still occupy disk and can expose network metadata. Apply appropriate storage, retention, and deletion practices when analyzing authorized non-synthetic captures.

## Expected-Result Summary

| Scenario | Packets | Expected alerts |
| --- | ---: | --- |
| Normal traffic | 7 | 0 |
| Port scan | 11 | `PORT_SCAN_001` |
| Connection burst | 51 | `CONNECTION_BURST_001` |
| DNS anomaly | 31 | `DNS_ANOMALY_001` with `query_burst` |
| Mixed | 93 | `PORT_SCAN_001`, `CONNECTION_BURST_001`, `DNS_ANOMALY_001` in that order |

## What the Demo Verifies

With deterministic synthetic inputs, the scenario exercises:

- safe offline PCAP ingestion;
- packet normalization;
- validated optional configuration;
- deterministic stateful rule execution;
- structured alert generation;
- Rich terminal presentation;
- packet and alert JSONL persistence;
- aggregate traffic statistics;
- complete JSON report generation;
- explicit overwrite behavior; and
- clear expected-error handling.

## What the Demo Does Not Prove

This controlled demonstration does not establish:

- production readiness or enterprise-scale performance;
- complete attack or protocol coverage;
- absence of false positives or false negatives;
- live-capture support;
- payload-signature detection or encrypted-traffic decryption;
- automatic prevention, blocking, or remediation;
- capture provenance or forensic attribution; or
- suitability of default thresholds for another network.

## Next Steps for Reviewers

- [Project README](../README.md)
- [Architecture](architecture.md)
- [Detection Rules](detection-rules.md)
- [Threat Model](threat-model.md)
- [Testing Report](testing-report.md)
- [PCAP Safety and Samples](../pcaps/README.md)
