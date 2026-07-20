# Testing Report

This report records the Mini IDS testing state after the Issue #16 traffic-summary pass. It is a development snapshot, not a claim of production readiness or complete security validation.

## Tools and Environment

- Python 3.13.0
- `pytest` 9.1.1
- `pytest-cov` 7.1.0 and `coverage.py` for statement coverage
- PyYAML for configuration loading and parser-error tests
- Scapy-generated packets and PCAP files for deterministic network inputs
- Typer `CliRunner` for command-line tests
- Rich consoles backed by `StringIO` for terminal-output assertions
- `tmp_path` for isolated filesystem output

All packet data used by the suite is synthetic. Tests use documentation address ranges and do not access live interfaces, private captures, or the internet.

## Running the Suite

Run all tests from the repository root:

```bash
python3 -m pytest
```

Run the suite with a terminal coverage report:

```bash
python3 -m pytest --cov=mini_ids --cov-report=term-missing
```

## Current Results

Results measured on 2026-07-20:

- Collected test cases: **388**
- Passing test cases: **388**
- Overall statement coverage: **99%**
- Covered statements: **846 of 853**

Issue #15 established a 354-test, 99%-coverage baseline with full DNS-rule coverage. Issue #16 added focused aggregation, ranking, serialization, Rich presentation, single-parse CLI, and public-pipeline coverage.

### Module Coverage

| Module | Statement coverage |
| --- | ---: |
| `mini_ids/__init__.py` | 100% |
| `mini_ids/capture.py` | 100% |
| `mini_ids/cli.py` | 96% |
| `mini_ids/config.py` | 100% |
| `mini_ids/console.py` | 100% |
| `mini_ids/engine.py` | 100% |
| `mini_ids/logger.py` | 100% |
| `mini_ids/models.py` | 100% |
| `mini_ids/parser.py` | 92% |
| `mini_ids/reporting.py` | 100% |
| `mini_ids/rules/__init__.py` | 100% |
| `mini_ids/rules/base.py` | 100% |
| `mini_ids/rules/connection_burst.py` | 100% |
| `mini_ids/rules/dns_anomaly.py` | 100% |
| `mini_ids/rules/port_scan.py` | 100% |

## Covered Behavior

The suite currently covers:

- `PacketInfo` and `Alert` creation, optional fields, immutability, detached dictionary serialization, and JSON serialization
- Valid, missing, directory, and invalid PCAP inputs, including exception chaining
- TCP, UDP, ICMP, DNS query, DNS response, `OTHER`, invalid timestamp, and unsupported parser inputs
- Detection rule contracts, engine ordering, generators, statistics, state retention, resets, and exception propagation
- Port-scan and connection-burst filtering, exact thresholds, rolling-window boundaries, expiry, re-arming, state isolation, input validation, evidence, and coexistence
- DNS query-burst, unique-domain, and long-domain boundaries; normalization; per-source state; inclusive expiry; subtype suppression and re-arming; bounded evidence; MITRE context; and three-rule coexistence
- YAML defaults and partial overrides for all three rules, strict schema and value validation, immutable typed configuration, deterministic rule construction, rule enable/disable behavior, and clean CLI configuration errors
- Empty, list, and one-pass generator traffic aggregation; endpoint, port, protocol, `OTHER`, unexpected-protocol, and DNS counts; deterministic top-N ranking; limit validation; detached JSON-compatible serialization; and non-mutation
- Packet and alert JSONL append/overwrite behavior, generators, empty outputs, newline escaping, directory creation, and filesystem failures
- Rich alert, detection-summary, and bounded traffic-summary output, all severities, optional fields, ordering, empty results, literal text, provided-console behavior, and non-mutation
- CLI help, single-parse synthetic-PCAP analysis, all three rules, traffic statistics, `OTHER` packets, optional logs, overwrite behavior, output errors, and future-feature boundaries
- A framework-independent integration path from synthetic PCAP ingestion through parsing, all three rules, traffic aggregation, JSONL persistence, and console presentation

## Intentionally Uncovered

The coverage pass does not force tests for branches that Scapy normalizes away in ordinary packet objects, such as DNS question or answer fields remaining literally `None` after layer construction. The normal query and response paths are covered.

The coverage command imports `mini_ids.cli` through `CliRunner`, so it does not execute the two module-dispatch statements under `if __name__ == "__main__"`. CLI commands and help behavior are covered through Typer without asserting terminal layout byte for byte.

Features that do not exist yet are not tested: final JSON reports, live capture, packaging entry points, and CI workflows.

## Limitations

- Synthetic traffic cannot represent every malformed capture or protocol implementation found in real networks.
- The suite does not measure throughput, memory use, or behavior on large PCAP files.
- Filesystem tests avoid platform-specific permission assumptions where possible.
- Statement coverage does not prove that every logical combination or security failure mode is tested.
- Tests validate the documented threshold rules; they do not establish that those thresholds are suitable for every network.
- Synthetic DNS queries do not establish real-world false-positive rates or confirm malicious DNS behavior.

## Future Testing

Future v1.0 work should add focused tests alongside each new feature:

- Final-report consistency with separate engine and traffic summaries
- Larger authorized DNS datasets for threshold tuning and false-positive evaluation
- Optional live-capture permission and platform boundaries without relying on public traffic
- CI across supported Python versions
- Larger synthetic PCAP and performance checks after the functional contracts stabilize
