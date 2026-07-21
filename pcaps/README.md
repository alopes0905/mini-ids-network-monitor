# PCAP Files

This directory is reserved for offline PCAP files used during development and demonstrations. Never commit real or private captures: they can contain sensitive addresses, hostnames, credentials, payloads, and other identifying metadata.

## Safe Samples

The files under `samples/` are small, deterministic captures created entirely in memory by `scripts/generate_sample_pcaps.py`. Generation writes packet objects directly to disk with Scapy; it does not send packets, open sockets, sniff interfaces, use live capture, contact external systems, or require root privileges.

All addresses belong to the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`. DNS questions use only `example.com`, `example.net`, or `example.org`. The samples contain no application payloads, credentials, cookies, or tokens.

| Sample | Packets | Expected default-rule alerts |
| --- | ---: | --- |
| `normal-traffic.pcap` | 7 | None |
| `port-scan.pcap` | 11 | One `PORT_SCAN_001` |
| `connection-burst.pcap` | 51 | One `CONNECTION_BURST_001` |
| `dns-anomaly.pcap` | 31 | One `DNS_ANOMALY_001` with `query_burst` subtype |
| `mixed-alerts.pcap` | 93 | One alert from each rule family, in port-scan, connection-burst, DNS order |

`manifest.json` records these machine-readable packet and alert expectations.

Regenerate and intentionally overwrite the known sample files from the repository root:

```bash
python3 scripts/generate_sample_pcaps.py
```

An isolated output directory can be selected for inspection or testing:

```bash
python3 scripts/generate_sample_pcaps.py --output-dir /tmp/mini-ids-samples
```

Analyze a focused sample:

```bash
python3 -m mini_ids.cli analyze --pcap pcaps/samples/port-scan.pcap
```

Analyze the mixed sample and explicitly request all supported output files:

```bash
python3 -m mini_ids.cli analyze \
  --pcap pcaps/samples/mixed-alerts.pcap \
  --packet-log logs/demo-packets.jsonl \
  --alert-log logs/demo-alerts.jsonl \
  --report reports/demo-analysis.json
```

Arbitrary `.pcap` and `.pcapng` files remain ignored by Git. The narrow exception for `pcaps/samples/*.pcap` exists only for these reviewed synthetic files. Generated logs and reports also remain ignored.
