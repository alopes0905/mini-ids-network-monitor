# Detection Rules

Mini IDS detection rules operate on normalized `PacketInfo` metadata and return structured `Alert` objects. They do not inspect packet payloads or receive raw Scapy packets.

## Vertical TCP Port Scan

Status: implemented.

Class: `mini_ids.rules.PortScanRule`

Default constructor values:

```python
PortScanRule(port_threshold=10, time_window_seconds=60)
```

### Detection Semantics

The rule groups observations by `(src_ip, dst_ip)` and counts distinct destination ports from likely initial TCP connection attempts. A packet qualifies only when it has protocol `TCP`, includes the SYN flag, excludes the ACK flag, and has usable source IP, destination IP, destination port, and timestamp metadata.

The default alert condition is **more than 10 distinct destination ports within an inclusive rolling 60-second window**. Ten ports do not alert; the 11th distinct port alerts. Observations exactly 60 seconds old remain in the active window, while older observations expire.

Repeated SYN attempts to the same port do not increase the distinct-port count. The pair emits one alert when it crosses into the alerting state and emits no further alerts while it remains above the threshold. It re-arms after expiry returns the active distinct-port count to 10 or fewer.

Packet timestamps must be positive, finite Unix timestamps representable as UTC datetimes. Older timestamps arriving after a newer qualifying packet for the same pair are ignored so the rolling window remains deterministic.

### Alert Evidence

Each alert includes:

- Source and destination IP addresses
- Distinct destination-port count
- Sorted destination-port list
- Configured port threshold
- Configured time window
- TCP protocol metadata
- MITRE ATT&CK `T1046 - Network Service Discovery`
- A defensive review recommendation

### Limitations and False Positives

Legitimate vulnerability scanners, monitoring systems, inventory tools, and administrator diagnostics can contact many ports and trigger this rule. The rule reports suspicious-looking metadata and does not prove malicious intent.

This first implementation detects vertical TCP SYN scanning only. It does not detect horizontal scanning, UDP scanning, established-connection traffic, payload behavior, or distributed scanning. The threshold and window can be changed through the optional YAML configuration, and the rule can be disabled.

## TCP Connection Burst

Status: implemented.

Class: `mini_ids.rules.ConnectionBurstRule`

Default constructor values:

```python
ConnectionBurstRule(connection_threshold=50, time_window_seconds=60)
```

### Detection Semantics

The rule groups attempts by source IP and counts every TCP packet that includes SYN, excludes ACK, and has a usable source IP and timestamp. Destination metadata is optional. Repeated attempts to the same destination and port count separately because this rule measures connection-attempt volume rather than target diversity.

The default alert condition is **more than 50 initial connection attempts within an inclusive rolling 60-second window**. Fifty attempts do not alert; the 51st alerts. Attempts exactly 60 seconds old remain active, while older attempts expire.

One alert is emitted when a source enters the alerting state. Further attempts are suppressed while the active count remains above the threshold. The source re-arms after expiry returns the count to 50 or fewer. Non-positive or non-finite timestamps are ignored, as are timestamps older than the latest qualifying attempt for that source.

### Alert Evidence

Each alert includes the source IP, active attempt count, configured threshold and window, first and latest active timestamps, counts of observed destinations and ports, and the top five destination IPs and ports by attempt count. The bounded top-five lists keep evidence compact and JSON-serializable.

Connection volume alone does not identify a specific attack technique, so this rule does not assign a MITRE ATT&CK mapping. Its recommendation is to review the source and correlate the activity with authentication, firewall, and service logs.

### Limitations and False Positives

Possible causes include scanning, brute-force-like activity, worm-like behavior, automated clients, misconfigured software, and legitimate high-volume workloads. An alert identifies unusual volume, not malicious intent.

Unlike vertical port-scan detection, this rule aggregates all qualifying attempts from one source across destinations and ports. It counts repeated attempts to the same target separately; the port-scan rule instead counts distinct ports for one source/destination pair.

The threshold and window can be changed through the optional YAML configuration, and the rule can be disabled.

## DNS Anomaly Detection

Status: implemented.

Class: `mini_ids.rules.DNSAnomalyRule`

Default constructor values:

```python
DNSAnomalyRule(
    query_threshold=30,
    unique_domain_threshold=20,
    long_domain_threshold=70,
    time_window_seconds=60,
)
```

The rule uses one stable ID, `DNS_ANOMALY_001`. Each alert's `anomaly_type` evidence field identifies `query_burst`, `unique_domain_burst`, or `long_domain`.

### Detection Semantics

A packet qualifies only when its protocol is `DNS` and it has a non-empty query, source IP, and usable timestamp. Queries are grouped by source IP. Names are normalized by lowercasing them and removing one trailing dot; an empty normalized result is ignored. Public-suffix processing, IDN enrichment, entropy scoring, allowlists, suspicious-TLD lists, and threat-intelligence lookups are intentionally outside this rule.

The three independent checks are:

- **Query burst:** more than 30 qualifying queries in an inclusive rolling 60-second window. Repeated names count separately. Thirty queries do not alert; query 31 alerts.
- **Unique-domain burst:** more than 20 distinct normalized names in the same window. Repeated normalized names count once. Twenty domains do not alert; domain 21 alerts.
- **Long domain:** normalized length greater than 70 characters. Length 70 does not alert; length 71 alerts.

Queries exactly 60 seconds old remain active; older observations expire. Out-of-order timestamps older than the latest qualifying query from that source are ignored. Query-burst and unique-domain alerts are independently suppressed while their counts remain above threshold and re-arm when expiry returns the relevant count to the threshold or below.

For long domains, one alert is emitted per normalized name and source while that same name remains in the active window. Repeats refresh its last-seen time. The name re-arms after it has been absent for more than the configured window.

### Alert Evidence

Query-burst evidence includes the source IP, active query count, configured threshold and window, and first and latest active timestamps. Unique-domain evidence includes the source IP, active distinct count, threshold and window, and a deterministic sorted sample of at most five names. Long-domain evidence includes the source IP, normalized name, measured length, and threshold. Evidence contains metadata only, not raw DNS payloads.

All three variants use `MEDIUM` severity and the contextual MITRE ATT&CK mapping `T1071.004 - Application Layer Protocol: DNS`. This mapping does not establish command-and-control or DNS tunneling. The recommendation is to inspect the source host, review resolver logs, and correlate activity with endpoint and network telemetry.

### Limitations and False Positives

Browsers, operating systems, security tools, service discovery, CDNs, development environments, automated tests, and legitimate long service names can trigger these heuristics. High query volume, high domain diversity, or a long name is anomalous metadata, not proof of malicious behavior.

## Rule Configuration

Configuration is optional. Without a file, all three rules retain the constructor defaults documented above. The supported YAML structure is:

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

Missing sections or fields retain defaults. Set `enabled: false` to omit a rule. Threshold semantics do not change when configured: alerts occur only when the observed value is greater than the threshold. Unknown fields and invalid values are rejected rather than ignored or coerced.
