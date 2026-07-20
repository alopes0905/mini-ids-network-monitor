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

This first implementation detects vertical TCP SYN scanning only. It does not detect horizontal scanning, UDP scanning, established-connection traffic, payload behavior, or distributed scanning. Thresholds are constructor arguments until configuration loading is implemented.

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

Thresholds are constructor arguments until configuration loading is implemented.

## Planned Rules

- DNS anomaly detection: not implemented
