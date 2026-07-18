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

## Planned Rules

- Connection burst detection: not implemented
- DNS anomaly detection: not implemented
