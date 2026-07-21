# Detection Rules

## Purpose and Scope

This document is the technical reference for the detection rules currently implemented by Mini IDS. The rules consume normalized `PacketInfo` objects, retain state for rolling-window analysis, and return structured `Alert` objects. They never receive raw Scapy packets.

The rules identify threshold-based indicators for investigation. An alert does not prove malicious intent, attribute activity to a person, or confirm that an attack succeeded. Rules do not block, transmit, replay, or modify traffic. See [Architecture](architecture.md) for the full processing design and [Threat Model](threat-model.md) for trust boundaries and residual risks.

## Shared Rule Architecture

Every concrete rule implements the abstract `DetectionRule` contract:

```text
rule_id
name
description
severity
process_packet(packet: PacketInfo) -> list[Alert]
```

The engine passes one `PacketInfo` to each registered rule at a time. A rule may retain mutable instance state and may return zero, one, or several alerts for that packet. `DetectionEngine` executes rules in registration order and preserves both that order and the order of alerts returned by each rule.

Unexpected rule exceptions propagate to the caller. Engine counters are updated only after every registered rule processes the packet successfully; state already changed by an earlier rule is not rolled back if a later rule fails. `DetectionEngine.reset_statistics()` resets engine counters only. It does not reset registered rules or their internal state.

Configured analyses construct enabled rules in this deterministic order:

1. `PortScanRule`
2. `ConnectionBurstRule`
3. `DNSAnomalyRule`

There is no dynamic plugin discovery or cross-rule correlation system.

## Timestamps and Rolling Windows

`PacketInfo.timestamp` is expected to be a numeric Unix timestamp. Each current rule normalizes it with `float()` and accepts it only when it is:

- not a boolean;
- convertible to a finite number;
- greater than zero; and
- representable as a UTC `datetime` on the current platform.

Invalid timestamps are ignored under the supported `PacketInfo` contract. After a rule accepts a timestamp for a state key, a later relevant packet with an older timestamp for that same key is ignored. Equal timestamps are accepted.

Rolling windows are inclusive. For a 60-second window, observations at times `t=100` and `t=160` are active together. At `t=160.001`, the observation at `t=100` is older than the cutoff and expires. In implementation terms, observations expire only when their timestamp is strictly less than `current_timestamp - time_window_seconds`.

Expiry is packet-driven. A rule removes old observations only when a later relevant packet for that state key is processed. There is no background timer, inactive state is not cleaned independently, and state is not persisted across process executions.

## Threshold Semantics

All numeric detection thresholds use a strict greater-than condition:

```text
configured threshold = N
alert when active value > N
```

Consequently, a threshold of 10 alerts on value 11, a threshold of 50 alerts on value 51, and a threshold of 30 alerts on value 31. Configuration and documentation say "more than" rather than "at least" for this reason.

## Suppression and Re-arming

The rolling-count detections use the same state transition:

```text
active value <= threshold
  -> active value crosses above threshold
  -> emit one alert
  -> suppress alerts while active value remains above threshold
  -> re-arm after expiry returns active value to threshold or below
```

Suppression limits repeated alerts from one continuous active window. It does not merge related behavior across keys, rules, or process executions. DNS long-domain suppression uses a separate normalized-domain and last-seen design described in its rule section.

## Rule Summary

| Rule | Rule ID | Eligible input | Grouping key | Default trigger | Severity | MITRE ATT&CK |
| --- | --- | --- | --- | --- | --- | --- |
| Vertical TCP port scan | `PORT_SCAN_001` | TCP SYN without ACK plus source, destination, valid destination port, and timestamp | `(src_ip, dst_ip)` | More than 10 distinct ports in 60 seconds; port 11 alerts | `MEDIUM` | `T1046 - Network Service Discovery` |
| TCP connection burst | `CONNECTION_BURST_001` | TCP SYN without ACK plus source and timestamp | `src_ip` | More than 50 attempts in 60 seconds; attempt 51 alerts | `MEDIUM` | None |
| DNS query burst | `DNS_ANOMALY_001` | DNS query plus source and timestamp | `src_ip` | More than 30 queries in 60 seconds; query 31 alerts | `MEDIUM` | `T1071.004 - Application Layer Protocol: DNS` |
| DNS unique-domain burst | `DNS_ANOMALY_001` | DNS query plus source and timestamp | `src_ip` | More than 20 normalized domains in 60 seconds; domain 21 alerts | `MEDIUM` | `T1071.004 - Application Layer Protocol: DNS` |
| DNS long domain | `DNS_ANOMALY_001` | DNS query plus source and timestamp | `(src_ip, normalized_domain)` for suppression | Normalized length greater than 70; length 71 alerts | `MEDIUM` | `T1071.004 - Application Layer Protocol: DNS` |

DNS alerts share one rule ID. Their evidence field `anomaly_type` distinguishes `query_burst`, `unique_domain_burst`, and `long_domain`.

## Vertical TCP Port Scan

### Purpose

`PortScanRule` detects vertical TCP SYN scanning behavior: one source probing many destination ports on one destination host inside a rolling window.

### Packet Eligibility

A packet contributes only when all of these conditions hold:

```text
protocol == "TCP"
tcp_flags is text
SYN flag present
ACK flag absent
src_ip present and non-empty
dst_ip present and non-empty
dst_port is an integer from 1 through 65535
timestamp usable
```

Flag matching is case-insensitive. Non-TCP packets, TCP packets without SYN, SYN-ACK packets, non-text flags, missing addresses, missing or invalid destination ports, and unusable timestamps are ignored. Once the rule has accepted a timestamp for a source/destination pair, an older qualifying packet for that pair is also ignored.

### Grouping and Counting

State is isolated by:

```text
(src_ip, dst_ip)
```

The rule counts distinct active destination ports. Repeated SYN attempts to the same port create observations for expiry bookkeeping but do not increase the distinct-port count. Traffic from a different source or to a different destination uses separate state.

### Default Boundary

```text
port_threshold = 10
time_window_seconds = 60
alert condition = active distinct ports > 10
```

Ten distinct ports do not alert. The 11th distinct port alerts when all 11 remain in the inclusive 60-second window.

### State, Expiry, and Suppression

The rule stores timestamped port observations in a deque and maintains counts for currently active ports. On each relevant in-order packet, it removes observations older than the cutoff, updates the active-port counts, and evaluates the strict threshold.

One alert is emitted when a source/destination pair first moves above the threshold. Additional ports do not produce another alert while the pair remains above it. The pair re-arms only after packet-driven expiry returns the active distinct-port count to the configured threshold or below.

### Alert and Evidence

The alert uses:

- rule ID `PORT_SCAN_001`;
- rule name `Vertical TCP Port Scan`;
- severity `MEDIUM`;
- the triggering packet timestamp in UTC;
- source and destination IP fields;
- protocol `TCP`;
- a defensive authorization-review recommendation; and
- contextual MITRE ATT&CK mapping `T1046 - Network Service Discovery`.

Evidence contains these exact keys:

| Evidence field | Meaning |
| --- | --- |
| `source_ip` | Source address for the state key |
| `destination_ip` | Destination address for the state key |
| `distinct_port_count` | Number of active distinct destination ports |
| `destination_ports` | Complete sorted list of active destination ports |
| `port_threshold` | Configured strict threshold |
| `time_window_seconds` | Configured rolling-window duration |

The destination-port list is deterministic and naturally limited to valid TCP port numbers, but it is not truncated to a fixed top-N size. The T1046 mapping provides reconnaissance context only; it does not confirm that network-service discovery was malicious or successful.

### False Positives

Possible legitimate causes include:

- authorized vulnerability scanning;
- administrative troubleshooting and discovery;
- inventory or service-catalog tools;
- monitoring and health-check systems;
- test and lab automation; and
- applications probing several optional services on one host.

### False Negatives and Evasion

The rule may miss activity that:

- probes 10 or fewer active ports with the default threshold;
- spreads ports over longer than the active window;
- distributes probes across source addresses;
- spreads a scan across many destination hosts with few ports per host;
- uses UDP, non-SYN TCP probes, or established sessions;
- relies on missing, malformed, or out-of-order timestamps; or
- depends on payload or protocol details absent from `PacketInfo`.

### Configuration

```yaml
rules:
  port_scan:
    enabled: true
    port_threshold: 10
    time_window_seconds: 60
```

A lower threshold increases sensitivity and likely alert volume. A higher threshold or shorter window may reduce noise but can miss slower or narrower scans. There is no universal setting; tune against authorized traffic from the relevant capture point.

## TCP Connection Burst

### Purpose

`ConnectionBurstRule` detects unusually high volumes of initial TCP connection attempts from one source. It measures attempt volume, not target diversity.

This differs from port-scan detection:

- port scan counts distinct ports for one source/destination pair;
- connection burst counts every qualifying attempt from one source; and
- repeated attempts to the same destination and port count separately.

### Packet Eligibility

A packet contributes only when:

```text
protocol == "TCP"
tcp_flags is text
SYN flag present
ACK flag absent
src_ip present and non-empty
timestamp usable
```

Destination IP and port are optional. When present, they contribute to alert evidence; when absent, the source-side attempt still counts. Non-TCP packets, TCP packets without SYN, SYN-ACK packets, non-text flags, missing source addresses, unusable timestamps, and older out-of-order timestamps for the source are ignored.

### Grouping and Counting

State is isolated by:

```text
src_ip
```

Each qualifying packet adds one attempt regardless of destination. Different destinations and repeated attempts to the same destination and port are aggregated for that source.

### Default Boundary

```text
connection_threshold = 50
time_window_seconds = 60
alert condition = active attempts > 50
```

Fifty attempts do not alert. The 51st attempt alerts when all 51 remain in the inclusive 60-second window.

### State, Expiry, and Suppression

Each source has a deque of timestamped attempts with optional destination metadata. Relevant in-order packets trigger expiry, append one new attempt, and evaluate the active count.

One alert is emitted when the source crosses above the threshold. Further qualifying attempts are suppressed while the source remains above it. The source re-arms after packet-driven expiry lowers the active count to the threshold or below.

### Alert and Evidence

The alert uses:

- rule ID `CONNECTION_BURST_001`;
- rule name `TCP Connection Burst`;
- severity `MEDIUM`;
- the triggering packet timestamp in UTC;
- the source IP;
- protocol `TCP`; and
- a recommendation to correlate with authentication, firewall, and service logs.

The alert's destination fields are not populated because the finding aggregates a source across targets. Evidence contains:

| Evidence field | Meaning |
| --- | --- |
| `source_ip` | Source address used as the state key |
| `connection_attempt_count` | Active qualifying attempt count |
| `connection_threshold` | Configured strict threshold |
| `time_window_seconds` | Configured rolling-window duration |
| `first_active_timestamp` | UTC timestamp of the oldest active attempt |
| `latest_active_timestamp` | UTC timestamp of the triggering attempt |
| `observed_destination_ip_count` | Number of distinct non-missing destination IPs |
| `observed_destination_port_count` | Number of distinct non-missing destination ports |
| `top_destination_ips` | Up to five destinations ranked by count, then address |
| `top_destination_ports` | Up to five ports ranked by count, then numeric port |

The two top lists contain objects with the destination value and `attempt_count`, making evidence bounded, deterministic, and JSON-serializable. This rule has no MITRE ATT&CK mapping because connection volume by itself is not specific enough to assign one responsibly.

### False Positives

Possible legitimate causes include:

- load balancers and service-health checks;
- web crawlers and automated clients;
- deployment and orchestration systems;
- integration, load, or resilience testing;
- retry storms and misconfigured clients; and
- legitimate high-volume applications.

The same signal can also accompany scanning, brute-force-like behavior, or worm-like propagation. Volume alone cannot distinguish these explanations.

### False Negatives and Evasion

The rule may miss activity that:

- stays at or below 50 active attempts by default;
- spreads attempts over a longer period;
- distributes activity across source addresses;
- uses non-SYN packets or existing sessions;
- uses spoofed source addresses that split state;
- appears in an incomplete capture; or
- relies on missing, malformed, or out-of-order timestamps.

### Configuration

```yaml
rules:
  connection_burst:
    enabled: true
    connection_threshold: 50
    time_window_seconds: 60
```

Tune for expected connection rates at the capture point. Busy proxies, gateways, test runners, and application tiers may require different settings from endpoint-oriented captures.

## DNS Anomaly Detection

### Purpose and Shared Eligibility

`DNSAnomalyRule` performs three independent checks under one rule ID. Each alert includes an `anomaly_type` evidence value that identifies the triggered variant.

A packet contributes only when:

```text
protocol == "DNS"
dns_query is non-empty text after normalization
src_ip present and non-empty
timestamp usable
```

Non-DNS packets, missing or non-text queries, queries that normalize to an empty string, missing source addresses, unusable timestamps, and older out-of-order timestamps for the source are ignored.

### Domain Normalization

Normalization is deliberately small and deterministic:

1. Remove exactly one trailing dot when present.
2. Convert the remaining text to lowercase.
3. Ignore the result if it is empty.

For example, `Example.COM.` becomes `example.com`, while `Example.COM..` becomes `example.com.` because only one trailing dot is removed. The rule does not trim whitespace, apply Public Suffix List logic, transform internationalized domain names, calculate entropy, consult TLD reputation, use allowlists, or perform threat-intelligence lookups.

State for all three variants is isolated by source IP.

### Query Burst

The query-volume check counts every qualifying DNS query, including repeated queries to the same normalized domain.

```text
query_threshold = 30
time_window_seconds = 60
alert condition = active queries > 30
```

Thirty active queries do not alert. Query 31 alerts. A per-source deque holds timestamped query observations. One query-burst alert is emitted on threshold crossing, suppressed while the active query count stays above 30, and re-armed after packet-driven expiry returns the count to 30 or fewer.

Evidence contains:

- `anomaly_type: "query_burst"`;
- `source_ip`;
- `active_query_count`;
- `query_threshold`;
- `time_window_seconds`;
- `first_active_timestamp`; and
- `latest_active_timestamp`.

### Unique-Domain Burst

The unique-domain check counts distinct normalized domains. Repeats remain query observations but do not increase the active unique-domain count.

```text
unique_domain_threshold = 20
time_window_seconds = 60
alert condition = active normalized domains > 20
```

Twenty active domains do not alert. Domain 21 alerts. A deque plus per-domain counts keeps a domain active until its final observation expires. One unique-domain alert is emitted on threshold crossing, suppressed while the active unique count stays above 20, and re-armed after packet-driven expiry returns the count to 20 or fewer.

Evidence contains:

- `anomaly_type: "unique_domain_burst"`;
- `source_ip`;
- `active_unique_domain_count`;
- `unique_domain_threshold`;
- `time_window_seconds`; and
- `domain_sample`, the first five names from the sorted active-domain set.

The sample is bounded and deterministic. It is not a ranking by query count.

### Long Queried Domain

The long-domain check evaluates every qualifying packet independently:

```text
long_domain_threshold = 70
alert condition = normalized domain length > 70
```

A normalized length of 70 does not alert. Length 71 alerts. The check uses the complete normalized domain string, including dots.

For suppression, the rule remembers the last-seen timestamp for each normalized long domain under each source. The first occurrence alerts. An identical normalized domain queried again within the inclusive rolling window is suppressed and refreshes its last-seen timestamp. It re-arms only after that domain has been absent for more than `time_window_seconds`; a repeat exactly at the boundary remains suppressed.

Evidence contains:

- `anomaly_type: "long_domain"`;
- `source_ip`;
- `normalized_domain`;
- `domain_length`; and
- `long_domain_threshold`.

### Shared Alert Metadata

All three variants use:

- rule ID `DNS_ANOMALY_001`;
- rule name `DNS Anomaly Detection`;
- severity `MEDIUM`;
- source and available destination metadata from the triggering packet;
- protocol `DNS`;
- a recommendation to inspect the source, resolver logs, and related endpoint and network telemetry; and
- contextual MITRE ATT&CK mapping `T1071.004 - Application Layer Protocol: DNS`.

One packet can produce several DNS alerts. Their order is query burst, unique-domain burst, then long domain. The MITRE mapping supplies investigation context; it does not prove DNS tunneling, command-and-control, data exfiltration, or malicious intent.

### False Positives

Possible legitimate causes include:

- browsers and operating-system services;
- CDNs and service discovery;
- security, inventory, and monitoring tools;
- automated tests and development environments;
- resolver retry behavior; and
- legitimate long cloud or service names.

### False Negatives and Evasion

The rule may miss activity that:

- remains at or below the configured counts or length;
- spreads queries across source addresses;
- distributes queries over longer than the rolling window;
- uses short, low-volume encoded names;
- uses encrypted DNS when query metadata is unavailable in the capture;
- falls outside the parser's DNS representation;
- uses missing or malformed query metadata; or
- relies on incomplete, malformed, or out-of-order timestamps.

The rule performs no entropy analysis, baseline learning, tunneling confirmation, payload inspection, domain reputation, or resolver correlation.

### Configuration

```yaml
rules:
  dns_anomaly:
    enabled: true
    query_threshold: 30
    unique_domain_threshold: 20
    long_domain_threshold: 70
    time_window_seconds: 60
```

Tune query and diversity thresholds with resolver behavior and the capture location in mind. Shared resolvers can aggregate many clients under one source address, while endpoint captures may show much lower normal volume. Long names are common in some cloud, service-discovery, and tracking workflows.

## Rule Interactions

Rules maintain independent state and the engine does not merge, score, or correlate alerts.

- A TCP sequence can trigger both `PORT_SCAN_001` and `CONNECTION_BURST_001` when it crosses both rules' conditions.
- DNS processing is independent from the TCP rules.
- One DNS query contributes simultaneously to query volume, unique-domain state, and the per-packet length check.
- One DNS packet can return up to three ordered alerts when all variant boundaries are crossed together.
- Configured alert order follows `PortScanRule`, `ConnectionBurstRule`, then `DNSAnomalyRule` for each packet.

Engine statistics count every returned alert. Suppression and re-arming remain local to each rule and state key.

## Evidence Design

Alert evidence is designed to be:

- structured and JSON-serializable;
- derived from normalized metadata rather than raw Scapy objects;
- deterministic where ordering is meaningful;
- compact or bounded for destination distributions and DNS domain samples; and
- directly relevant to the rule condition.

The port-scan alert intentionally includes its complete sorted active-port set rather than a top-five sample. No rule stores full packet payloads in evidence. Evidence provides context for investigation and should be correlated with firewall, resolver, endpoint, authentication, and service telemetry where available.

## Configuration and Validation

Configuration is optional. Without a YAML file, all three rules are enabled and use defaults matching their constructors. Missing sections and fields retain defaults. Rules may be disabled independently, and disabling every rule is valid.

Validation enforces:

- only known top-level, rule, and field names;
- actual boolean values for `enabled`;
- positive integers for thresholds;
- positive finite integers or floats for windows;
- rejection of booleans as numeric values; and
- no string-to-number coercion.

Constructor validation applies the same positive threshold and finite-window constraints to rules created directly, raising `ValueError` for invalid values. YAML loading reports invalid configuration through `ConfigError`.

See the annotated [example configuration](../examples/config.example.yaml) and the [README configuration section](../README.md#configuration).

## Threshold Tuning Guidance

Suitable thresholds depend on network size, capture location, capture completeness, expected workloads, approved scanning tools, resolver activity, application retry behavior, and the duration represented by the PCAP. The defaults are transparent project defaults, not universal security policy.

A practical tuning process is:

1. Establish expected traffic patterns for the monitored context.
2. Analyze authorized historical or synthetic captures.
3. Review alerts and identify explainable false positives.
4. Adjust one threshold or window at a time.
5. Document local values and why they were selected.
6. Re-test after application, infrastructure, or capture-point changes.
7. Correlate alerts with independent logs before drawing conclusions.

Lower count thresholds generally increase sensitivity and alert volume. Longer windows generally increase sensitivity and retained state. Higher thresholds and shorter windows can reduce noise but can also increase false negatives. Mini IDS does not learn baselines or tune itself automatically.

## Testing and Validation

Rule behavior is covered with fixed `PacketInfo` fixtures, constructor-validation tests, exact threshold boundaries, inclusive-window expiry, state isolation, duplicate suppression, re-arming, deterministic evidence, engine coexistence, synthetic CLI PCAPs, and committed sample contracts.

The current verified suite contains 465 passing tests with 99% statement coverage. These results provide regression confidence; they do not prove detection effectiveness, production security, or suitability of the defaults for a particular network. See the [Testing Report](testing-report.md) and [PCAP Safety and Samples](../pcaps/README.md).

## Limitations

Current rule behavior is deliberately constrained:

- heuristic thresholds rather than signatures or learned baselines;
- normalized packet metadata only;
- no flow or TCP session reconstruction;
- no payload inspection or encrypted-traffic decryption;
- no threat-intelligence or reputation enrichment;
- packet-driven rather than timer-driven expiry;
- no persistent rule state between analyses;
- no cross-run or cross-rule correlation;
- no automatic blocking or remediation;
- dependence on capture completeness, ordering, and timestamps; and
- no proof of malicious intent from an alert or MITRE mapping.

## Adding a Future Rule

The current development pattern is:

1. Subclass `DetectionRule` and define stable metadata.
2. Accept one normalized `PacketInfo` at a time.
3. Return zero or more structured `Alert` objects.
4. Validate constructor values explicitly.
5. Keep state on the rule instance when required.
6. Add focused eligibility, boundary, state, evidence, and engine tests.
7. Add a typed configuration model only when the rule is configurable.
8. Add enabled construction in a documented deterministic order.
9. Update rule documentation and safe samples where relevant.

This is contributor guidance, not a runtime plugin API. The project does not dynamically discover or import rules.

## Quick Reference

| Setting | Default | Alert boundary |
| --- | ---: | --- |
| Port-scan distinct ports | 10 | 11th distinct port |
| Port-scan window | 60 s | Inclusive |
| Connection attempts | 50 | 51st attempt |
| Connection window | 60 s | Inclusive |
| DNS queries | 30 | 31st query |
| DNS unique domains | 20 | 21st normalized domain |
| DNS long-domain length | 70 | 71 characters |
| DNS window | 60 s | Inclusive |

## Related Documentation

- [Architecture](architecture.md)
- [Threat Model](threat-model.md)
- [Testing Report](testing-report.md)
- [Example Configuration](../examples/config.example.yaml)
- [PCAP Safety and Samples](../pcaps/README.md)
- [Project README](../README.md)
