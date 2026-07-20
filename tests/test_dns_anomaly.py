import json

import pytest

from mini_ids.engine import DetectionEngine
from mini_ids.models import Alert, PacketInfo
from mini_ids.rules import (
    ConnectionBurstRule,
    DNSAnomalyRule,
    DetectionRule,
    PortScanRule,
)


BASE_TIMESTAMP = 1_720_000_000.0


def make_dns_packet(
    *,
    timestamp: object = BASE_TIMESTAMP,
    source_ip: str | None = "192.0.2.70",
    destination_ip: str | None = "198.51.100.53",
    domain: object = "example.com",
    protocol: str = "DNS",
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,  # type: ignore[arg-type]
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=53000,
        dst_port=53,
        protocol=protocol,
        packet_length=82,
        dns_query=domain,  # type: ignore[arg-type]
        raw_summary="Synthetic DNS query",
    )


def process_sequence(
    rule: DNSAnomalyRule,
    packets: list[PacketInfo],
) -> list[Alert]:
    return [
        alert
        for packet in packets
        for alert in rule.process_packet(packet)
    ]


def test_rule_metadata_and_subclass_relationship() -> None:
    rule = DNSAnomalyRule()

    assert isinstance(rule, DetectionRule)
    assert rule.rule_id == "DNS_ANOMALY_001"
    assert rule.name == "DNS Anomaly Detection"
    assert rule.severity == "MEDIUM"
    assert "DNS" in rule.description


def test_constructor_defaults() -> None:
    rule = DNSAnomalyRule()

    assert rule.query_threshold == 30
    assert rule.unique_domain_threshold == 20
    assert rule.long_domain_threshold == 70
    assert rule.time_window_seconds == 60.0


def test_custom_thresholds_and_window() -> None:
    rule = DNSAnomalyRule(
        query_threshold=5,
        unique_domain_threshold=4,
        long_domain_threshold=40,
        time_window_seconds=15.5,
    )

    assert rule.query_threshold == 5
    assert rule.unique_domain_threshold == 4
    assert rule.long_domain_threshold == 40
    assert rule.time_window_seconds == 15.5


@pytest.mark.parametrize(
    "field_name",
    [
        "query_threshold",
        "unique_domain_threshold",
        "long_domain_threshold",
    ],
)
@pytest.mark.parametrize("value", [True, "10", 0, -1, 1.5])
def test_invalid_thresholds_are_rejected(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match=field_name):
        DNSAnomalyRule(**{field_name: value})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [True, "60", 0, -1, float("inf"), float("nan")],
)
def test_invalid_time_windows_are_rejected(value: object) -> None:
    with pytest.raises(ValueError, match="time_window_seconds"):
        DNSAnomalyRule(time_window_seconds=value)  # type: ignore[arg-type]


def test_non_dns_traffic_is_ignored() -> None:
    rule = DNSAnomalyRule(query_threshold=1)

    assert rule.process_packet(make_dns_packet(protocol="UDP")) == []
    assert rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1, protocol="TCP")
    ) == []


@pytest.mark.parametrize("domain", [None, "", ".", b"example.com"])
def test_missing_or_unsupported_dns_queries_are_ignored(domain: object) -> None:
    rule = DNSAnomalyRule(long_domain_threshold=1)

    assert rule.process_packet(make_dns_packet(domain=domain)) == []


def test_missing_source_ip_is_ignored() -> None:
    rule = DNSAnomalyRule(query_threshold=1)

    assert rule.process_packet(make_dns_packet(source_ip=None)) == []


@pytest.mark.parametrize(
    "timestamp",
    [
        True,
        "invalid",
        0,
        -1,
        float("inf"),
        float("nan"),
        1e308,
        10**1000,
    ],
)
def test_unusable_timestamps_are_ignored(timestamp: object) -> None:
    rule = DNSAnomalyRule(long_domain_threshold=1)

    assert rule.process_packet(make_dns_packet(timestamp=timestamp)) == []


def test_domain_normalization_lowercases_and_removes_one_trailing_dot() -> None:
    rule = DNSAnomalyRule(long_domain_threshold=5)

    alert = rule.process_packet(make_dns_packet(domain="Example.COM."))[0]

    assert alert.evidence["normalized_domain"] == "example.com"
    assert alert.evidence["domain_length"] == 11


def test_normalization_removes_only_one_trailing_dot() -> None:
    rule = DNSAnomalyRule(long_domain_threshold=5)

    alert = rule.process_packet(make_dns_packet(domain="EXAMPLE.COM.."))[0]

    assert alert.evidence["normalized_domain"] == "example.com."


def test_repeated_queries_count_separately_for_query_volume() -> None:
    rule = DNSAnomalyRule(query_threshold=2)
    packets = [
        make_dns_packet(timestamp=BASE_TIMESTAMP + index)
        for index in range(3)
    ]

    alerts = process_sequence(rule, packets)

    assert [alert.evidence["anomaly_type"] for alert in alerts] == [
        "query_burst"
    ]
    assert alerts[0].evidence["active_query_count"] == 3


def test_repeated_normalized_domains_count_once_for_unique_volume() -> None:
    rule = DNSAnomalyRule(
        query_threshold=10,
        unique_domain_threshold=1,
    )
    packets = [
        make_dns_packet(domain="Example.COM."),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1, domain="example.com"),
    ]

    assert process_sequence(rule, packets) == []


def test_state_is_isolated_by_source_ip() -> None:
    rule = DNSAnomalyRule(query_threshold=2)
    packets = [
        make_dns_packet(source_ip="192.0.2.1"),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1, source_ip="192.0.2.2"),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 2, source_ip="192.0.2.1"),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 3, source_ip="192.0.2.2"),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 4, source_ip="192.0.2.1"),
    ]

    alerts = process_sequence(rule, packets)

    assert len(alerts) == 1
    assert alerts[0].src_ip == "192.0.2.1"


def test_expired_queries_leave_the_rolling_window() -> None:
    rule = DNSAnomalyRule(query_threshold=2, time_window_seconds=10)
    packets = [
        make_dns_packet(timestamp=BASE_TIMESTAMP),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 11.1),
    ]

    assert process_sequence(rule, packets) == []


def test_query_at_exact_window_boundary_is_retained() -> None:
    rule = DNSAnomalyRule(query_threshold=2, time_window_seconds=10)
    packets = [
        make_dns_packet(timestamp=BASE_TIMESTAMP),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 5),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 10),
    ]

    alerts = process_sequence(rule, packets)

    assert len(alerts) == 1
    assert alerts[0].evidence["active_query_count"] == 3


def test_default_query_threshold_alerts_on_31st_query() -> None:
    rule = DNSAnomalyRule(unique_domain_threshold=100)
    packets = [
        make_dns_packet(timestamp=BASE_TIMESTAMP + index, domain="example.com")
        for index in range(31)
    ]

    assert process_sequence(rule, packets[:30]) == []
    alerts = rule.process_packet(packets[30])

    assert len(alerts) == 1
    assert alerts[0].evidence["anomaly_type"] == "query_burst"
    assert alerts[0].evidence["active_query_count"] == 31


def test_default_unique_domain_threshold_alerts_on_21st_domain() -> None:
    rule = DNSAnomalyRule(query_threshold=100)
    packets = [
        make_dns_packet(
            timestamp=BASE_TIMESTAMP + index,
            domain=f"domain-{index:02d}.example",
        )
        for index in range(21)
    ]

    assert process_sequence(rule, packets[:20]) == []
    alerts = rule.process_packet(packets[20])

    assert len(alerts) == 1
    assert alerts[0].evidence["anomaly_type"] == "unique_domain_burst"
    assert alerts[0].evidence["active_unique_domain_count"] == 21


def test_long_domain_threshold_alerts_only_above_70_characters() -> None:
    rule = DNSAnomalyRule()
    domain_70 = f"{'a' * 66}.com"
    domain_71 = f"{'b' * 67}.com"

    assert len(domain_70) == 70
    assert len(domain_71) == 71
    assert rule.process_packet(make_dns_packet(domain=domain_70)) == []
    alerts = rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1, domain=domain_71)
    )

    assert len(alerts) == 1
    assert alerts[0].evidence["anomaly_type"] == "long_domain"
    assert alerts[0].evidence["domain_length"] == 71


def test_query_burst_alert_is_suppressed_while_above_threshold() -> None:
    rule = DNSAnomalyRule(query_threshold=2)

    alerts = process_sequence(
        rule,
        [
            make_dns_packet(timestamp=BASE_TIMESTAMP + index)
            for index in range(5)
        ],
    )

    assert [alert.evidence["anomaly_type"] for alert in alerts] == [
        "query_burst"
    ]


def test_query_burst_rearms_after_expiry() -> None:
    rule = DNSAnomalyRule(query_threshold=2, time_window_seconds=10)
    first_alerts = process_sequence(
        rule,
        [
            make_dns_packet(timestamp=BASE_TIMESTAMP + index)
            for index in range(3)
        ],
    )
    rearm_packet = make_dns_packet(timestamp=BASE_TIMESTAMP + 12.1)
    second_packets = [
        make_dns_packet(timestamp=BASE_TIMESTAMP + 12.2),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 12.3),
    ]

    assert len(first_alerts) == 1
    assert rule.process_packet(rearm_packet) == []
    second_alerts = process_sequence(rule, second_packets)
    assert len(second_alerts) == 1
    assert second_alerts[0].evidence["anomaly_type"] == "query_burst"


def test_unique_domain_alert_is_suppressed_while_above_threshold() -> None:
    rule = DNSAnomalyRule(query_threshold=100, unique_domain_threshold=2)

    alerts = process_sequence(
        rule,
        [
            make_dns_packet(
                timestamp=BASE_TIMESTAMP + index,
                domain=f"domain-{index}.example",
            )
            for index in range(5)
        ],
    )

    assert [alert.evidence["anomaly_type"] for alert in alerts] == [
        "unique_domain_burst"
    ]


def test_unique_domain_alert_rearms_after_expiry() -> None:
    rule = DNSAnomalyRule(
        query_threshold=100,
        unique_domain_threshold=2,
        time_window_seconds=10,
    )
    first_alerts = process_sequence(
        rule,
        [
            make_dns_packet(
                timestamp=BASE_TIMESTAMP + index,
                domain=f"first-{index}.example",
            )
            for index in range(3)
        ],
    )
    rearm_packet = make_dns_packet(
        timestamp=BASE_TIMESTAMP + 12.1,
        domain="second-0.example",
    )
    second_packets = [
        make_dns_packet(
            timestamp=BASE_TIMESTAMP + 12.2,
            domain="second-1.example",
        ),
        make_dns_packet(
            timestamp=BASE_TIMESTAMP + 12.3,
            domain="second-2.example",
        ),
    ]

    assert len(first_alerts) == 1
    assert rule.process_packet(rearm_packet) == []
    second_alerts = process_sequence(rule, second_packets)
    assert len(second_alerts) == 1
    assert second_alerts[0].evidence["anomaly_type"] == "unique_domain_burst"


def test_identical_long_domains_are_suppressed_within_window() -> None:
    rule = DNSAnomalyRule(long_domain_threshold=5, time_window_seconds=10)
    first = rule.process_packet(make_dns_packet(domain="long.example"))
    repeated = rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1, domain="LONG.EXAMPLE.")
    )

    assert len(first) == 1
    assert repeated == []


def test_long_domain_suppression_rearms_after_last_repeat_expires() -> None:
    rule = DNSAnomalyRule(long_domain_threshold=5, time_window_seconds=10)
    packet = make_dns_packet(domain="long.example")
    repeated = make_dns_packet(
        timestamp=BASE_TIMESTAMP + 1,
        domain="long.example",
    )
    rearmed = make_dns_packet(
        timestamp=BASE_TIMESTAMP + 11.1,
        domain="long.example",
    )

    assert len(rule.process_packet(packet)) == 1
    assert rule.process_packet(repeated) == []
    assert len(rule.process_packet(rearmed)) == 1


def test_out_of_order_packet_is_ignored_without_corrupting_state() -> None:
    rule = DNSAnomalyRule(query_threshold=1)

    assert rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 10)
    ) == []
    assert rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 9)
    ) == []
    alerts = rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 11)
    )

    assert len(alerts) == 1
    assert alerts[0].evidence["active_query_count"] == 2


def test_query_burst_alert_fields_and_evidence_are_structured() -> None:
    rule = DNSAnomalyRule(query_threshold=1)
    rule.process_packet(make_dns_packet())

    alert = rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 1)
    )[0]

    assert alert.rule_id == "DNS_ANOMALY_001"
    assert alert.rule_name == "DNS Anomaly Detection"
    assert alert.severity == "MEDIUM"
    assert alert.src_ip == "192.0.2.70"
    assert alert.dst_ip == "198.51.100.53"
    assert alert.protocol == "DNS"
    assert alert.evidence == {
        "anomaly_type": "query_burst",
        "source_ip": "192.0.2.70",
        "active_query_count": 2,
        "query_threshold": 1,
        "time_window_seconds": 60.0,
        "first_active_timestamp": "2024-07-03T09:46:40Z",
        "latest_active_timestamp": "2024-07-03T09:46:41Z",
    }
    assert alert.mitre_attack == "T1071.004 - Application Layer Protocol: DNS"
    assert alert.recommendation is not None
    json.dumps(alert.to_dict())


def test_unique_domain_sample_is_bounded_and_deterministic() -> None:
    rule = DNSAnomalyRule(query_threshold=100, unique_domain_threshold=5)
    domains = [
        "z.example",
        "b.example",
        "f.example",
        "a.example",
        "e.example",
        "c.example",
    ]

    alerts = process_sequence(
        rule,
        [
            make_dns_packet(
                timestamp=BASE_TIMESTAMP + index,
                domain=domain,
            )
            for index, domain in enumerate(domains)
        ],
    )

    assert alerts[0].evidence["domain_sample"] == [
        "a.example",
        "b.example",
        "c.example",
        "e.example",
        "f.example",
    ]


def test_independent_anomaly_types_can_alert_on_one_packet() -> None:
    rule = DNSAnomalyRule(
        query_threshold=1,
        unique_domain_threshold=1,
        long_domain_threshold=5,
    )
    rule.process_packet(make_dns_packet(domain="first.example"))

    alerts = rule.process_packet(
        make_dns_packet(
            timestamp=BASE_TIMESTAMP + 1,
            domain="second.example",
        )
    )

    assert [alert.evidence["anomaly_type"] for alert in alerts] == [
        "query_burst",
        "unique_domain_burst",
        "long_domain",
    ]


def test_rule_works_through_detection_engine() -> None:
    engine = DetectionEngine(
        [
            DNSAnomalyRule(
                query_threshold=1,
                unique_domain_threshold=10,
                long_domain_threshold=100,
            )
        ]
    )

    alerts = engine.process_packets(
        [
            make_dns_packet(),
            make_dns_packet(timestamp=BASE_TIMESTAMP + 1),
        ]
    )

    assert len(alerts) == 1
    assert isinstance(alerts[0], Alert)
    assert engine.get_summary()["alerts_generated"] == 1


def test_all_concrete_rules_coexist_without_state_corruption() -> None:
    dns_rule = DNSAnomalyRule(query_threshold=1)
    engine = DetectionEngine(
        [
            PortScanRule(port_threshold=1),
            ConnectionBurstRule(connection_threshold=1),
            dns_rule,
        ]
    )
    tcp_packets = [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + index,
            src_ip="192.0.2.80",
            dst_ip="198.51.100.80",
            src_port=44000 + index,
            dst_port=80 + index,
            protocol="TCP",
            packet_length=60,
            tcp_flags="S",
        )
        for index in range(2)
    ]
    dns_packets = [
        make_dns_packet(timestamp=BASE_TIMESTAMP + 2),
        make_dns_packet(timestamp=BASE_TIMESTAMP + 3),
    ]

    alerts = engine.process_packets([*tcp_packets, *dns_packets])

    assert [alert.rule_id for alert in alerts] == [
        "PORT_SCAN_001",
        "CONNECTION_BURST_001",
        "DNS_ANOMALY_001",
    ]
    assert dns_rule.process_packet(
        make_dns_packet(timestamp=BASE_TIMESTAMP + 4)
    ) == []
