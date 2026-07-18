from dataclasses import replace

import pytest

from mini_ids.engine import DetectionEngine
from mini_ids.models import Alert, PacketInfo
from mini_ids.rules import DetectionRule, PortScanRule


BASE_TIMESTAMP = 1_720_000_000.0


def make_syn_packet(
    destination_port: int,
    *,
    timestamp: float = BASE_TIMESTAMP,
    source_ip: str = "192.0.2.50",
    destination_ip: str = "198.51.100.30",
    protocol: str = "TCP",
    tcp_flags: str | None = "S",
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=41000,
        dst_port=destination_port,
        protocol=protocol,
        packet_length=60,
        tcp_flags=tcp_flags,
        raw_summary=f"TCP SYN to destination port {destination_port}",
    )


def process_ports(
    rule: PortScanRule,
    ports: list[int],
    *,
    start_timestamp: float = BASE_TIMESTAMP,
    source_ip: str = "192.0.2.50",
    destination_ip: str = "198.51.100.30",
) -> list[Alert]:
    alerts: list[Alert] = []
    for offset, port in enumerate(ports):
        alerts.extend(
            rule.process_packet(
                make_syn_packet(
                    port,
                    timestamp=start_timestamp + offset,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                )
            )
        )
    return alerts


def test_rule_metadata_and_subclass_relationship() -> None:
    rule = PortScanRule()

    assert isinstance(rule, DetectionRule)
    assert rule.rule_id == "PORT_SCAN_001"
    assert rule.name == "Vertical TCP Port Scan"
    assert rule.severity == "MEDIUM"
    assert rule.port_threshold == 10
    assert rule.time_window_seconds == 60.0


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("port_threshold", 0, "port_threshold"),
        ("time_window_seconds", 0, "time_window_seconds"),
        ("time_window_seconds", float("inf"), "time_window_seconds"),
    ],
)
def test_rule_rejects_invalid_configuration(
    keyword: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PortScanRule(**{keyword: value})  # type: ignore[arg-type]


def test_normal_low_volume_tcp_traffic_produces_no_alert(
    normal_tcp_packets: list[PacketInfo],
) -> None:
    rule = PortScanRule()

    assert all(rule.process_packet(packet) == [] for packet in normal_tcp_packets)


def test_non_tcp_traffic_is_ignored(
    normal_udp_packets: list[PacketInfo],
) -> None:
    rule = PortScanRule(port_threshold=1)

    assert all(rule.process_packet(packet) == [] for packet in normal_udp_packets)


def test_tcp_packets_without_syn_are_ignored() -> None:
    rule = PortScanRule(port_threshold=1)

    assert rule.process_packet(make_syn_packet(80, tcp_flags="PA")) == []
    assert rule.process_packet(make_syn_packet(443, tcp_flags="A")) == []


def test_syn_ack_packets_are_ignored() -> None:
    rule = PortScanRule(port_threshold=1)

    assert rule.process_packet(make_syn_packet(80, tcp_flags="SA")) == []
    assert rule.process_packet(make_syn_packet(443, tcp_flags="AS")) == []


@pytest.mark.parametrize(
    "changes",
    [
        {"src_ip": None},
        {"dst_ip": None},
        {"dst_port": None},
    ],
)
def test_packets_missing_required_metadata_are_ignored(
    changes: dict[str, object],
) -> None:
    rule = PortScanRule(port_threshold=1)
    packet = replace(make_syn_packet(80), **changes)

    assert rule.process_packet(packet) == []


def test_repeated_syn_attempts_to_same_port_count_once() -> None:
    rule = PortScanRule(port_threshold=1)

    for offset in range(5):
        assert rule.process_packet(
            make_syn_packet(80, timestamp=BASE_TIMESTAMP + offset)
        ) == []

    alerts = rule.process_packet(make_syn_packet(443, timestamp=BASE_TIMESTAMP + 5))

    assert len(alerts) == 1
    assert alerts[0].evidence["distinct_port_count"] == 2
    assert alerts[0].evidence["destination_ports"] == [80, 443]


def test_different_destination_ports_are_counted() -> None:
    rule = PortScanRule(port_threshold=2)

    alerts = process_ports(rule, [22, 80, 443])

    assert len(alerts) == 1
    assert alerts[0].evidence["distinct_port_count"] == 3


def test_traffic_is_isolated_by_source_ip() -> None:
    rule = PortScanRule(port_threshold=2)

    assert process_ports(rule, [22, 80], source_ip="192.0.2.10") == []
    assert process_ports(rule, [22, 80], source_ip="192.0.2.11") == []

    alerts = rule.process_packet(
        make_syn_packet(443, timestamp=BASE_TIMESTAMP + 2, source_ip="192.0.2.10")
    )

    assert len(alerts) == 1
    assert alerts[0].src_ip == "192.0.2.10"


def test_traffic_is_isolated_by_destination_ip() -> None:
    rule = PortScanRule(port_threshold=2)

    assert process_ports(rule, [22, 80], destination_ip="198.51.100.10") == []
    assert process_ports(rule, [22, 80], destination_ip="198.51.100.11") == []

    alerts = rule.process_packet(
        make_syn_packet(
            443,
            timestamp=BASE_TIMESTAMP + 2,
            destination_ip="198.51.100.10",
        )
    )

    assert len(alerts) == 1
    assert alerts[0].dst_ip == "198.51.100.10"


def test_ports_outside_rolling_window_expire() -> None:
    rule = PortScanRule(port_threshold=2, time_window_seconds=10)

    assert rule.process_packet(make_syn_packet(22, timestamp=BASE_TIMESTAMP)) == []
    assert rule.process_packet(make_syn_packet(80, timestamp=BASE_TIMESTAMP + 1)) == []
    assert rule.process_packet(make_syn_packet(443, timestamp=BASE_TIMESTAMP + 11)) == []


def test_time_window_includes_observations_at_exact_boundary() -> None:
    rule = PortScanRule(port_threshold=2, time_window_seconds=10)

    assert rule.process_packet(make_syn_packet(22, timestamp=BASE_TIMESTAMP)) == []
    assert rule.process_packet(make_syn_packet(80, timestamp=BASE_TIMESTAMP + 5)) == []
    alerts = rule.process_packet(make_syn_packet(443, timestamp=BASE_TIMESTAMP + 10))

    assert len(alerts) == 1


def test_default_threshold_requires_more_than_ten_distinct_ports(
    port_scan_like_packets: list[PacketInfo],
) -> None:
    rule = PortScanRule()

    assert all(rule.process_packet(packet) == [] for packet in port_scan_like_packets)

    eleventh_packet = make_syn_packet(
        8080,
        timestamp=port_scan_like_packets[-1].timestamp + 1,
    )
    alerts = rule.process_packet(eleventh_packet)

    assert len(alerts) == 1
    assert alerts[0].evidence["distinct_port_count"] == 11


def test_alert_contains_expected_structured_details() -> None:
    rule = PortScanRule(port_threshold=2, time_window_seconds=30)

    alert = process_ports(rule, [443, 22, 80])[0]

    assert isinstance(alert, Alert)
    assert alert.rule_id == rule.rule_id
    assert alert.rule_name == rule.name
    assert alert.severity == "MEDIUM"
    assert alert.src_ip == "192.0.2.50"
    assert alert.dst_ip == "198.51.100.30"
    assert alert.protocol == "TCP"
    assert alert.evidence == {
        "source_ip": "192.0.2.50",
        "destination_ip": "198.51.100.30",
        "distinct_port_count": 3,
        "destination_ports": [22, 80, 443],
        "port_threshold": 2,
        "time_window_seconds": 30.0,
    }
    assert alert.mitre_attack == "T1046 - Network Service Discovery"
    assert alert.recommendation is not None
    assert "authorized" in alert.recommendation


def test_only_one_alert_is_generated_while_pair_remains_above_threshold() -> None:
    rule = PortScanRule(port_threshold=2)

    alerts = process_ports(rule, [22, 80, 443, 8080, 8443])

    assert len(alerts) == 1


def test_rule_rearms_after_window_returns_pair_to_non_alerting_range() -> None:
    rule = PortScanRule(port_threshold=2, time_window_seconds=10)

    assert len(process_ports(rule, [22, 80, 443])) == 1

    later_alerts = process_ports(
        rule,
        [8080, 8443, 9000],
        start_timestamp=BASE_TIMESTAMP + 20,
    )

    assert len(later_alerts) == 1
    assert later_alerts[0].evidence["destination_ports"] == [8080, 8443, 9000]


@pytest.mark.parametrize(
    "timestamp",
    [0.0, -1.0, float("nan"), float("inf")],
)
def test_unusable_timestamps_are_ignored(timestamp: float) -> None:
    rule = PortScanRule(port_threshold=1)

    assert rule.process_packet(make_syn_packet(80, timestamp=timestamp)) == []


def test_out_of_order_timestamp_is_ignored() -> None:
    rule = PortScanRule(port_threshold=2)

    assert rule.process_packet(make_syn_packet(22, timestamp=BASE_TIMESTAMP + 10)) == []
    assert rule.process_packet(make_syn_packet(80, timestamp=BASE_TIMESTAMP + 5)) == []
    assert rule.process_packet(make_syn_packet(443, timestamp=BASE_TIMESTAMP + 11)) == []
    alerts = rule.process_packet(make_syn_packet(8080, timestamp=BASE_TIMESTAMP + 12))

    assert len(alerts) == 1
    assert alerts[0].evidence["destination_ports"] == [22, 443, 8080]


def test_rule_generates_structured_alert_through_detection_engine() -> None:
    rule = PortScanRule(port_threshold=2)
    engine = DetectionEngine([rule])
    packets = [
        make_syn_packet(port, timestamp=BASE_TIMESTAMP + offset)
        for offset, port in enumerate([22, 80, 443])
    ]

    alerts = engine.process_packets(packets)
    summary = engine.get_summary()

    assert len(alerts) == 1
    assert isinstance(alerts[0], Alert)
    assert alerts[0].rule_id == rule.rule_id
    assert summary["packets_processed"] == 3
    assert summary["alerts_generated"] == 1
    assert summary["severity_counts"] == {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 0,
        "CRITICAL": 0,
    }
