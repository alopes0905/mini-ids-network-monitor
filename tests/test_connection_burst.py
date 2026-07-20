import json
from dataclasses import replace

import pytest

from mini_ids.engine import DetectionEngine
from mini_ids.models import Alert, PacketInfo
from mini_ids.rules import ConnectionBurstRule, DetectionRule, PortScanRule


BASE_TIMESTAMP = 1_720_000_000.0


def make_connection_attempt(
    *,
    timestamp: float = BASE_TIMESTAMP,
    source_ip: str | None = "192.0.2.60",
    destination_ip: str | None = "198.51.100.40",
    destination_port: int | None = 443,
    protocol: str = "TCP",
    tcp_flags: str | None = "S",
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=42000,
        dst_port=destination_port,
        protocol=protocol,
        packet_length=60,
        tcp_flags=tcp_flags,
        raw_summary="TCP initial connection attempt",
    )


def process_attempts(
    rule: ConnectionBurstRule,
    count: int,
    *,
    start_timestamp: float = BASE_TIMESTAMP,
    source_ip: str = "192.0.2.60",
    destination_ip: str | None = "198.51.100.40",
    destination_port: int | None = 443,
) -> list[Alert]:
    alerts: list[Alert] = []
    for offset in range(count):
        alerts.extend(
            rule.process_packet(
                make_connection_attempt(
                    timestamp=start_timestamp + offset,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                )
            )
        )
    return alerts


def test_rule_metadata_subclass_and_constructor_defaults() -> None:
    rule = ConnectionBurstRule()

    assert isinstance(rule, DetectionRule)
    assert rule.rule_id == "CONNECTION_BURST_001"
    assert rule.name == "TCP Connection Burst"
    assert rule.severity == "MEDIUM"
    assert rule.connection_threshold == 50
    assert rule.time_window_seconds == 60.0


def test_custom_threshold_and_time_window() -> None:
    rule = ConnectionBurstRule(connection_threshold=5, time_window_seconds=15)

    assert rule.connection_threshold == 5
    assert rule.time_window_seconds == 15.0


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("connection_threshold", 0, "connection_threshold"),
        ("connection_threshold", True, "connection_threshold"),
        ("connection_threshold", 1.5, "connection_threshold"),
        ("time_window_seconds", 0, "time_window_seconds"),
        ("time_window_seconds", True, "time_window_seconds"),
        ("time_window_seconds", "60", "time_window_seconds"),
        ("time_window_seconds", float("inf"), "time_window_seconds"),
    ],
)
def test_rule_rejects_invalid_configuration(
    keyword: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ConnectionBurstRule(**{keyword: value})  # type: ignore[arg-type]


def test_normal_low_volume_traffic_produces_no_alert(
    connection_burst_like_packets: list[PacketInfo],
) -> None:
    rule = ConnectionBurstRule()

    assert all(
        rule.process_packet(packet) == []
        for packet in connection_burst_like_packets
    )


def test_non_tcp_traffic_is_ignored(
    normal_udp_packets: list[PacketInfo],
) -> None:
    rule = ConnectionBurstRule(connection_threshold=1)

    assert all(rule.process_packet(packet) == [] for packet in normal_udp_packets)


@pytest.mark.parametrize("tcp_flags", [None, "", "A", "PA", "F", 1])
def test_tcp_packets_without_syn_are_ignored(tcp_flags: object) -> None:
    rule = ConnectionBurstRule(connection_threshold=1)
    packet = replace(make_connection_attempt(), tcp_flags=tcp_flags)

    assert rule.process_packet(packet) == []


@pytest.mark.parametrize("tcp_flags", ["SA", "AS"])
def test_syn_ack_packets_are_ignored(tcp_flags: str) -> None:
    rule = ConnectionBurstRule(connection_threshold=1)

    assert rule.process_packet(
        make_connection_attempt(tcp_flags=tcp_flags)
    ) == []


def test_repeated_attempts_to_same_target_count_separately() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)

    alerts = process_attempts(rule, 3)

    assert len(alerts) == 1
    assert alerts[0].evidence["connection_attempt_count"] == 3
    assert alerts[0].evidence["top_destination_ips"] == [
        {"destination_ip": "198.51.100.40", "attempt_count": 3}
    ]
    assert alerts[0].evidence["top_destination_ports"] == [
        {"destination_port": 443, "attempt_count": 3}
    ]


def test_attempts_to_different_destinations_are_aggregated() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)
    alerts: list[Alert] = []

    for offset in range(3):
        alerts.extend(
            rule.process_packet(
                make_connection_attempt(
                    timestamp=BASE_TIMESTAMP + offset,
                    destination_ip=f"198.51.100.{40 + offset}",
                    destination_port=440 + offset,
                )
            )
        )

    assert len(alerts) == 1
    assert alerts[0].evidence["connection_attempt_count"] == 3
    assert alerts[0].evidence["observed_destination_ip_count"] == 3


def test_traffic_is_isolated_by_source_ip() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)

    assert process_attempts(rule, 2, source_ip="192.0.2.10") == []
    assert process_attempts(rule, 2, source_ip="192.0.2.11") == []

    alerts = rule.process_packet(
        make_connection_attempt(
            timestamp=BASE_TIMESTAMP + 2,
            source_ip="192.0.2.10",
        )
    )

    assert len(alerts) == 1
    assert alerts[0].src_ip == "192.0.2.10"


def test_expired_attempts_leave_rolling_window() -> None:
    rule = ConnectionBurstRule(connection_threshold=2, time_window_seconds=10)

    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP)
    ) == []
    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 1)
    ) == []
    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 11)
    ) == []


def test_window_includes_attempts_at_exact_boundary() -> None:
    rule = ConnectionBurstRule(connection_threshold=2, time_window_seconds=10)

    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP)
    ) == []
    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 5)
    ) == []
    alerts = rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 10)
    )

    assert len(alerts) == 1


def test_exactly_fifty_attempts_do_not_alert() -> None:
    rule = ConnectionBurstRule()

    assert process_attempts(rule, 50) == []


def test_fifty_first_attempt_alerts() -> None:
    rule = ConnectionBurstRule()

    alerts = process_attempts(rule, 51)

    assert len(alerts) == 1
    assert alerts[0].evidence["connection_attempt_count"] == 51


def test_alert_is_suppressed_while_source_remains_above_threshold() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)

    alerts = process_attempts(rule, 6)

    assert len(alerts) == 1


def test_rule_rearms_after_expiry_returns_source_to_threshold_or_below() -> None:
    rule = ConnectionBurstRule(connection_threshold=2, time_window_seconds=10)

    assert len(process_attempts(rule, 3)) == 1

    later_alerts = process_attempts(
        rule,
        3,
        start_timestamp=BASE_TIMESTAMP + 20,
    )

    assert len(later_alerts) == 1
    assert later_alerts[0].evidence["connection_attempt_count"] == 3


def test_missing_destination_information_still_counts() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)

    alerts = process_attempts(
        rule,
        3,
        destination_ip=None,
        destination_port=None,
    )

    assert len(alerts) == 1
    assert alerts[0].evidence["observed_destination_ip_count"] == 0
    assert alerts[0].evidence["observed_destination_port_count"] == 0
    assert alerts[0].evidence["top_destination_ips"] == []
    assert alerts[0].evidence["top_destination_ports"] == []


def test_missing_source_ip_is_ignored() -> None:
    rule = ConnectionBurstRule(connection_threshold=1)

    assert rule.process_packet(make_connection_attempt(source_ip=None)) == []


@pytest.mark.parametrize(
    "timestamp",
    [0.0, -1.0, float("nan"), float("inf")],
)
def test_unusable_timestamps_are_ignored(timestamp: float) -> None:
    rule = ConnectionBurstRule(connection_threshold=1)

    assert rule.process_packet(
        make_connection_attempt(timestamp=timestamp)
    ) == []


@pytest.mark.parametrize("timestamp", [True, "invalid", 10**100])
def test_invalid_timestamp_types_and_ranges_are_ignored(timestamp: object) -> None:
    rule = ConnectionBurstRule(connection_threshold=1)
    packet = replace(make_connection_attempt(), timestamp=timestamp)

    assert rule.process_packet(packet) == []


def test_out_of_order_timestamp_is_ignored() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)

    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 10)
    ) == []
    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 5)
    ) == []
    assert rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 11)
    ) == []
    alerts = rule.process_packet(
        make_connection_attempt(timestamp=BASE_TIMESTAMP + 12)
    )

    assert len(alerts) == 1
    assert alerts[0].evidence["connection_attempt_count"] == 3


def test_alert_fields_and_evidence_are_correct() -> None:
    rule = ConnectionBurstRule(connection_threshold=2, time_window_seconds=30)

    alert = process_attempts(rule, 3)[0]

    assert isinstance(alert, Alert)
    assert alert.rule_id == rule.rule_id
    assert alert.rule_name == rule.name
    assert alert.severity == "MEDIUM"
    assert alert.src_ip == "192.0.2.60"
    assert alert.dst_ip is None
    assert alert.protocol == "TCP"
    assert alert.mitre_attack is None
    assert alert.evidence["source_ip"] == "192.0.2.60"
    assert alert.evidence["connection_attempt_count"] == 3
    assert alert.evidence["connection_threshold"] == 2
    assert alert.evidence["time_window_seconds"] == 30.0
    assert alert.evidence["first_active_timestamp"] == "2024-07-03T09:46:40Z"
    assert alert.evidence["latest_active_timestamp"] == "2024-07-03T09:46:42Z"
    assert alert.recommendation is not None
    assert "authentication" in alert.recommendation


def test_evidence_is_compact_and_json_serializable() -> None:
    rule = ConnectionBurstRule(connection_threshold=6)
    alerts: list[Alert] = []

    for offset in range(7):
        alerts.extend(
            rule.process_packet(
                make_connection_attempt(
                    timestamp=BASE_TIMESTAMP + offset,
                    destination_ip=f"198.51.100.{40 + offset}",
                    destination_port=440 + offset,
                )
            )
        )

    alert = alerts[0]
    serialized = json.loads(alert.to_json())

    assert len(alert.evidence["top_destination_ips"]) == 5
    assert len(alert.evidence["top_destination_ports"]) == 5
    assert serialized["evidence"]["connection_attempt_count"] == 7


def test_rule_generates_alert_through_detection_engine() -> None:
    rule = ConnectionBurstRule(connection_threshold=2)
    engine = DetectionEngine([rule])
    packets = [
        make_connection_attempt(timestamp=BASE_TIMESTAMP + offset)
        for offset in range(3)
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


def test_port_scan_and_connection_burst_rules_coexist_in_engine() -> None:
    port_scan_rule = PortScanRule(port_threshold=2)
    connection_burst_rule = ConnectionBurstRule(connection_threshold=2)
    engine = DetectionEngine([port_scan_rule, connection_burst_rule])
    packets = [
        make_connection_attempt(
            timestamp=BASE_TIMESTAMP + offset,
            destination_port=port,
        )
        for offset, port in enumerate([22, 80, 443])
    ]

    alerts = engine.process_packets(packets)

    assert [alert.rule_id for alert in alerts] == [
        port_scan_rule.rule_id,
        connection_burst_rule.rule_id,
    ]
    assert all(isinstance(alert, Alert) for alert in alerts)
    assert engine.get_summary()["alerts_generated"] == 2
