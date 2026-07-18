import pytest

from mini_ids.models import Alert, PacketInfo, Severity
from mini_ids.rules import DetectionRule


class DummyRule(DetectionRule):
    rule_id = "TEST-001"
    name = "Dummy Rule"
    description = "A test-only detection rule."
    severity: Severity = "LOW"

    def __init__(self, alerts: list[Alert] | None = None) -> None:
        self.alerts = alerts if alerts is not None else []
        self.processed_packets: list[PacketInfo] = []

    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        self.processed_packets.append(packet)
        return list(self.alerts)


def test_detection_rule_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        DetectionRule()


def test_dummy_rule_exposes_required_metadata() -> None:
    rule = DummyRule()

    assert rule.rule_id == "TEST-001"
    assert rule.name == "Dummy Rule"
    assert rule.description == "A test-only detection rule."
    assert rule.severity == "LOW"


def test_dummy_rule_accepts_packet_and_can_retain_state(
    normal_tcp_packets: list[PacketInfo],
) -> None:
    rule = DummyRule()
    packet = normal_tcp_packets[0]

    rule.process_packet(packet)

    assert rule.processed_packets == [packet]


def test_dummy_rule_can_return_no_alerts(
    normal_tcp_packets: list[PacketInfo],
) -> None:
    rule = DummyRule()

    assert rule.process_packet(normal_tcp_packets[0]) == []


def test_dummy_rule_can_return_valid_alerts(
    normal_tcp_packets: list[PacketInfo],
) -> None:
    alerts = [
        Alert(
            timestamp="2024-07-03T09:46:40Z",
            rule_id="TEST-001",
            rule_name="Dummy Rule",
            severity="LOW",
            description="Test alert one.",
        ),
        Alert(
            timestamp="2024-07-03T09:46:41Z",
            rule_id="TEST-001",
            rule_name="Dummy Rule",
            severity="LOW",
            description="Test alert two.",
        ),
    ]
    rule = DummyRule(alerts)

    result = rule.process_packet(normal_tcp_packets[0])

    assert result == alerts
    assert all(isinstance(alert, Alert) for alert in result)
