import json
from dataclasses import FrozenInstanceError

import pytest

from mini_ids.models import Alert, PacketInfo


def test_packet_info_can_represent_tcp_packet() -> None:
    packet = PacketInfo(
        timestamp=1720000000.0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=51514,
        dst_port=443,
        protocol="TCP",
        packet_length=74,
        tcp_flags="S",
        raw_summary="TCP 192.168.1.10:51514 -> 192.168.1.20:443",
    )

    assert packet.protocol == "TCP"
    assert packet.src_port == 51514
    assert packet.dst_port == 443
    assert packet.tcp_flags == "S"


def test_packet_info_can_represent_udp_packet() -> None:
    packet = PacketInfo(
        timestamp=1720000001.0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        src_port=5353,
        dst_port=5353,
        protocol="UDP",
        packet_length=90,
    )

    assert packet.protocol == "UDP"
    assert packet.tcp_flags is None
    assert packet.dns_query is None


def test_packet_info_can_represent_dns_packet() -> None:
    packet = PacketInfo(
        timestamp=1720000002.0,
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="DNS",
        packet_length=82,
        dns_query="example.com",
        dns_response="93.184.216.34",
    )

    assert packet.protocol == "DNS"
    assert packet.dns_query == "example.com"
    assert packet.dns_response == "93.184.216.34"


def test_packet_info_can_represent_other_packet() -> None:
    packet = PacketInfo(
        timestamp=1720000003.0,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol="OTHER",
        packet_length=60,
        raw_summary="Unsupported packet",
    )

    assert packet.protocol == "OTHER"
    assert packet.src_ip is None
    assert packet.dst_port is None


def test_packet_info_serializes_to_dict() -> None:
    packet = PacketInfo(
        timestamp=1720000004.0,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        packet_length=66,
        tcp_flags="PA",
    )

    assert packet.to_dict() == {
        "timestamp": 1720000004.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_length": 66,
        "tcp_flags": "PA",
        "dns_query": None,
        "dns_response": None,
        "raw_summary": None,
    }


def test_packet_info_serializes_to_json() -> None:
    packet = PacketInfo(
        timestamp=1720000005.0,
        src_ip="10.0.0.5",
        dst_ip="1.1.1.1",
        src_port=53001,
        dst_port=53,
        protocol="DNS",
        packet_length=70,
        dns_query="openai.com",
    )

    data = json.loads(packet.to_json())

    assert data["timestamp"] == 1720000005.0
    assert data["protocol"] == "DNS"
    assert data["dns_query"] == "openai.com"


def test_alert_can_be_created_with_basic_fields() -> None:
    alert = Alert(
        timestamp="2026-07-13T12:00:00Z",
        rule_id="TEST-001",
        rule_name="Test Rule",
        severity="LOW",
        description="A test alert was generated.",
    )

    assert alert.rule_id == "TEST-001"
    assert alert.severity == "LOW"
    assert alert.evidence == {}
    assert alert.src_ip is None


def test_alert_can_include_source_and_destination_details() -> None:
    alert = Alert(
        timestamp="2026-07-13T12:01:00Z",
        rule_id="SCAN-001",
        rule_name="Port Scan",
        severity="MEDIUM",
        description="Many destination ports were contacted.",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=51514,
        dst_port=443,
        protocol="TCP",
    )

    assert alert.src_ip == "192.168.1.10"
    assert alert.dst_ip == "192.168.1.20"
    assert alert.src_port == 51514
    assert alert.dst_port == 443
    assert alert.protocol == "TCP"


def test_alert_can_include_evidence() -> None:
    alert = Alert(
        timestamp="2026-07-13T12:02:00Z",
        rule_id="BURST-001",
        rule_name="Connection Burst",
        severity="HIGH",
        description="A source created many connections in a short window.",
        evidence={
            "connection_count": 75,
            "threshold": 50,
            "time_window_seconds": 60,
        },
    )

    assert alert.evidence["connection_count"] == 75
    assert alert.evidence["threshold"] == 50
    assert alert.evidence["time_window_seconds"] == 60


def test_alert_can_include_mitre_mapping() -> None:
    alert = Alert(
        timestamp="2026-07-13T12:03:00Z",
        rule_id="SCAN-001",
        rule_name="Port Scan",
        severity="MEDIUM",
        description="Many destination ports were contacted.",
        mitre_attack="T1046 - Network Service Discovery",
        recommendation="Review whether this source should contact many ports.",
    )

    assert alert.mitre_attack == "T1046 - Network Service Discovery"
    assert alert.recommendation == "Review whether this source should contact many ports."


def test_alert_serializes_to_dict() -> None:
    alert = Alert(
        timestamp="2026-07-13T12:04:00Z",
        rule_id="SCAN-001",
        rule_name="Port Scan",
        severity="MEDIUM",
        description="Many destination ports were contacted.",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=40000,
        dst_port=22,
        protocol="TCP",
        evidence={"unique_ports": 12, "threshold": 10},
        mitre_attack="T1046 - Network Service Discovery",
        recommendation="Investigate the source host.",
    )

    assert alert.to_dict() == {
        "timestamp": "2026-07-13T12:04:00Z",
        "rule_id": "SCAN-001",
        "rule_name": "Port Scan",
        "severity": "MEDIUM",
        "description": "Many destination ports were contacted.",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "src_port": 40000,
        "dst_port": 22,
        "protocol": "TCP",
        "evidence": {"unique_ports": 12, "threshold": 10},
        "mitre_attack": "T1046 - Network Service Discovery",
        "recommendation": "Investigate the source host.",
    }


def test_alert_serializes_to_json() -> None:
    alert = Alert(
        timestamp="2026-07-13T12:05:00Z",
        rule_id="DNS-001",
        rule_name="DNS Anomaly",
        severity="CRITICAL",
        description="Suspicious DNS activity was observed.",
        evidence={"query_count": 120},
        mitre_attack="T1071.004 - Application Layer Protocol: DNS",
    )

    data = json.loads(alert.to_json())

    assert data["rule_id"] == "DNS-001"
    assert data["severity"] == "CRITICAL"
    assert data["evidence"] == {"query_count": 120}
    assert data["mitre_attack"] == "T1071.004 - Application Layer Protocol: DNS"


def test_packet_info_fields_are_immutable() -> None:
    packet = PacketInfo(
        timestamp=1720000006.0,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_length=60,
    )

    with pytest.raises(FrozenInstanceError):
        packet.protocol = "UDP"  # type: ignore[misc]


def test_alert_fields_are_immutable_and_serialization_is_detached() -> None:
    alert = Alert(
        timestamp="2026-07-20T12:00:00Z",
        rule_id="TEST-IMMUTABLE",
        rule_name="Immutability Test",
        severity="LOW",
        description="Test immutable alert fields.",
        evidence={"ports": [22, 80]},
    )

    serialized = alert.to_dict()
    serialized_evidence = serialized["evidence"]
    assert isinstance(serialized_evidence, dict)
    ports = serialized_evidence["ports"]
    assert isinstance(ports, list)
    ports.append(443)

    with pytest.raises(FrozenInstanceError):
        alert.severity = "HIGH"  # type: ignore[misc]
    assert alert.evidence == {"ports": [22, 80]}
