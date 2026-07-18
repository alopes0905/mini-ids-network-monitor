import json
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from mini_ids.models import PacketInfo


MOCK_PACKET_PATH = Path(__file__).resolve().parents[1] / "examples" / "mock_packets.json"
DOCUMENTATION_NETWORKS = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
)
PACKET_INFO_FIELDS = set(PacketInfo.__dataclass_fields__)


@pytest.mark.parametrize(
    "fixture_name",
    [
        "normal_tcp_packets",
        "normal_udp_packets",
        "normal_dns_packets",
        "port_scan_like_packets",
        "connection_burst_like_packets",
        "mixed_normal_packets",
        "other_packets",
    ],
)
def test_packet_fixtures_return_packet_info(
    request: pytest.FixtureRequest,
    fixture_name: str,
) -> None:
    packets = request.getfixturevalue(fixture_name)

    assert packets
    assert all(isinstance(packet, PacketInfo) for packet in packets)


def test_port_scan_like_fixture_has_one_source_and_many_destination_ports(
    port_scan_like_packets: list[PacketInfo],
) -> None:
    sources = {packet.src_ip for packet in port_scan_like_packets}
    destination_ports = {packet.dst_port for packet in port_scan_like_packets}

    assert sources == {"192.0.2.50"}
    assert len(destination_ports) >= 10
    assert all(packet.protocol == "TCP" for packet in port_scan_like_packets)


def test_connection_burst_like_fixture_has_one_source_in_short_window(
    connection_burst_like_packets: list[PacketInfo],
) -> None:
    sources = {packet.src_ip for packet in connection_burst_like_packets}
    timestamps = [packet.timestamp for packet in connection_burst_like_packets]
    time_window = max(timestamps) - min(timestamps)

    assert sources == {"192.0.2.60"}
    assert len(connection_burst_like_packets) >= 20
    assert time_window <= 5.0


def test_mock_packet_json_exists() -> None:
    assert MOCK_PACKET_PATH.exists()


def test_mock_packet_json_is_valid_json() -> None:
    data = json.loads(MOCK_PACKET_PATH.read_text())

    assert data["description"]
    assert "scenarios" in data
    assert data["scenarios"]["port_scan_like"]
    assert data["scenarios"]["connection_burst_like"]


def test_mock_packet_json_matches_packet_info_shape() -> None:
    data = json.loads(MOCK_PACKET_PATH.read_text())

    packets = [
        packet
        for scenario_packets in data["scenarios"].values()
        for packet in scenario_packets
    ]

    assert packets
    assert all(set(packet) == PACKET_INFO_FIELDS for packet in packets)


def test_mock_packet_json_uses_documentation_ip_ranges() -> None:
    data = json.loads(MOCK_PACKET_PATH.read_text())

    observed_ips = {
        value
        for packets in data["scenarios"].values()
        for packet in packets
        for value in (packet.get("src_ip"), packet.get("dst_ip"))
        if value is not None
    }

    assert observed_ips
    assert all(
        any(ip_address(value) in network for network in DOCUMENTATION_NETWORKS)
        for value in observed_ips
    )
