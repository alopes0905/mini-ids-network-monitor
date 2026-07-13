import json

from mini_ids.models import PacketInfo


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
