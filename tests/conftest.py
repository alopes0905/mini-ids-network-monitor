import pytest

from mini_ids.models import PacketInfo


BASE_TIMESTAMP = 1_720_000_000.0


@pytest.fixture
def normal_tcp_packets() -> list[PacketInfo]:
    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51514,
            dst_port=443,
            protocol="TCP",
            packet_length=74,
            tcp_flags="PA",
            raw_summary="TCP normal web session packet",
        ),
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 1.0,
            src_ip="198.51.100.20",
            dst_ip="192.0.2.10",
            src_port=443,
            dst_port=51514,
            protocol="TCP",
            packet_length=66,
            tcp_flags="A",
            raw_summary="TCP normal web session response",
        ),
    ]


@pytest.fixture
def normal_udp_packets() -> list[PacketInfo]:
    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 10.0,
            src_ip="192.0.2.11",
            dst_ip="198.51.100.53",
            src_port=53000,
            dst_port=123,
            protocol="UDP",
            packet_length=76,
            raw_summary="UDP normal NTP-like request",
        ),
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 11.0,
            src_ip="198.51.100.53",
            dst_ip="192.0.2.11",
            src_port=123,
            dst_port=53000,
            protocol="UDP",
            packet_length=76,
            raw_summary="UDP normal NTP-like response",
        ),
    ]


@pytest.fixture
def normal_dns_packets() -> list[PacketInfo]:
    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 20.0,
            src_ip="192.0.2.12",
            dst_ip="198.51.100.53",
            src_port=53001,
            dst_port=53,
            protocol="DNS",
            packet_length=82,
            dns_query="example.com",
            raw_summary="DNS query for example.com",
        ),
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 20.2,
            src_ip="198.51.100.53",
            dst_ip="192.0.2.12",
            src_port=53,
            dst_port=53001,
            protocol="DNS",
            packet_length=98,
            dns_query="example.com",
            dns_response="203.0.113.10",
            raw_summary="DNS response for example.com",
        ),
    ]


@pytest.fixture
def port_scan_like_packets() -> list[PacketInfo]:
    source = "192.0.2.50"
    destination = "198.51.100.30"
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]

    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 60.0 + index,
            src_ip=source,
            dst_ip=destination,
            src_port=41000 + index,
            dst_port=port,
            protocol="TCP",
            packet_length=60,
            tcp_flags="S",
            raw_summary=f"TCP SYN to destination port {port}",
        )
        for index, port in enumerate(ports)
    ]


@pytest.fixture
def connection_burst_like_packets() -> list[PacketInfo]:
    source = "192.0.2.60"

    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 120.0 + (index * 0.2),
            src_ip=source,
            dst_ip=f"198.51.100.{40 + (index % 5)}",
            src_port=42000 + index,
            dst_port=443,
            protocol="TCP",
            packet_length=66,
            tcp_flags="S",
            raw_summary="TCP short-window connection attempt",
        )
        for index in range(20)
    ]


@pytest.fixture
def mixed_normal_packets(
    normal_tcp_packets: list[PacketInfo],
    normal_udp_packets: list[PacketInfo],
    normal_dns_packets: list[PacketInfo],
) -> list[PacketInfo]:
    return [*normal_tcp_packets, *normal_udp_packets, *normal_dns_packets]


@pytest.fixture
def other_packets() -> list[PacketInfo]:
    return [
        PacketInfo(
            timestamp=BASE_TIMESTAMP + 180.0,
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            protocol="OTHER",
            packet_length=60,
            raw_summary="Unsupported non-IP packet metadata",
        )
    ]
