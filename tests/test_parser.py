from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, TCP, UDP
from scapy.packet import Raw

from mini_ids.models import PacketInfo
from mini_ids.parser import parse_packet


def test_parse_tcp_packet() -> None:
    packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
        sport=51514,
        dport=443,
        flags="S",
    )

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.src_ip == "192.0.2.10"
    assert parsed.dst_ip == "198.51.100.20"
    assert parsed.src_port == 51514
    assert parsed.dst_port == 443
    assert parsed.protocol == "TCP"


def test_parse_udp_packet() -> None:
    packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.53") / UDP(
        sport=53000,
        dport=5353,
    )

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.src_port == 53000
    assert parsed.dst_port == 5353
    assert parsed.protocol == "UDP"
    assert parsed.tcp_flags is None


def test_parse_icmp_packet() -> None:
    packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.1") / ICMP()

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.src_ip == "192.0.2.10"
    assert parsed.dst_ip == "198.51.100.1"
    assert parsed.src_port is None
    assert parsed.dst_port is None
    assert parsed.protocol == "ICMP"


def test_parse_dns_query_packet() -> None:
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.protocol == "DNS"
    assert parsed.src_port == 53000
    assert parsed.dst_port == 53
    assert parsed.dns_query == "example.com"
    assert parsed.dns_response is None


def test_parse_dns_response_packet() -> None:
    packet = (
        Ether()
        / IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                rdata="203.0.113.5",
            ),
            ancount=1,
        )
    )

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.protocol == "DNS"
    assert parsed.dns_query == "example.com"
    assert parsed.dns_response == "203.0.113.5"


def test_invalid_packet_timestamp_falls_back_to_zero() -> None:
    packet = Ether() / IP(dst="203.0.113.10") / TCP(dport=443)
    packet.time = "not-a-timestamp"

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.timestamp == 0.0


def test_unsupported_packet_returns_other_packet_info() -> None:
    packet = Ether() / Raw(load=b"unsupported payload")

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.protocol == "OTHER"
    assert parsed.src_ip is None
    assert parsed.dst_ip is None
    assert parsed.raw_summary is not None


def test_packet_length_is_extracted() -> None:
    packet = Ether() / IP(dst="203.0.113.10") / TCP(dport=80)

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.packet_length == len(packet)


def test_tcp_flags_are_extracted() -> None:
    packet = Ether() / IP(dst="203.0.113.10") / TCP(dport=80, flags="SA")

    parsed = parse_packet(packet)

    assert isinstance(parsed, PacketInfo)
    assert parsed.tcp_flags == "SA"


def test_non_packet_input_returns_none() -> None:
    parsed = parse_packet(object())  # type: ignore[arg-type]

    assert parsed is None
