"""Packet parsing helpers."""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet

from mini_ids.models import PacketInfo


def _packet_timestamp(packet: Packet) -> float:
    timestamp = getattr(packet, "time", 0.0)
    try:
        return float(timestamp)
    except (TypeError, ValueError):
        return 0.0


def _decode_dns_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value).rstrip(".")


def _dns_query(packet: Packet) -> str | None:
    if not packet.haslayer(DNSQR):
        return None
    qname = packet[DNSQR].qname
    if qname is None:
        return None
    return _decode_dns_value(qname)


def _dns_response(packet: Packet) -> str | None:
    if not packet.haslayer(DNSRR):
        return None
    answer = packet[DNSRR]
    rdata = getattr(answer, "rdata", None)
    if rdata is not None:
        return _decode_dns_value(rdata)
    rrname = getattr(answer, "rrname", None)
    if rrname is not None:
        return _decode_dns_value(rrname)
    return None


def parse_packet(packet: Packet) -> PacketInfo | None:
    """Convert one raw Scapy packet into a `PacketInfo` object.

    This function does not read PCAP files and does not run detection logic.
    It only normalizes packet metadata for future project layers.
    """

    if not isinstance(packet, Packet):
        return None

    src_ip = packet[IP].src if packet.haslayer(IP) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    dns_query = _dns_query(packet)
    dns_response = _dns_response(packet)

    if packet.haslayer(DNS):
        protocol = "DNS"
    elif packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "OTHER"

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    return PacketInfo(
        timestamp=_packet_timestamp(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=len(packet),
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        dns_response=dns_response,
        raw_summary=packet.summary(),
    )
