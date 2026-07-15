"""Offline packet capture helpers."""

from __future__ import annotations

from pathlib import Path

from scapy.all import rdpcap
from scapy.packet import Packet


class PcapReadError(Exception):
    """Raised when a PCAP file exists but cannot be read as a valid capture."""


def read_pcap(path: str | Path) -> list[Packet]:
    """Read raw Scapy packets from an offline PCAP file.

    This function only handles file ingestion. It deliberately does not parse
    packet metadata into `PacketInfo` objects; that belongs in the parser layer.
    """

    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    if not pcap_path.is_file():
        raise PcapReadError(f"PCAP path is not a file: {pcap_path}")

    try:
        return list(rdpcap(str(pcap_path)))
    except Exception as exc:
        raise PcapReadError(f"Unable to read PCAP file: {pcap_path}") from exc
