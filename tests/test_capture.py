from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, wrpcap
from scapy.packet import Packet

from mini_ids.capture import PcapReadError, read_pcap


def test_read_pcap_opens_valid_synthetic_pcap(tmp_path: Path) -> None:
    pcap_path = tmp_path / "sample.pcap"
    packets = [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(dport=80),
        Ether() / IP(src="192.0.2.10", dst="198.51.100.53") / UDP(dport=53),
    ]
    wrpcap(str(pcap_path), packets)

    loaded_packets = read_pcap(pcap_path)

    assert len(loaded_packets) == 2
    assert all(isinstance(packet, Packet) for packet in loaded_packets)
    assert loaded_packets[0].haslayer(TCP)
    assert loaded_packets[1].haslayer(UDP)


def test_read_pcap_accepts_string_path(tmp_path: Path) -> None:
    pcap_path = tmp_path / "single.pcap"
    wrpcap(str(pcap_path), [Ether() / IP(dst="203.0.113.10") / TCP(dport=443)])

    loaded_packets = read_pcap(str(pcap_path))

    assert len(loaded_packets) == 1
    assert loaded_packets[0].haslayer(TCP)


def test_read_pcap_raises_clear_error_for_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.pcap"

    with pytest.raises(FileNotFoundError, match="PCAP file not found"):
        read_pcap(missing_path)


def test_read_pcap_raises_clear_error_for_directory(tmp_path: Path) -> None:
    with pytest.raises(PcapReadError, match="PCAP path is not a file"):
        read_pcap(tmp_path)


def test_read_pcap_raises_clear_error_for_invalid_file(tmp_path: Path) -> None:
    invalid_path = tmp_path / "invalid.pcap"
    invalid_path.write_text("this is not a valid pcap file")

    with pytest.raises(PcapReadError, match="Unable to read PCAP file") as caught:
        read_pcap(invalid_path)

    assert caught.value.__cause__ is not None
