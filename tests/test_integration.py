import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap
from scapy.packet import Packet

from mini_ids.capture import read_pcap
from mini_ids.config import build_rules, load_config
from mini_ids.console import print_alerts, print_summary
from mini_ids.engine import DetectionEngine
from mini_ids.logger import write_alerts_jsonl, write_packets_jsonl
from mini_ids.models import PacketInfo
from mini_ids.parser import parse_packet


BASE_TIMESTAMP = 1_720_000_000.0


def make_combined_detection_packets() -> list[Packet]:
    packets: list[Packet] = []
    for index in range(51):
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.80", dst="198.51.100.80")
            / TCP(
                sport=45000 + index,
                dport=1000 + index,
                flags="S",
            )
        )
        packet.time = BASE_TIMESTAMP + index
        packets.append(packet)
    for index in range(31):
        packet = (
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")
            / IP(src="192.0.2.90", dst="198.51.100.53")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="repeated.example"))
        )
        packet.time = BASE_TIMESTAMP + 60 + index
        packets.append(packet)
    return packets


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_public_offline_pipeline_detects_logs_and_displays_results(
    tmp_path: Path,
) -> None:
    pcap_path = tmp_path / "combined-detection.pcap"
    packet_log = tmp_path / "logs" / "packets.jsonl"
    alert_log = tmp_path / "logs" / "alerts.jsonl"
    wrpcap(str(pcap_path), make_combined_detection_packets())

    parsed_packets = [
        parsed
        for raw_packet in read_pcap(pcap_path)
        if (parsed := parse_packet(raw_packet)) is not None
    ]
    engine = DetectionEngine(build_rules(load_config()))
    alerts = engine.process_packets(parsed_packets)
    summary = engine.get_summary()
    write_packets_jsonl(parsed_packets, packet_log, append=False)
    write_alerts_jsonl(alerts, alert_log, append=False)
    stream = StringIO()
    console = Console(file=stream, color_system=None, width=120)
    print_alerts(alerts, console)
    print_summary(summary, console)

    packet_records = read_jsonl(packet_log)
    alert_records = read_jsonl(alert_log)
    assert all(isinstance(packet, PacketInfo) for packet in parsed_packets)
    assert len(packet_records) == len(parsed_packets) == 82
    assert [record["rule_id"] for record in alert_records] == [
        "PORT_SCAN_001",
        "CONNECTION_BURST_001",
        "DNS_ANOMALY_001",
    ]
    assert summary == {
        "packets_processed": 82,
        "alerts_generated": 3,
        "severity_counts": {
            "LOW": 0,
            "MEDIUM": 3,
            "HIGH": 0,
            "CRITICAL": 0,
        },
    }
    output = stream.getvalue()
    assert output.index("PORT_SCAN_001") < output.index("CONNECTION_BURST_001")
    assert output.index("CONNECTION_BURST_001") < output.index("DNS_ANOMALY_001")
    assert "Packets processed" in output
    assert "Alerts generated" in output
