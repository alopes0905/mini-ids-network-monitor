"""Generate deterministic, synthetic PCAP samples without network access."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import wrpcap


BASE_TIMESTAMP = 1_720_000_000.0
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "pcaps" / "samples"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def _timestamp_packets(
    packets: list[Packet],
    start: float,
    step: float,
) -> list[Packet]:
    for index, packet in enumerate(packets):
        packet.time = start + (index * step)
    return packets


def _tcp_syn(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
) -> Packet:
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=source_ip, dst=destination_ip)
        / TCP(sport=source_port, dport=destination_port, flags="S")
    )


def _dns_query(source_ip: str, domain: str, source_port: int) -> Packet:
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=source_ip, dst="198.51.100.53")
        / UDP(sport=source_port, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )


def _normal_traffic() -> list[Packet]:
    packets = [
        _tcp_syn("192.0.2.10", "198.51.100.20", 41000, 80),
        _tcp_syn("192.0.2.10", "198.51.100.20", 41001, 443),
        _tcp_syn("192.0.2.10", "198.51.100.20", 41002, 8080),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.0.2.11", dst="198.51.100.21")
        / UDP(sport=42000, dport=123),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.0.2.12", dst="198.51.100.22")
        / ICMP(type=8, code=0),
        _dns_query("192.0.2.13", "example.com", 43000),
        _dns_query("192.0.2.13", "example.net", 43001),
    ]
    return _timestamp_packets(packets, BASE_TIMESTAMP, 1.0)


def _port_scan(start: float = BASE_TIMESTAMP) -> list[Packet]:
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
    packets = [
        _tcp_syn("192.0.2.50", "198.51.100.50", 44000 + index, port)
        for index, port in enumerate(ports)
    ]
    return _timestamp_packets(packets, start, 1.0)


def _connection_burst(start: float = BASE_TIMESTAMP) -> list[Packet]:
    packets = [
        _tcp_syn("192.0.2.60", "198.51.100.60", 45000 + index, 443)
        for index in range(51)
    ]
    return _timestamp_packets(packets, start, 0.5)


def _dns_anomaly(start: float = BASE_TIMESTAMP) -> list[Packet]:
    packets = [
        _dns_query("192.0.2.70", "example.org", 46000 + index)
        for index in range(31)
    ]
    return _timestamp_packets(packets, start, 0.5)


def _mixed_alerts() -> list[Packet]:
    return [
        *_port_scan(BASE_TIMESTAMP),
        *_connection_burst(BASE_TIMESTAMP + 15.0),
        *_dns_anomaly(BASE_TIMESTAMP + 45.0),
    ]


SAMPLE_BUILDERS: dict[str, Callable[[], list[Packet]]] = {
    "normal-traffic.pcap": _normal_traffic,
    "port-scan.pcap": _port_scan,
    "connection-burst.pcap": _connection_burst,
    "dns-anomaly.pcap": _dns_anomaly,
    "mixed-alerts.pcap": _mixed_alerts,
}

SAMPLE_DESCRIPTIONS = {
    "normal-traffic.pcap": (
        "Benign TCP, UDP, ICMP, and DNS metadata below all thresholds."
    ),
    "port-scan.pcap": (
        "Eleven distinct TCP SYN destination ports for one endpoint pair."
    ),
    "connection-burst.pcap": (
        "Fifty-one TCP SYN attempts to one repeated target."
    ),
    "dns-anomaly.pcap": (
        "Thirty-one repeated example.org DNS queries from one source."
    ),
    "mixed-alerts.pcap": (
        "Independent synthetic sequences for all three rule families."
    ),
}

EXPECTED_ALERTS: dict[str, list[dict[str, str | None]]] = {
    "normal-traffic.pcap": [],
    "port-scan.pcap": [
        {"rule_id": "PORT_SCAN_001", "anomaly_type": None}
    ],
    "connection-burst.pcap": [
        {"rule_id": "CONNECTION_BURST_001", "anomaly_type": None}
    ],
    "dns-anomaly.pcap": [
        {"rule_id": "DNS_ANOMALY_001", "anomaly_type": "query_burst"}
    ],
    "mixed-alerts.pcap": [
        {"rule_id": "PORT_SCAN_001", "anomaly_type": None},
        {"rule_id": "CONNECTION_BURST_001", "anomaly_type": None},
        {"rule_id": "DNS_ANOMALY_001", "anomaly_type": "query_burst"},
    ],
}


def generate_sample_pcaps(
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> list[Path]:
    """Write all samples and a manifest, overwriting only known filenames."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    generated_paths: list[Path] = []
    manifest_samples: list[dict[str, object]] = []

    for filename, builder in SAMPLE_BUILDERS.items():
        packets = builder()
        output_path = destination / filename
        wrpcap(str(output_path), packets)
        generated_paths.append(output_path)
        manifest_samples.append(
            {
                "filename": filename,
                "description": SAMPLE_DESCRIPTIONS[filename],
                "packet_count": len(packets),
                "expected_alert_count": len(EXPECTED_ALERTS[filename]),
                "expected_alerts": EXPECTED_ALERTS[filename],
            }
        )

    manifest_path = destination / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {"schema_version": 1, "samples": manifest_samples},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    generated_paths.append(manifest_path)
    return generated_paths


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate safe synthetic PCAP files without transmitting packets."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to overwrite with the known sample files.",
    )
    arguments = parser.parse_args()

    for path in generate_sample_pcaps(arguments.output_dir):
        print(path)


if __name__ == "__main__":
    main()
