import ast
import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scapy.layers.dns import DNSQR
from scapy.packet import Packet, Raw

from mini_ids.capture import read_pcap
from mini_ids.config import build_rules, load_config
from mini_ids.engine import DetectionEngine
from mini_ids.parser import parse_packet
from mini_ids.reporting import build_analysis_report, build_traffic_summary
from scripts.generate_sample_pcaps import (
    EXPECTED_ALERTS,
    SAMPLE_BUILDERS,
    generate_sample_pcaps,
)


APPROVED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)
EXPECTED_PACKET_COUNTS = {
    "normal-traffic.pcap": 7,
    "port-scan.pcap": 11,
    "connection-burst.pcap": 51,
    "dns-anomaly.pcap": 31,
    "mixed-alerts.pcap": 93,
}
SAMPLE_NAMES = tuple(EXPECTED_PACKET_COUNTS)


def _parsed_packets(path: Path):
    return [
        packet
        for raw_packet in read_pcap(path)
        if (packet := parse_packet(raw_packet)) is not None
    ]


def _analyze(path: Path):
    packets = _parsed_packets(path)
    engine = DetectionEngine(build_rules(load_config()))
    alerts = engine.process_packets(packets)
    return packets, alerts, engine.get_summary()


@pytest.fixture
def generated_samples(tmp_path: Path) -> Path:
    output_dir = tmp_path / "samples"
    generate_sample_pcaps(output_dir)
    return output_dir


def test_generator_creates_expected_pcaps_and_manifest(
    generated_samples: Path,
) -> None:
    assert {path.name for path in generated_samples.iterdir()} == {
        *SAMPLE_NAMES,
        "manifest.json",
    }
    manifest = json.loads(
        (generated_samples / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == 1
    assert [sample["filename"] for sample in manifest["samples"]] == list(
        SAMPLE_NAMES
    )
    assert all(
        not Path(sample["filename"]).is_absolute()
        for sample in manifest["samples"]
    )


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_generated_sample_is_readable_nonempty_and_small(
    generated_samples: Path,
    filename: str,
) -> None:
    path = generated_samples / filename
    packets = read_pcap(path)

    assert len(packets) == EXPECTED_PACKET_COUNTS[filename]
    assert path.stat().st_size < 100_000


def test_generation_is_repeatable_at_normalized_metadata_level(
    tmp_path: Path,
) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    generate_sample_pcaps(first_dir)
    generate_sample_pcaps(second_dir)

    for filename in SAMPLE_NAMES:
        first = [
            packet.to_dict()
            for packet in _parsed_packets(first_dir / filename)
        ]
        second = [
            packet.to_dict()
            for packet in _parsed_packets(second_dir / filename)
        ]
        assert first == second

    assert (first_dir / "manifest.json").read_bytes() == (
        second_dir / "manifest.json"
    ).read_bytes()


def test_committed_samples_match_fresh_generation(tmp_path: Path) -> None:
    committed_dir = Path(__file__).parents[1] / "pcaps" / "samples"
    generated_dir = tmp_path / "generated"
    generate_sample_pcaps(generated_dir)

    for filename in SAMPLE_NAMES:
        committed = [
            packet.to_dict()
            for packet in _parsed_packets(committed_dir / filename)
        ]
        generated = [
            packet.to_dict()
            for packet in _parsed_packets(generated_dir / filename)
        ]
        assert committed == generated

    assert (committed_dir / "manifest.json").read_bytes() == (
        generated_dir / "manifest.json"
    ).read_bytes()


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_samples_use_only_documentation_addresses_and_example_domains(
    generated_samples: Path,
    filename: str,
) -> None:
    packets = _parsed_packets(generated_samples / filename)

    for packet in packets:
        for address in (packet.src_ip, packet.dst_ip):
            if address is not None:
                assert any(
                    ipaddress.ip_address(address) in network
                    for network in APPROVED_NETWORKS
                )
        if packet.dns_query is not None:
            assert packet.dns_query in {
                "example.com",
                "example.net",
                "example.org",
            }


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_samples_have_no_raw_or_large_packet_payloads(
    generated_samples: Path,
    filename: str,
) -> None:
    packets = read_pcap(generated_samples / filename)

    assert all(not packet.haslayer(Raw) for packet in packets)
    assert all(len(packet) < 512 for packet in packets)


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_samples_generate_exact_documented_alerts(
    generated_samples: Path,
    filename: str,
) -> None:
    _, alerts, summary = _analyze(generated_samples / filename)
    actual = [
        {
            "rule_id": alert.rule_id,
            "anomaly_type": alert.evidence.get("anomaly_type"),
        }
        for alert in alerts
    ]

    assert actual == EXPECTED_ALERTS[filename]
    assert summary["alerts_generated"] == len(EXPECTED_ALERTS[filename])


@pytest.mark.parametrize("filename", SAMPLE_NAMES)
def test_every_sample_supports_summary_and_analysis_report(
    generated_samples: Path,
    filename: str,
) -> None:
    packets, alerts, detection_summary = _analyze(
        generated_samples / filename
    )
    traffic_summary = build_traffic_summary(packets)
    report = build_analysis_report(
        pcap_file=filename,
        analysis_started=datetime(2026, 7, 21, 12, 0, tzinfo=UTC),
        analysis_finished=datetime(2026, 7, 21, 12, 1, tzinfo=UTC),
        detection_summary=detection_summary,
        traffic_summary=traffic_summary,
        alerts=alerts,
    )

    assert (
        traffic_summary.packets_processed
        == EXPECTED_PACKET_COUNTS[filename]
    )
    assert json.loads(report.to_json())["pcap_file"] == filename


def test_manifest_matches_generated_packets_and_alert_contracts(
    generated_samples: Path,
) -> None:
    manifest = json.loads(
        (generated_samples / "manifest.json").read_text(encoding="utf-8")
    )

    for sample in manifest["samples"]:
        filename = sample["filename"]
        assert sample["packet_count"] == EXPECTED_PACKET_COUNTS[filename]
        assert sample["expected_alert_count"] == len(
            EXPECTED_ALERTS[filename]
        )
        assert sample["expected_alerts"] == EXPECTED_ALERTS[filename]


def test_generator_uses_only_offline_packet_construction_and_writing() -> None:
    source_path = (
        Path(__file__).parents[1]
        / "scripts"
        / "generate_sample_pcaps.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_names = {"send", "sendp", "sr", "srp", "sniff", "socket"}
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
    }
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_modules.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    imported_symbols = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert not forbidden_names & called_names
    assert not forbidden_names & called_attributes
    assert not forbidden_names & imported_symbols
    assert all(not module.startswith("socket") for module in imported_modules)
    assert "Raw" not in imported_symbols
    assert set(SAMPLE_BUILDERS) == set(SAMPLE_NAMES)


def test_dns_samples_contain_only_dns_questions(
    generated_samples: Path,
) -> None:
    dns_files = ("dns-anomaly.pcap", "mixed-alerts.pcap")
    questions: list[Packet] = []
    for filename in dns_files:
        questions.extend(
            packet[DNSQR]
            for packet in read_pcap(generated_samples / filename)
            if packet.haslayer(DNSQR)
        )

    assert questions
    assert all(
        bytes(question.qname).rstrip(b".") == b"example.org"
        for question in questions
    )
