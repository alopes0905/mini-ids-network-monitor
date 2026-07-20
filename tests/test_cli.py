import json
from pathlib import Path

import pytest
from scapy.all import Ether, IP, Raw, TCP, wrpcap
from scapy.packet import Packet
from scapy.utils import PcapWriter
from typer.testing import CliRunner

from mini_ids.cli import _create_default_engine, app
from mini_ids.rules import ConnectionBurstRule, PortScanRule


BASE_TIMESTAMP = 1_720_000_000.0
runner = CliRunner()


def write_pcap(path: Path, packets: list[Packet]) -> None:
    wrpcap(str(path), packets)


def write_empty_pcap(path: Path) -> None:
    writer = PcapWriter(str(path), linktype=1, sync=True)
    writer.write_header(None)
    writer.close()


def make_tcp_packet(
    *,
    timestamp: float = BASE_TIMESTAMP,
    source_ip: str = "192.0.2.10",
    destination_ip: str = "198.51.100.20",
    source_port: int = 41000,
    destination_port: int = 443,
    flags: str = "S",
) -> Packet:
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=source_ip, dst=destination_ip)
        / TCP(sport=source_port, dport=destination_port, flags=flags)
    )
    packet.time = timestamp
    return packet


def make_port_scan_packets() -> list[Packet]:
    return [
        make_tcp_packet(
            timestamp=BASE_TIMESTAMP + index,
            source_ip="192.0.2.50",
            destination_ip="198.51.100.30",
            source_port=41000 + index,
            destination_port=port,
        )
        for index, port in enumerate(
            [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
        )
    ]


def make_connection_burst_packets() -> list[Packet]:
    return [
        make_tcp_packet(
            timestamp=BASE_TIMESTAMP + (index * 0.5),
            source_ip="192.0.2.60",
            destination_ip="198.51.100.40",
            source_port=42000 + index,
            destination_port=443,
        )
        for index in range(51)
    ]


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_application_help_succeeds() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Analyze offline PCAP files" in result.output
    assert "analyze" in result.output


def test_analyze_help_documents_required_and_optional_paths() -> None:
    result = runner.invoke(app, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "--pcap" in result.output
    assert "required" in result.output.lower()
    assert "--packet-log" in result.output
    assert "--alert-log" in result.output


def test_valid_synthetic_pcap_is_parsed_and_processed(tmp_path: Path) -> None:
    pcap_path = tmp_path / "normal.pcap"
    write_pcap(
        pcap_path,
        [
            make_tcp_packet(flags="PA"),
            make_tcp_packet(timestamp=BASE_TIMESTAMP + 1, flags="A"),
        ],
    )

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "No alerts generated." in result.output
    assert "Packets processed" in result.output
    assert "2" in result.output
    assert "Alerts generated" in result.output


def test_empty_valid_pcap_is_handled(tmp_path: Path) -> None:
    pcap_path = tmp_path / "empty.pcap"
    write_empty_pcap(pcap_path)

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "No alerts generated." in result.output
    assert "Packets processed" in result.output
    assert "Alerts generated" in result.output


def test_port_scan_pcap_generates_alert(tmp_path: Path) -> None:
    pcap_path = tmp_path / "port-scan.pcap"
    write_pcap(pcap_path, make_port_scan_packets())

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "Vertical TCP Port Scan" in result.output
    assert "PORT_SCAN_001" in result.output
    assert "MEDIUM alerts" in result.output


def test_connection_burst_pcap_generates_alert(tmp_path: Path) -> None:
    pcap_path = tmp_path / "connection-burst.pcap"
    write_pcap(pcap_path, make_connection_burst_packets())

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "TCP Connection Burst" in result.output
    assert "CONNECTION_BURST_001" in result.output
    assert "51" in result.output


def test_both_rules_can_alert_in_one_analysis(tmp_path: Path) -> None:
    pcap_path = tmp_path / "both-rules.pcap"
    packets = [*make_port_scan_packets(), *make_connection_burst_packets()]
    write_pcap(pcap_path, packets)

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "PORT_SCAN_001" in result.output
    assert "CONNECTION_BURST_001" in result.output
    assert "Packets processed" in result.output
    assert "62" in result.output
    assert "Alerts generated" in result.output


def test_packet_log_contains_one_record_per_parsed_packet(tmp_path: Path) -> None:
    pcap_path = tmp_path / "normal.pcap"
    packet_log = tmp_path / "packets.jsonl"
    packets = [
        make_tcp_packet(flags="PA"),
        make_tcp_packet(timestamp=BASE_TIMESTAMP + 1, flags="A"),
    ]
    write_pcap(pcap_path, packets)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--packet-log",
            str(packet_log),
        ],
    )

    assert result.exit_code == 0
    records = read_jsonl(packet_log)
    assert len(records) == 2
    assert all(record["protocol"] == "TCP" for record in records)


def test_alert_log_matches_generated_alerts_and_preserves_order(
    tmp_path: Path,
) -> None:
    pcap_path = tmp_path / "both-rules.pcap"
    alert_log = tmp_path / "alerts.jsonl"
    write_pcap(
        pcap_path,
        [*make_port_scan_packets(), *make_connection_burst_packets()],
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--alert-log",
            str(alert_log),
        ],
    )

    assert result.exit_code == 0
    records = read_jsonl(alert_log)
    assert [record["rule_id"] for record in records] == [
        "PORT_SCAN_001",
        "CONNECTION_BURST_001",
    ]


def test_log_paths_are_overwritten_and_parent_directories_are_created(
    tmp_path: Path,
) -> None:
    first_pcap = tmp_path / "first.pcap"
    second_pcap = tmp_path / "second.pcap"
    packet_log = tmp_path / "nested" / "packets" / "packets.jsonl"
    alert_log = tmp_path / "nested" / "alerts" / "alerts.jsonl"
    write_pcap(first_pcap, make_port_scan_packets())
    write_pcap(second_pcap, [make_tcp_packet(flags="PA")])

    first_result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(first_pcap),
            "--packet-log",
            str(packet_log),
            "--alert-log",
            str(alert_log),
        ],
    )
    second_result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(second_pcap),
            "--packet-log",
            str(packet_log),
            "--alert-log",
            str(alert_log),
        ],
    )

    assert first_result.exit_code == 0
    assert second_result.exit_code == 0
    assert len(read_jsonl(packet_log)) == 1
    assert alert_log.read_text(encoding="utf-8") == ""


def test_other_packets_are_counted_as_parsed_packets(tmp_path: Path) -> None:
    pcap_path = tmp_path / "other.pcap"
    packet_log = tmp_path / "other.jsonl"
    packet = Ether(
        src="02:00:00:00:00:01",
        dst="02:00:00:00:00:02",
    ) / Raw(load=b"safe synthetic payload")
    packet.time = BASE_TIMESTAMP
    write_pcap(pcap_path, [packet])

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--packet-log",
            str(packet_log),
        ],
    )

    assert result.exit_code == 0
    assert "Packets processed" in result.output
    records = read_jsonl(packet_log)
    assert len(records) == 1
    assert records[0]["protocol"] == "OTHER"


def test_packets_returning_none_from_parser_are_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap_path = tmp_path / "skipped.pcap"
    packet_log = tmp_path / "packets.jsonl"
    write_pcap(pcap_path, [make_tcp_packet()])
    monkeypatch.setattr("mini_ids.cli.parse_packet", lambda packet: None)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--packet-log",
            str(packet_log),
        ],
    )

    assert result.exit_code == 0
    assert packet_log.read_text(encoding="utf-8") == ""
    assert "Packets processed" in result.output


@pytest.mark.parametrize(
    ("pcap_setup", "expected_message"),
    [
        ("missing", "PCAP file not found"),
        ("directory", "PCAP path is not a file"),
        ("invalid", "Unable to read PCAP file"),
    ],
)
def test_expected_pcap_errors_are_clear_and_have_no_traceback(
    tmp_path: Path,
    pcap_setup: str,
    expected_message: str,
) -> None:
    pcap_path = tmp_path / "input.pcap"
    if pcap_setup == "directory":
        pcap_path.mkdir()
    elif pcap_setup == "invalid":
        pcap_path.write_text("not a pcap", encoding="utf-8")

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code != 0
    assert expected_message in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("option", "log_name"),
    [
        ("--packet-log", "packet"),
        ("--alert-log", "alert"),
    ],
)
def test_unwritable_output_path_exits_cleanly(
    tmp_path: Path,
    option: str,
    log_name: str,
) -> None:
    pcap_path = tmp_path / "normal.pcap"
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("blocking file", encoding="utf-8")
    write_pcap(pcap_path, [make_tcp_packet(flags="PA")])

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            option,
            str(blocking_file / f"{log_name}s.jsonl"),
        ],
    )

    assert result.exit_code != 0
    assert "Error:" in result.output
    assert f"Unable to write {log_name} log" in result.output
    assert "Traceback" not in result.output


def test_unexpected_processing_errors_are_not_swallowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap_path = tmp_path / "unexpected-error.pcap"
    write_pcap(pcap_path, [make_tcp_packet()])

    def fail_to_parse(packet: Packet) -> None:
        raise RuntimeError("unexpected parser failure")

    monkeypatch.setattr("mini_ids.cli.parse_packet", fail_to_parse)

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "unexpected parser failure"


def test_default_engine_registers_only_current_rules() -> None:
    engine = _create_default_engine()

    assert [type(rule) for rule in engine.rules] == [
        PortScanRule,
        ConnectionBurstRule,
    ]


def test_cli_does_not_expose_future_config_or_live_features() -> None:
    app_help = runner.invoke(app, ["--help"])
    analyze_help = runner.invoke(app, ["analyze", "--help"])

    assert app_help.exit_code == 0
    assert analyze_help.exit_code == 0
    assert "live" not in app_help.output.lower()
    assert "--config" not in analyze_help.output
