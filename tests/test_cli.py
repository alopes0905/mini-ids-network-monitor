import json
from pathlib import Path

import pytest
import yaml
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap
from scapy.packet import Packet
from scapy.utils import PcapWriter
from typer.testing import CliRunner

from mini_ids.cli import app
from mini_ids.config import build_rules, load_config
from mini_ids.rules import ConnectionBurstRule, DNSAnomalyRule, PortScanRule


BASE_TIMESTAMP = 1_720_000_000.0
runner = CliRunner()


def write_pcap(path: Path, packets: list[Packet]) -> None:
    wrpcap(str(path), packets)


def write_empty_pcap(path: Path) -> None:
    writer = PcapWriter(str(path), linktype=1, sync=True)
    writer.write_header(None)
    writer.close()


def write_config(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


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


def make_dns_query_packet(
    *,
    timestamp: float = BASE_TIMESTAMP,
    source_ip: str = "192.0.2.70",
    domain: str = "example.com",
) -> Packet:
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=source_ip, dst="198.51.100.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )
    packet.time = timestamp
    return packet


def make_dns_query_packets(
    count: int,
    *,
    unique_domains: bool = False,
) -> list[Packet]:
    return [
        make_dns_query_packet(
            timestamp=BASE_TIMESTAMP + index,
            domain=(
                f"domain-{index}.example"
                if unique_domains
                else "repeated.example"
            ),
        )
        for index in range(count)
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
    assert "--config" in result.output


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
    assert "Traffic Summary" in result.output
    assert "Total parsed packets" in result.output
    assert "Protocol TCP" in result.output
    assert "192.0.2.10 (2)" in result.output
    assert "198.51.100.20 (2)" in result.output
    assert "443 (2)" in result.output
    assert "DNS queries" in result.output


def test_empty_valid_pcap_is_handled(tmp_path: Path) -> None:
    pcap_path = tmp_path / "empty.pcap"
    write_empty_pcap(pcap_path)

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "No alerts generated." in result.output
    assert "Packets processed" in result.output
    assert "Alerts generated" in result.output
    assert "Traffic Summary" in result.output
    assert "Total parsed packets" in result.output
    assert "Protocols" in result.output
    assert "None observed" in result.output


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


def test_dns_query_burst_pcap_generates_alert_by_default(tmp_path: Path) -> None:
    pcap_path = tmp_path / "dns-query-burst.pcap"
    write_pcap(pcap_path, make_dns_query_packets(31))

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert "DNS Anomaly Detection" in result.output
    assert "DNS_ANOMALY_001" in result.output
    assert "query_burst" in result.output
    assert "Packets processed" in result.output
    assert "31" in result.output
    assert "Protocol DNS" in result.output
    assert "DNS queries" in result.output


def test_valid_configuration_is_accepted(tmp_path: Path) -> None:
    pcap_path = tmp_path / "normal.pcap"
    config_path = write_config(
        tmp_path,
        {
            "rules": {
                "port_scan": {
                    "enabled": True,
                    "port_threshold": 10,
                    "time_window_seconds": 60,
                },
                "connection_burst": {
                    "enabled": True,
                    "connection_threshold": 50,
                    "time_window_seconds": 60,
                },
            }
        },
    )
    write_pcap(pcap_path, [make_tcp_packet(flags="PA")])

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert "Packets processed" in result.output
    assert "No alerts generated." in result.output


def test_custom_port_threshold_changes_detection_behavior(tmp_path: Path) -> None:
    pcap_path = tmp_path / "short-port-scan.pcap"
    config_path = write_config(
        tmp_path,
        {"rules": {"port_scan": {"port_threshold": 2}}},
    )
    write_pcap(pcap_path, make_port_scan_packets()[:3])

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert "PORT_SCAN_001" in result.output
    assert "CONNECTION_BURST_001" not in result.output


def test_custom_connection_threshold_changes_detection_behavior(
    tmp_path: Path,
) -> None:
    pcap_path = tmp_path / "short-connection-burst.pcap"
    config_path = write_config(
        tmp_path,
        {"rules": {"connection_burst": {"connection_threshold": 2}}},
    )
    write_pcap(pcap_path, make_connection_burst_packets()[:3])

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert "CONNECTION_BURST_001" in result.output
    assert "PORT_SCAN_001" not in result.output


@pytest.mark.parametrize(
    ("dns_settings", "packets", "anomaly_type"),
    [
        (
            {"query_threshold": 2},
            make_dns_query_packets(3),
            "query_burst",
        ),
        (
            {
                "query_threshold": 100,
                "unique_domain_threshold": 2,
            },
            make_dns_query_packets(3, unique_domains=True),
            "unique_domain_burst",
        ),
        (
            {"long_domain_threshold": 5},
            [make_dns_query_packet(domain="long.example")],
            "long_domain",
        ),
    ],
)
def test_custom_dns_thresholds_change_detection_behavior(
    tmp_path: Path,
    dns_settings: dict[str, object],
    packets: list[Packet],
    anomaly_type: str,
) -> None:
    pcap_path = tmp_path / f"custom-{anomaly_type}.pcap"
    config_path = write_config(
        tmp_path,
        {"rules": {"dns_anomaly": dns_settings}},
    )
    write_pcap(pcap_path, packets)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert "DNS_ANOMALY_001" in result.output
    assert anomaly_type in result.output


def test_disabling_dns_rule_prevents_dns_alert(tmp_path: Path) -> None:
    pcap_path = tmp_path / "dns-disabled.pcap"
    config_path = write_config(
        tmp_path,
        {"rules": {"dns_anomaly": {"enabled": False}}},
    )
    write_pcap(pcap_path, make_dns_query_packets(31))

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert "DNS_ANOMALY_001" not in result.output
    assert "No alerts generated." in result.output


@pytest.mark.parametrize("disabled_rule", ["port_scan", "connection_burst"])
def test_disabling_one_rule_prevents_its_alert(
    tmp_path: Path,
    disabled_rule: str,
) -> None:
    pcap_path = tmp_path / f"disabled-{disabled_rule}.pcap"
    config_path = write_config(
        tmp_path,
        {"rules": {disabled_rule: {"enabled": False}}},
    )
    packets = (
        make_port_scan_packets()
        if disabled_rule == "port_scan"
        else make_connection_burst_packets()
    )
    write_pcap(pcap_path, packets)

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    rule_id = (
        "PORT_SCAN_001"
        if disabled_rule == "port_scan"
        else "CONNECTION_BURST_001"
    )
    assert rule_id not in result.output
    assert "No alerts generated." in result.output


def test_disabling_all_rules_still_processes_packets(tmp_path: Path) -> None:
    pcap_path = tmp_path / "all-disabled.pcap"
    config_path = write_config(
        tmp_path,
        {
            "rules": {
                "port_scan": {"enabled": False},
                "connection_burst": {"enabled": False},
                "dns_anomaly": {"enabled": False},
            }
        },
    )
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
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    assert "No alerts generated." in result.output
    assert "Packets processed" in result.output
    assert "62" in result.output
    assert "Alerts generated" in result.output


@pytest.mark.parametrize(
    ("config_kind", "expected_message"),
    [
        ("missing", "Configuration file not found"),
        ("malformed", "Unable to parse YAML configuration"),
        ("invalid", "rules.port_scan.port_threshold"),
    ],
)
def test_configuration_errors_exit_cleanly(
    tmp_path: Path,
    config_kind: str,
    expected_message: str,
) -> None:
    pcap_path = tmp_path / "normal.pcap"
    config_path = tmp_path / "config.yaml"
    write_pcap(pcap_path, [make_tcp_packet(flags="PA")])
    if config_kind == "malformed":
        config_path.write_text("rules:\n  port_scan: [\n", encoding="utf-8")
    elif config_kind == "invalid":
        config_path = write_config(
            tmp_path,
            {"rules": {"port_scan": {"port_threshold": 0}}},
        )

    result = runner.invoke(
        app,
        [
            "analyze",
            "--pcap",
            str(pcap_path),
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code != 0
    assert expected_message in result.output
    assert "Traceback" not in result.output


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


def test_dns_alert_is_written_to_alert_jsonl(tmp_path: Path) -> None:
    pcap_path = tmp_path / "dns-alert.pcap"
    alert_log = tmp_path / "dns-alerts.jsonl"
    write_pcap(pcap_path, make_dns_query_packets(31))

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
    assert len(records) == 1
    assert records[0]["rule_id"] == "DNS_ANOMALY_001"
    evidence = records[0]["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["anomaly_type"] == "query_burst"


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
    assert "Protocol OTHER" in result.output


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


def test_cli_parses_each_raw_packet_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pcap_path = tmp_path / "single-parse.pcap"
    write_pcap(
        pcap_path,
        [
            make_tcp_packet(flags="PA"),
            make_tcp_packet(timestamp=BASE_TIMESTAMP + 1, flags="A"),
        ],
    )
    from mini_ids.parser import parse_packet as real_parse_packet

    parse_calls = 0

    def counting_parser(packet: Packet):
        nonlocal parse_calls
        parse_calls += 1
        return real_parse_packet(packet)

    monkeypatch.setattr("mini_ids.cli.parse_packet", counting_parser)

    result = runner.invoke(app, ["analyze", "--pcap", str(pcap_path)])

    assert result.exit_code == 0
    assert parse_calls == 2


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


def test_default_engine_registers_all_current_rules() -> None:
    rules = build_rules(load_config())

    assert [type(rule) for rule in rules] == [
        PortScanRule,
        ConnectionBurstRule,
        DNSAnomalyRule,
    ]


def test_cli_does_not_add_standalone_dns_or_live_features() -> None:
    app_help = runner.invoke(app, ["--help"])
    analyze_help = runner.invoke(app, ["analyze", "--help"])

    assert app_help.exit_code == 0
    assert analyze_help.exit_code == 0
    assert "live" not in app_help.output.lower()
    assert "dns" not in analyze_help.output.lower()
    assert "traffic-summary" not in analyze_help.output.lower()
