import json
from dataclasses import replace
from pathlib import Path

import pytest

from mini_ids.logger import (
    write_alert_jsonl,
    write_alerts_jsonl,
    write_packet_jsonl,
    write_packets_jsonl,
)
from mini_ids.models import Alert, PacketInfo


def make_alert(
    *,
    rule_id: str = "TEST-001",
    description: str = "Test alert.",
    evidence: dict[str, object] | None = None,
) -> Alert:
    return Alert(
        timestamp="2026-07-20T12:00:00Z",
        rule_id=rule_id,
        rule_name="Logger Test Rule",
        severity="MEDIUM",
        description=description,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        protocol="TCP",
        evidence=evidence if evidence is not None else {},
    )


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_writes_one_packet_record(
    tmp_path: Path,
    normal_tcp_packets: list[PacketInfo],
) -> None:
    path = tmp_path / "packets.jsonl"
    packet = normal_tcp_packets[0]

    write_packet_jsonl(packet, path)

    assert read_jsonl(path) == [packet.to_dict()]


def test_writes_multiple_packet_records(
    tmp_path: Path,
    mixed_normal_packets: list[PacketInfo],
) -> None:
    path = tmp_path / "packets.jsonl"

    write_packets_jsonl(mixed_normal_packets, path)

    assert read_jsonl(path) == [
        packet.to_dict() for packet in mixed_normal_packets
    ]


def test_writes_one_alert_record(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    alert = make_alert()

    write_alert_jsonl(alert, path)

    assert read_jsonl(path) == [alert.to_dict()]


def test_writes_multiple_alert_records(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    alerts = [make_alert(rule_id="TEST-001"), make_alert(rule_id="TEST-002")]

    write_alerts_jsonl(alerts, path)

    assert read_jsonl(path) == [alert.to_dict() for alert in alerts]


def test_append_is_the_default_and_preserves_existing_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "alerts.jsonl"
    first = make_alert(rule_id="TEST-001")
    second = make_alert(rule_id="TEST-002")

    write_alert_jsonl(first, path)
    write_alert_jsonl(second, path)

    assert read_jsonl(path) == [first.to_dict(), second.to_dict()]


def test_append_mode_does_not_discard_preexisting_data(tmp_path: Path) -> None:
    path = tmp_path / "packets.jsonl"
    path.write_text('{"existing": true}\n', encoding="utf-8")
    packet = PacketInfo(
        timestamp=1_720_000_000.0,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_length=60,
        tcp_flags="S",
    )

    write_packet_jsonl(packet, path)

    assert read_jsonl(path) == [{"existing": True}, packet.to_dict()]


def test_append_separates_existing_record_without_trailing_newline(
    tmp_path: Path,
) -> None:
    path = tmp_path / "alerts.jsonl"
    path.write_text('{"existing": true}', encoding="utf-8")
    alert = make_alert()

    write_alert_jsonl(alert, path)

    assert read_jsonl(path) == [{"existing": True}, alert.to_dict()]


def test_explicit_overwrite_replaces_existing_records(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    first = make_alert(rule_id="TEST-001")
    replacement = make_alert(rule_id="TEST-002")
    write_alert_jsonl(first, path)

    write_alert_jsonl(replacement, path, append=False)

    assert read_jsonl(path) == [replacement.to_dict()]


def test_parent_directories_are_created_automatically(
    tmp_path: Path,
    normal_tcp_packets: list[PacketInfo],
) -> None:
    path = tmp_path / "nested" / "packet-logs" / "packets.jsonl"

    write_packet_jsonl(normal_tcp_packets[0], path)

    assert path.is_file()


def test_string_paths_are_supported(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    alert = make_alert()

    write_alert_jsonl(alert, str(path))

    assert read_jsonl(path) == [alert.to_dict()]


def test_every_output_line_is_valid_json(
    tmp_path: Path,
    mixed_normal_packets: list[PacketInfo],
) -> None:
    path = tmp_path / "packets.jsonl"

    write_packets_jsonl(mixed_normal_packets, path)
    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == len(mixed_normal_packets)
    assert all(isinstance(json.loads(line), dict) for line in lines)


def test_alert_evidence_remains_valid_json(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    alert = make_alert(
        evidence={
            "connection_attempt_count": 51,
            "destination_ports": [22, 80, 443],
            "details": {"window_seconds": 60},
        }
    )

    write_alert_jsonl(alert, path)

    assert read_jsonl(path)[0]["evidence"] == alert.evidence


def test_newlines_inside_models_do_not_create_extra_records(
    tmp_path: Path,
    normal_tcp_packets: list[PacketInfo],
) -> None:
    packet_path = tmp_path / "packets.jsonl"
    alert_path = tmp_path / "alerts.jsonl"
    packet = replace(
        normal_tcp_packets[0],
        raw_summary="first line\nsecond line",
    )
    alert = make_alert(
        description="first line\nsecond line",
        evidence={"note": "alpha\nbeta"},
    )

    write_packet_jsonl(packet, packet_path)
    write_alert_jsonl(alert, alert_path)

    assert len(packet_path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(alert_path.read_text(encoding="utf-8").splitlines()) == 1
    assert read_jsonl(packet_path)[0] == packet.to_dict()
    assert read_jsonl(alert_path)[0] == alert.to_dict()


def test_empty_iterables_create_empty_valid_files(tmp_path: Path) -> None:
    packet_path = tmp_path / "packets.jsonl"
    alert_path = tmp_path / "alerts.jsonl"

    write_packets_jsonl([], packet_path)
    write_alerts_jsonl([], alert_path)

    assert packet_path.read_text(encoding="utf-8") == ""
    assert alert_path.read_text(encoding="utf-8") == ""


def test_filesystem_errors_are_not_swallowed(
    tmp_path: Path,
    normal_tcp_packets: list[PacketInfo],
) -> None:
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("blocking file", encoding="utf-8")
    invalid_path = parent_file / "packets.jsonl"

    with pytest.raises(OSError):
        write_packet_jsonl(normal_tcp_packets[0], invalid_path)
