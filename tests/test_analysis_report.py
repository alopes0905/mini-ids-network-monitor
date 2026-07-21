import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mini_ids.models import Alert
from mini_ids.reporting import (
    AnalysisReport,
    TrafficSummary,
    build_analysis_report,
    write_analysis_report,
)


STARTED = datetime(2026, 7, 21, 20, 15, 30, 123456, tzinfo=UTC)
FINISHED = datetime(2026, 7, 21, 20, 15, 31, 654321, tzinfo=UTC)


def make_detection_summary(
    *,
    packets_processed: object = 3,
    alerts_generated: object = 0,
    severity_counts: object | None = None,
) -> dict[str, object]:
    return {
        "packets_processed": packets_processed,
        "alerts_generated": alerts_generated,
        "severity_counts": (
            {"LOW": 0, "MEDIUM": alerts_generated, "HIGH": 0, "CRITICAL": 0}
            if severity_counts is None
            else severity_counts
        ),
    }


def make_traffic_summary() -> TrafficSummary:
    return TrafficSummary(
        packets_processed=8,
        source_packet_counts={
            "192.0.2.10": 3,
            "192.0.2.20": 2,
            "192.0.2.30": 1,
            "192.0.2.40": 1,
            "192.0.2.50": 1,
            "192.0.2.60": 1,
        },
        destination_packet_counts={
            "198.51.100.10": 4,
            "198.51.100.20": 2,
            "198.51.100.30": 1,
            "198.51.100.40": 1,
        },
        destination_port_counts={443: 4, 53: 2, 80: 1, 22: 1},
        protocol_counts={"TCP": 5, "DNS": 2, "OTHER": 1},
        dns_query_count=2,
    )


def make_alert(
    *,
    rule_id: str = "TEST_001",
    timestamp: str = "2026-07-21T20:15:30.500000Z",
) -> Alert:
    return Alert(
        timestamp=timestamp,
        rule_id=rule_id,
        rule_name="Synthetic Detection",
        severity="MEDIUM",
        description="Synthetic alert for report testing.",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        protocol="TCP",
        evidence={"ports": [22, 80, 443]},
        recommendation="Review the source host.",
    )


def build_report(
    *,
    pcap_file: str | Path = "pcaps/sample.pcap",
    analysis_started: datetime | str = STARTED,
    analysis_finished: datetime | str = FINISHED,
    detection_summary: dict[str, object] | None = None,
    traffic_summary: TrafficSummary | None = None,
    alerts: object = (),
) -> AnalysisReport:
    return build_analysis_report(
        pcap_file=pcap_file,
        analysis_started=analysis_started,
        analysis_finished=analysis_finished,
        detection_summary=(
            make_detection_summary()
            if detection_summary is None
            else detection_summary
        ),
        traffic_summary=(
            make_traffic_summary()
            if traffic_summary is None
            else traffic_summary
        ),
        alerts=alerts,  # type: ignore[arg-type]
    )


def test_minimal_empty_report_is_valid() -> None:
    traffic = TrafficSummary(0, {}, {}, {}, {}, 0)

    report = build_report(
        detection_summary=make_detection_summary(packets_processed=0),
        traffic_summary=traffic,
    )

    assert report.pcap_file == "pcaps/sample.pcap"
    assert report.alerts == ()
    assert report.to_dict()["traffic_summary"] == {
        "packets_processed": 0,
        "source_packet_counts": {},
        "destination_packet_counts": {},
        "destination_port_counts": {},
        "protocol_counts": {},
        "dns_query_count": 0,
        "top_sources": [],
        "top_destinations": [],
        "top_destination_ports": [],
    }


def test_full_report_preserves_multiple_alerts_in_order() -> None:
    alerts = [make_alert(rule_id="FIRST"), make_alert(rule_id="SECOND")]

    report = build_report(
        detection_summary=make_detection_summary(alerts_generated=2),
        alerts=alerts,
    )

    assert [alert.rule_id for alert in report.alerts] == ["FIRST", "SECOND"]
    assert [alert["rule_id"] for alert in report.to_dict()["alerts"]] == [
        "FIRST",
        "SECOND",
    ]


def test_alert_generator_is_consumed_once() -> None:
    yielded = 0

    def alerts():
        nonlocal yielded
        for rule_id in ("FIRST", "SECOND"):
            yielded += 1
            yield make_alert(rule_id=rule_id)

    report = build_report(
        detection_summary=make_detection_summary(alerts_generated=2),
        alerts=alerts(),
    )

    assert yielded == 2
    assert [alert.rule_id for alert in report.alerts] == ["FIRST", "SECOND"]


@pytest.mark.parametrize(
    "pcap_file",
    ["pcaps/sample.pcap", Path("pcaps/sample.pcap")],
)
def test_string_and_path_pcap_inputs_are_supported(
    pcap_file: str | Path,
) -> None:
    assert build_report(pcap_file=pcap_file).pcap_file == "pcaps/sample.pcap"


def test_utc_timestamps_use_z_format() -> None:
    report = build_report()

    assert report.analysis_started == "2026-07-21T20:15:30.123456Z"
    assert report.analysis_finished == "2026-07-21T20:15:31.654321Z"


def test_non_utc_timestamps_are_normalized_to_utc() -> None:
    offset = timezone(timedelta(hours=2))

    report = build_report(
        analysis_started=datetime(2026, 7, 21, 22, 15, 30, tzinfo=offset),
        analysis_finished="2026-07-21T22:15:31+02:00",
    )

    assert report.analysis_started == "2026-07-21T20:15:30Z"
    assert report.analysis_finished == "2026-07-21T20:15:31Z"


def test_utc_string_timestamps_are_validated_and_normalized() -> None:
    report = build_report(
        analysis_started="2026-07-21T20:15:30Z",
        analysis_finished="2026-07-21T20:15:31+00:00",
    )

    assert report.analysis_started == "2026-07-21T20:15:30Z"
    assert report.analysis_finished == "2026-07-21T20:15:31Z"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("analysis_started", datetime(2026, 7, 21, 20, 15, 30)),
        ("analysis_finished", "2026-07-21T20:15:31"),
    ],
)
def test_naive_timestamps_are_rejected(field_name: str, value: object) -> None:
    values = {
        "analysis_started": STARTED,
        "analysis_finished": FINISHED,
        field_name: value,
    }

    with pytest.raises(ValueError, match=f"{field_name} must be timezone-aware"):
        build_report(**values)  # type: ignore[arg-type]


def test_invalid_timestamp_string_is_rejected_with_clear_field() -> None:
    with pytest.raises(ValueError, match="analysis_started.*ISO 8601"):
        build_report(analysis_started="not-a-timestamp")


def test_non_datetime_timestamp_type_is_rejected() -> None:
    with pytest.raises(TypeError, match="analysis_started"):
        build_report(analysis_started=123)  # type: ignore[arg-type]


def test_finish_before_start_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be earlier"):
        build_report(
            analysis_started=FINISHED,
            analysis_finished=STARTED,
        )


def test_detection_summary_is_normalized_and_detached() -> None:
    summary = make_detection_summary(
        severity_counts={"MEDIUM": 0},
    )

    report = build_report(detection_summary=summary)
    summary["packets_processed"] = 999
    severity_counts = summary["severity_counts"]
    assert isinstance(severity_counts, dict)
    severity_counts["MEDIUM"] = 999

    assert report.detection_summary == {
        "packets_processed": 3,
        "alerts_generated": 0,
        "severity_counts": {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        },
    }


def test_alerts_are_detached_from_caller_collection_and_evidence() -> None:
    alert = make_alert()
    alerts = [alert]
    report = build_report(
        detection_summary=make_detection_summary(alerts_generated=1),
        alerts=alerts,
    )

    alerts.append(make_alert(rule_id="LATER"))
    alert.evidence["ports"] = [9999]

    assert len(report.alerts) == 1
    assert report.alerts[0].evidence == {"ports": [22, 80, 443]}


def test_traffic_summary_is_copied_without_mutating_input() -> None:
    traffic = make_traffic_summary()
    before = traffic.to_dict()

    report = build_report(traffic_summary=traffic)
    traffic.source_packet_counts["192.0.2.99"] = 100

    assert report.traffic_summary.source_packet_counts != traffic.source_packet_counts
    assert before["destination_packet_counts"] == (
        report.traffic_summary.to_dict()["destination_packet_counts"]
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("packets_processed", True),
        ("packets_processed", -1),
        ("packets_processed", 1.5),
        ("alerts_generated", False),
        ("alerts_generated", -1),
        ("alerts_generated", "1"),
    ],
)
def test_invalid_detection_totals_are_rejected(
    field_name: str,
    value: object,
) -> None:
    summary = make_detection_summary()
    summary[field_name] = value

    with pytest.raises(ValueError, match=field_name):
        build_report(detection_summary=summary)


@pytest.mark.parametrize("value", [True, -1, 1.5, "1"])
def test_invalid_severity_counts_are_rejected(value: object) -> None:
    summary = make_detection_summary(severity_counts={"MEDIUM": value})

    with pytest.raises(ValueError, match="severity_counts.MEDIUM"):
        build_report(detection_summary=summary)


def test_unknown_severity_is_rejected() -> None:
    summary = make_detection_summary(severity_counts={"INFO": 0})

    with pytest.raises(ValueError, match="Unknown severity.*INFO"):
        build_report(detection_summary=summary)


def test_unknown_and_missing_detection_fields_are_rejected() -> None:
    unknown = make_detection_summary()
    unknown["extra"] = 1
    missing = make_detection_summary()
    del missing["packets_processed"]

    with pytest.raises(ValueError, match="Unknown detection summary field"):
        build_report(detection_summary=unknown)
    with pytest.raises(ValueError, match="Missing detection summary field"):
        build_report(detection_summary=missing)


def test_severity_counts_must_be_a_mapping() -> None:
    summary = make_detection_summary(severity_counts=[])

    with pytest.raises(ValueError, match="severity_counts must be a mapping"):
        build_report(detection_summary=summary)


def test_alert_count_must_match_detection_summary() -> None:
    with pytest.raises(ValueError, match="must match the alert count"):
        build_report(
            detection_summary=make_detection_summary(alerts_generated=1),
            alerts=[],
        )


def test_invalid_alert_and_traffic_inputs_are_rejected() -> None:
    with pytest.raises(TypeError, match="alerts must contain Alert"):
        build_report(alerts=["not-an-alert"])
    with pytest.raises(TypeError, match="traffic_summary"):
        build_report(traffic_summary="invalid")  # type: ignore[arg-type]


def test_to_dict_contains_string_port_keys_and_bounded_top_five() -> None:
    report = build_report()

    traffic = report.to_dict()["traffic_summary"]
    assert isinstance(traffic, dict)
    assert traffic["destination_port_counts"] == {
        "443": 4,
        "53": 2,
        "80": 1,
        "22": 1,
    }
    assert len(traffic["top_sources"]) == 5
    assert traffic["top_sources"][0] == {
        "source_ip": "192.0.2.10",
        "packet_count": 3,
    }
    assert traffic["top_destination_ports"][0] == {
        "destination_port": 443,
        "packet_count": 4,
    }


def test_to_dict_and_to_json_are_valid_and_repeatably_detached() -> None:
    alert = make_alert()
    report = build_report(
        detection_summary=make_detection_summary(alerts_generated=1),
        alerts=[alert],
    )

    first = report.to_dict()
    parsed = json.loads(report.to_json())
    compact = json.loads(report.to_json(indent=None))
    first["detection_summary"]["packets_processed"] = 999
    first["alerts"][0]["evidence"]["ports"] = []

    assert parsed == compact
    assert report.to_dict()["detection_summary"]["packets_processed"] == 3
    assert report.to_dict()["alerts"][0]["evidence"] == {
        "ports": [22, 80, 443]
    }


@pytest.mark.parametrize("path_kind", ["path", "string"])
def test_writer_creates_parent_and_returns_path(
    tmp_path: Path,
    path_kind: str,
) -> None:
    report = build_report()
    path = tmp_path / "nested" / "reports" / "analysis.json"
    supplied_path: str | Path = str(path) if path_kind == "string" else path

    result = write_analysis_report(report, supplied_path)

    assert result == path
    assert json.loads(path.read_text(encoding="utf-8")) == report.to_dict()


def test_writer_ends_with_exactly_one_newline(tmp_path: Path) -> None:
    report = build_report()
    path = tmp_path / "analysis.json"

    write_analysis_report(report, path)
    contents = path.read_text(encoding="utf-8")

    assert contents.endswith("\n")
    assert not contents.endswith("\n\n")


def test_writer_overwrites_existing_report_as_one_json_document(
    tmp_path: Path,
) -> None:
    path = tmp_path / "analysis.json"
    path.write_text('{"stale": true}\n{"second": true}\n', encoding="utf-8")
    report = build_report()

    write_analysis_report(report, path)

    assert json.loads(path.read_text(encoding="utf-8")) == report.to_dict()


def test_writer_can_refuse_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "analysis.json"
    path.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="already exists"):
        write_analysis_report(build_report(), path, overwrite=False)

    assert path.read_text(encoding="utf-8") == "existing"


def test_writer_rejects_non_boolean_overwrite(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="overwrite must be a boolean"):
        write_analysis_report(
            build_report(),
            tmp_path / "analysis.json",
            overwrite=1,  # type: ignore[arg-type]
        )


def test_writer_filesystem_errors_propagate(tmp_path: Path) -> None:
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("blocking", encoding="utf-8")
    report_path = blocking_file / "analysis.json"

    with pytest.raises(OSError):
        write_analysis_report(build_report(), report_path)

    assert not report_path.exists()
