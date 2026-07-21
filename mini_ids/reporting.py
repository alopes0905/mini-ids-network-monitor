"""Aggregate traffic metadata from normalized packets."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from mini_ids.models import Alert, PacketInfo, SEVERITY_LEVELS


_Key = TypeVar("_Key", str, int)
_REPORT_TOP_LIMIT = 5


def _validate_limit(limit: object) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    return limit


def _rank_counts(
    counts: Mapping[_Key, int],
    limit: int,
) -> list[tuple[_Key, int]]:
    validated_limit = _validate_limit(limit)
    return sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0]),
    )[:validated_limit]


@dataclass(frozen=True)
class TrafficSummary:
    """Aggregate metadata for one collection of normalized packets."""

    packets_processed: int
    source_packet_counts: dict[str, int]
    destination_packet_counts: dict[str, int]
    destination_port_counts: dict[int, int]
    protocol_counts: dict[str, int]
    dns_query_count: int

    def top_sources(self, limit: int = 5) -> list[tuple[str, int]]:
        """Return source IP counts ranked by count, then address text."""

        return _rank_counts(self.source_packet_counts, limit)

    def top_destinations(self, limit: int = 5) -> list[tuple[str, int]]:
        """Return destination IP counts ranked by count, then address text."""

        return _rank_counts(self.destination_packet_counts, limit)

    def top_destination_ports(self, limit: int = 5) -> list[tuple[int, int]]:
        """Return destination-port counts ranked by count, then port number."""

        return _rank_counts(self.destination_port_counts, limit)

    def to_dict(self) -> dict[str, object]:
        """Return detached JSON-compatible summary data.

        Destination ports remain integers in the model and become strings only
        in this serialized representation because JSON object keys are strings.
        """

        return {
            "packets_processed": self.packets_processed,
            "source_packet_counts": dict(self.source_packet_counts),
            "destination_packet_counts": dict(
                self.destination_packet_counts
            ),
            "destination_port_counts": {
                str(port): count
                for port, count in self.destination_port_counts.items()
            },
            "protocol_counts": dict(self.protocol_counts),
            "dns_query_count": self.dns_query_count,
        }


@dataclass(frozen=True)
class AnalysisReport:
    """Detached, complete result of one offline PCAP analysis."""

    pcap_file: str
    analysis_started: str
    analysis_finished: str
    detection_summary: dict[str, object]
    traffic_summary: TrafficSummary
    alerts: tuple[Alert, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a detached, JSON-compatible analysis document."""

        traffic_data = self.traffic_summary.to_dict()
        traffic_data["top_sources"] = [
            {"source_ip": source_ip, "packet_count": count}
            for source_ip, count in self.traffic_summary.top_sources(
                _REPORT_TOP_LIMIT
            )
        ]
        traffic_data["top_destinations"] = [
            {"destination_ip": destination_ip, "packet_count": count}
            for destination_ip, count in self.traffic_summary.top_destinations(
                _REPORT_TOP_LIMIT
            )
        ]
        traffic_data["top_destination_ports"] = [
            {"destination_port": port, "packet_count": count}
            for port, count in self.traffic_summary.top_destination_ports(
                _REPORT_TOP_LIMIT
            )
        ]
        return {
            "pcap_file": self.pcap_file,
            "analysis_started": self.analysis_started,
            "analysis_finished": self.analysis_finished,
            "detection_summary": deepcopy(self.detection_summary),
            "traffic_summary": traffic_data,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Return deterministic JSON text without writing a file."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )


def build_traffic_summary(packets: Iterable[PacketInfo]) -> TrafficSummary:
    """Consume normalized packets once and return aggregate traffic metadata."""

    packets_processed = 0
    source_packet_counts: Counter[str] = Counter()
    destination_packet_counts: Counter[str] = Counter()
    destination_port_counts: Counter[int] = Counter()
    protocol_counts: Counter[str] = Counter()
    dns_query_count = 0

    for packet in packets:
        packets_processed += 1
        if packet.src_ip:
            source_packet_counts[packet.src_ip] += 1
        if packet.dst_ip:
            destination_packet_counts[packet.dst_ip] += 1
        if packet.dst_port is not None:
            destination_port_counts[packet.dst_port] += 1
        protocol_counts[packet.protocol] += 1
        if packet.protocol == "DNS" and packet.dns_query:
            dns_query_count += 1

    return TrafficSummary(
        packets_processed=packets_processed,
        source_packet_counts=dict(source_packet_counts),
        destination_packet_counts=dict(destination_packet_counts),
        destination_port_counts=dict(destination_port_counts),
        protocol_counts=dict(protocol_counts),
        dns_query_count=dns_query_count,
    )


def build_analysis_report(
    *,
    pcap_file: str | Path,
    analysis_started: datetime | str,
    analysis_finished: datetime | str,
    detection_summary: Mapping[str, object],
    traffic_summary: TrafficSummary,
    alerts: Iterable[Alert],
) -> AnalysisReport:
    """Validate and detach completed-analysis data into one report model."""

    started_datetime, started_text = _normalize_timestamp(
        analysis_started,
        "analysis_started",
    )
    finished_datetime, finished_text = _normalize_timestamp(
        analysis_finished,
        "analysis_finished",
    )
    if finished_datetime < started_datetime:
        raise ValueError("analysis_finished must not be earlier than analysis_started")

    detached_alerts: list[Alert] = []
    for alert in alerts:
        if not isinstance(alert, Alert):
            raise TypeError("alerts must contain Alert objects")
        detached_alerts.append(deepcopy(alert))

    normalized_detection = _normalize_detection_summary(detection_summary)
    alerts_generated = normalized_detection["alerts_generated"]
    if alerts_generated != len(detached_alerts):
        raise ValueError(
            "detection_summary.alerts_generated must match the alert count"
        )

    if not isinstance(traffic_summary, TrafficSummary):
        raise TypeError("traffic_summary must be a TrafficSummary")

    return AnalysisReport(
        pcap_file=str(pcap_file),
        analysis_started=started_text,
        analysis_finished=finished_text,
        detection_summary=normalized_detection,
        traffic_summary=_copy_traffic_summary(traffic_summary),
        alerts=tuple(detached_alerts),
    )


def write_analysis_report(
    report: AnalysisReport,
    path: str | Path,
    *,
    overwrite: bool = True,
) -> Path:
    """Write one UTF-8 JSON document to an explicit caller-supplied path."""

    if not isinstance(overwrite, bool):
        raise ValueError("overwrite must be a boolean")

    output_path = Path(path)
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Analysis report already exists: {output_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        f"{report.to_json()}\n",
        encoding="utf-8",
    )
    return output_path


def _normalize_timestamp(
    value: datetime | str,
    field_name: str,
) -> tuple[datetime, str]:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be a valid ISO 8601 timestamp"
            ) from exc
    else:
        raise TypeError(f"{field_name} must be a datetime or ISO 8601 string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")

    normalized = parsed.astimezone(UTC)
    return normalized, normalized.isoformat().replace("+00:00", "Z")


def _normalize_detection_summary(
    summary: Mapping[str, object],
) -> dict[str, object]:
    allowed_fields = {
        "packets_processed",
        "alerts_generated",
        "severity_counts",
    }
    unknown_fields = set(summary) - allowed_fields
    if unknown_fields:
        unknown = sorted(unknown_fields, key=str)[0]
        raise ValueError(f"Unknown detection summary field: {unknown!r}")

    missing_fields = allowed_fields - set(summary)
    if missing_fields:
        missing = sorted(missing_fields)[0]
        raise ValueError(f"Missing detection summary field: {missing}")

    packets_processed = _require_non_negative_count(
        summary["packets_processed"],
        "detection_summary.packets_processed",
    )
    alerts_generated = _require_non_negative_count(
        summary["alerts_generated"],
        "detection_summary.alerts_generated",
    )

    severity_value = summary["severity_counts"]
    if not isinstance(severity_value, Mapping):
        raise ValueError("detection_summary.severity_counts must be a mapping")
    unknown_severities = set(severity_value) - set(SEVERITY_LEVELS)
    if unknown_severities:
        unknown = sorted(unknown_severities, key=str)[0]
        raise ValueError(f"Unknown severity in detection summary: {unknown!r}")

    severity_counts = {
        severity: _require_non_negative_count(
            severity_value.get(severity, 0),
            f"detection_summary.severity_counts.{severity}",
        )
        for severity in SEVERITY_LEVELS
    }
    return {
        "packets_processed": packets_processed,
        "alerts_generated": alerts_generated,
        "severity_counts": severity_counts,
    }


def _require_non_negative_count(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return value


def _copy_traffic_summary(summary: TrafficSummary) -> TrafficSummary:
    return TrafficSummary(
        packets_processed=summary.packets_processed,
        source_packet_counts=dict(summary.source_packet_counts),
        destination_packet_counts=dict(summary.destination_packet_counts),
        destination_port_counts=dict(summary.destination_port_counts),
        protocol_counts=dict(summary.protocol_counts),
        dns_query_count=summary.dns_query_count,
    )
