"""Stateful DNS query anomaly detection."""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

from mini_ids.models import Alert, PacketInfo, Severity
from mini_ids.rules.base import DetectionRule


@dataclass
class _SourceState:
    observations: deque[tuple[float, str]] = field(default_factory=deque)
    domain_counts: Counter[str] = field(default_factory=Counter)
    long_domain_last_seen: dict[str, float] = field(default_factory=dict)
    last_timestamp: float | None = None
    query_alerting: bool = False
    unique_domain_alerting: bool = False


class DNSAnomalyRule(DetectionRule):
    """Detect DNS query bursts, unique-domain bursts, and long domains."""

    rule_id = "DNS_ANOMALY_001"
    name = "DNS Anomaly Detection"
    description = (
        "Detects unusually high DNS query or unique-domain volume and "
        "unusually long queried domain names."
    )
    severity: Severity = "MEDIUM"
    mitre_attack = "T1071.004 - Application Layer Protocol: DNS"

    def __init__(
        self,
        query_threshold: int = 30,
        unique_domain_threshold: int = 20,
        long_domain_threshold: int = 70,
        time_window_seconds: float = 60.0,
    ) -> None:
        self.query_threshold = self._validate_threshold(
            query_threshold,
            "query_threshold",
        )
        self.unique_domain_threshold = self._validate_threshold(
            unique_domain_threshold,
            "unique_domain_threshold",
        )
        self.long_domain_threshold = self._validate_threshold(
            long_domain_threshold,
            "long_domain_threshold",
        )
        if (
            isinstance(time_window_seconds, bool)
            or not isinstance(time_window_seconds, (int, float))
            or not math.isfinite(time_window_seconds)
            or time_window_seconds <= 0
        ):
            raise ValueError("time_window_seconds must be a positive finite number")

        self.time_window_seconds = float(time_window_seconds)
        self._states: dict[str, _SourceState] = {}

    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        """Process one normalized DNS packet and return anomaly alerts."""

        details = self._candidate_details(packet)
        if details is None:
            return []

        source_ip, domain, timestamp = details
        state = self._states.setdefault(source_ip, _SourceState())
        if state.last_timestamp is not None and timestamp < state.last_timestamp:
            return []

        self._expire_observations(state, timestamp)
        state.last_timestamp = timestamp
        state.observations.append((timestamp, domain))
        state.domain_counts[domain] += 1

        alerts: list[Alert] = []
        query_count = len(state.observations)
        if query_count > self.query_threshold and not state.query_alerting:
            state.query_alerting = True
            alerts.append(
                self._build_query_burst_alert(packet, timestamp, state)
            )

        unique_domain_count = len(state.domain_counts)
        if (
            unique_domain_count > self.unique_domain_threshold
            and not state.unique_domain_alerting
        ):
            state.unique_domain_alerting = True
            alerts.append(
                self._build_unique_domain_alert(packet, timestamp, state)
            )

        if len(domain) > self.long_domain_threshold:
            previous_timestamp = state.long_domain_last_seen.get(domain)
            state.long_domain_last_seen[domain] = timestamp
            if previous_timestamp is None:
                alerts.append(
                    self._build_long_domain_alert(packet, domain, timestamp)
                )

        return alerts

    @staticmethod
    def _validate_threshold(value: object, field_name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{field_name} must be a positive integer")
        return value

    def _candidate_details(
        self,
        packet: PacketInfo,
    ) -> tuple[str, str, float] | None:
        if packet.protocol != "DNS" or not packet.src_ip:
            return None

        domain = self._normalize_domain(packet.dns_query)
        if domain is None:
            return None

        timestamp = self._usable_timestamp(packet.timestamp)
        if timestamp is None:
            return None

        return packet.src_ip, domain, timestamp

    @staticmethod
    def _normalize_domain(value: object) -> str | None:
        if not isinstance(value, str) or not value:
            return None

        normalized = value[:-1] if value.endswith(".") else value
        normalized = normalized.lower()
        return normalized or None

    @staticmethod
    def _usable_timestamp(value: object) -> float | None:
        if isinstance(value, bool):
            return None

        try:
            timestamp = float(value)
        except (OverflowError, TypeError, ValueError):
            return None

        if not math.isfinite(timestamp) or timestamp <= 0:
            return None

        try:
            datetime.fromtimestamp(timestamp, UTC)
        except (OverflowError, OSError, ValueError):
            return None

        return timestamp

    def _expire_observations(
        self,
        state: _SourceState,
        timestamp: float,
    ) -> None:
        cutoff = timestamp - self.time_window_seconds
        while state.observations and state.observations[0][0] < cutoff:
            _, domain = state.observations.popleft()
            state.domain_counts[domain] -= 1
            if state.domain_counts[domain] == 0:
                del state.domain_counts[domain]

        expired_long_domains = [
            domain
            for domain, last_seen in state.long_domain_last_seen.items()
            if last_seen < cutoff
        ]
        for domain in expired_long_domains:
            del state.long_domain_last_seen[domain]

        if state.query_alerting and len(state.observations) <= self.query_threshold:
            state.query_alerting = False
        if (
            state.unique_domain_alerting
            and len(state.domain_counts) <= self.unique_domain_threshold
        ):
            state.unique_domain_alerting = False

    def _build_query_burst_alert(
        self,
        packet: PacketInfo,
        timestamp: float,
        state: _SourceState,
    ) -> Alert:
        query_count = len(state.observations)
        return self._build_alert(
            packet=packet,
            timestamp=timestamp,
            description=(
                f"Source {packet.src_ip} sent {query_count} DNS queries within "
                f"{self.time_window_seconds:g} seconds."
            ),
            evidence={
                "anomaly_type": "query_burst",
                "source_ip": packet.src_ip,
                "active_query_count": query_count,
                "query_threshold": self.query_threshold,
                "time_window_seconds": self.time_window_seconds,
                "first_active_timestamp": self._format_timestamp(
                    state.observations[0][0]
                ),
                "latest_active_timestamp": self._format_timestamp(timestamp),
            },
        )

    def _build_unique_domain_alert(
        self,
        packet: PacketInfo,
        timestamp: float,
        state: _SourceState,
    ) -> Alert:
        unique_domain_count = len(state.domain_counts)
        return self._build_alert(
            packet=packet,
            timestamp=timestamp,
            description=(
                f"Source {packet.src_ip} queried {unique_domain_count} unique "
                f"domains within {self.time_window_seconds:g} seconds."
            ),
            evidence={
                "anomaly_type": "unique_domain_burst",
                "source_ip": packet.src_ip,
                "active_unique_domain_count": unique_domain_count,
                "unique_domain_threshold": self.unique_domain_threshold,
                "time_window_seconds": self.time_window_seconds,
                "domain_sample": sorted(state.domain_counts)[:5],
            },
        )

    def _build_long_domain_alert(
        self,
        packet: PacketInfo,
        domain: str,
        timestamp: float,
    ) -> Alert:
        return self._build_alert(
            packet=packet,
            timestamp=timestamp,
            description=(
                f"Source {packet.src_ip} queried a domain with {len(domain)} "
                "characters."
            ),
            evidence={
                "anomaly_type": "long_domain",
                "source_ip": packet.src_ip,
                "normalized_domain": domain,
                "domain_length": len(domain),
                "long_domain_threshold": self.long_domain_threshold,
            },
        )

    def _build_alert(
        self,
        *,
        packet: PacketInfo,
        timestamp: float,
        description: str,
        evidence: dict[str, object],
    ) -> Alert:
        return Alert(
            timestamp=self._format_timestamp(timestamp),
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=description,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol="DNS",
            evidence=evidence,
            mitre_attack=self.mitre_attack,
            recommendation=(
                "Inspect the source host, review resolver logs, and correlate "
                "the queries with endpoint and network telemetry."
            ),
        )

    @staticmethod
    def _format_timestamp(timestamp: float) -> str:
        return (
            datetime.fromtimestamp(timestamp, UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
