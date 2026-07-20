"""TCP connection-attempt burst detection."""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

from mini_ids.models import Alert, PacketInfo, Severity
from mini_ids.rules.base import DetectionRule


@dataclass(frozen=True)
class _ConnectionAttempt:
    timestamp: float
    destination_ip: str | None
    destination_port: int | None


@dataclass
class _SourceState:
    attempts: deque[_ConnectionAttempt] = field(default_factory=deque)
    last_timestamp: float | None = None
    alerting: bool = False


class ConnectionBurstRule(DetectionRule):
    """Detect unusually high TCP connection-attempt volume from one source."""

    rule_id = "CONNECTION_BURST_001"
    name = "TCP Connection Burst"
    description = (
        "Detects one source sending many initial TCP connection attempts "
        "within a rolling time window."
    )
    severity: Severity = "MEDIUM"

    def __init__(
        self,
        connection_threshold: int = 50,
        time_window_seconds: float = 60.0,
    ) -> None:
        if (
            isinstance(connection_threshold, bool)
            or not isinstance(connection_threshold, int)
            or connection_threshold < 1
        ):
            raise ValueError("connection_threshold must be a positive integer")
        if (
            isinstance(time_window_seconds, bool)
            or not isinstance(time_window_seconds, (int, float))
            or not math.isfinite(time_window_seconds)
            or time_window_seconds <= 0
        ):
            raise ValueError("time_window_seconds must be a positive finite number")

        self.connection_threshold = connection_threshold
        self.time_window_seconds = float(time_window_seconds)
        self._states: dict[str, _SourceState] = {}

    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        """Process one packet and return a connection-burst alert if warranted."""

        details = self._candidate_details(packet)
        if details is None:
            return []

        source_ip, timestamp = details
        state = self._states.setdefault(source_ip, _SourceState())

        if state.last_timestamp is not None and timestamp < state.last_timestamp:
            return []

        self._expire_attempts(state, timestamp)
        state.last_timestamp = timestamp
        state.attempts.append(
            _ConnectionAttempt(
                timestamp=timestamp,
                destination_ip=packet.dst_ip,
                destination_port=packet.dst_port,
            )
        )

        attempt_count = len(state.attempts)
        if attempt_count <= self.connection_threshold or state.alerting:
            return []

        state.alerting = True
        return [self._build_alert(source_ip, timestamp, state)]

    def _candidate_details(self, packet: PacketInfo) -> tuple[str, float] | None:
        if packet.protocol != "TCP" or not packet.src_ip:
            return None
        if not isinstance(packet.tcp_flags, str):
            return None

        flags = packet.tcp_flags.upper()
        if "S" not in flags or "A" in flags:
            return None

        timestamp = self._usable_timestamp(packet.timestamp)
        if timestamp is None:
            return None

        return packet.src_ip, timestamp

    @staticmethod
    def _usable_timestamp(value: object) -> float | None:
        if isinstance(value, bool):
            return None

        try:
            timestamp = float(value)
        except (TypeError, ValueError):
            return None

        if not math.isfinite(timestamp) or timestamp <= 0:
            return None

        try:
            datetime.fromtimestamp(timestamp, UTC)
        except (OverflowError, OSError, ValueError):
            return None

        return timestamp

    def _expire_attempts(self, state: _SourceState, timestamp: float) -> None:
        cutoff = timestamp - self.time_window_seconds

        while state.attempts and state.attempts[0].timestamp < cutoff:
            state.attempts.popleft()

        if state.alerting and len(state.attempts) <= self.connection_threshold:
            state.alerting = False

    def _build_alert(
        self,
        source_ip: str,
        timestamp: float,
        state: _SourceState,
    ) -> Alert:
        attempt_count = len(state.attempts)
        first_timestamp = state.attempts[0].timestamp
        destination_ips = Counter(
            attempt.destination_ip
            for attempt in state.attempts
            if attempt.destination_ip is not None
        )
        destination_ports = Counter(
            attempt.destination_port
            for attempt in state.attempts
            if attempt.destination_port is not None
        )

        return Alert(
            timestamp=self._format_timestamp(timestamp),
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=(
                f"Source {source_ip} sent {attempt_count} initial TCP "
                f"connection attempts within {self.time_window_seconds:g} seconds."
            ),
            src_ip=source_ip,
            protocol="TCP",
            evidence={
                "source_ip": source_ip,
                "connection_attempt_count": attempt_count,
                "connection_threshold": self.connection_threshold,
                "time_window_seconds": self.time_window_seconds,
                "first_active_timestamp": self._format_timestamp(first_timestamp),
                "latest_active_timestamp": self._format_timestamp(timestamp),
                "observed_destination_ip_count": len(destination_ips),
                "observed_destination_port_count": len(destination_ports),
                "top_destination_ips": self._top_destination_ips(destination_ips),
                "top_destination_ports": self._top_destination_ports(
                    destination_ports
                ),
            },
            recommendation=(
                "Review the source host and correlate this activity with "
                "authentication, firewall, and service logs."
            ),
        )

    @staticmethod
    def _format_timestamp(timestamp: float) -> str:
        return (
            datetime.fromtimestamp(timestamp, UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _top_destination_ips(
        counts: Counter[str],
    ) -> list[dict[str, object]]:
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        return [
            {"destination_ip": destination_ip, "attempt_count": count}
            for destination_ip, count in ranked
        ]

    @staticmethod
    def _top_destination_ports(
        counts: Counter[int],
    ) -> list[dict[str, object]]:
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        return [
            {"destination_port": destination_port, "attempt_count": count}
            for destination_port, count in ranked
        ]
