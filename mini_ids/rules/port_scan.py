"""Vertical TCP port-scan detection."""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

from mini_ids.models import Alert, PacketInfo, Severity
from mini_ids.rules.base import DetectionRule


@dataclass
class _PairState:
    observations: deque[tuple[float, int]] = field(default_factory=deque)
    port_counts: Counter[int] = field(default_factory=Counter)
    last_timestamp: float | None = None
    alerting: bool = False


class PortScanRule(DetectionRule):
    """Detect TCP SYN attempts to many ports on one destination host."""

    rule_id = "PORT_SCAN_001"
    name = "Vertical TCP Port Scan"
    description = (
        "Detects one source sending initial TCP connection attempts to many "
        "ports on the same destination within a rolling time window."
    )
    severity: Severity = "MEDIUM"

    def __init__(
        self,
        port_threshold: int = 10,
        time_window_seconds: float = 60.0,
    ) -> None:
        if (
            isinstance(port_threshold, bool)
            or not isinstance(port_threshold, int)
            or port_threshold < 1
        ):
            raise ValueError("port_threshold must be a positive integer")
        if (
            isinstance(time_window_seconds, bool)
            or not isinstance(time_window_seconds, (int, float))
            or not math.isfinite(time_window_seconds)
            or time_window_seconds <= 0
        ):
            raise ValueError("time_window_seconds must be a positive finite number")

        self.port_threshold = port_threshold
        self.time_window_seconds = float(time_window_seconds)
        self._states: dict[tuple[str, str], _PairState] = {}

    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        """Process one packet and return a port-scan alert when warranted."""

        details = self._candidate_details(packet)
        if details is None:
            return []

        pair, destination_port, timestamp = details
        state = self._states.setdefault(pair, _PairState())

        if state.last_timestamp is not None and timestamp < state.last_timestamp:
            return []

        self._expire_observations(state, timestamp)
        state.last_timestamp = timestamp
        state.observations.append((timestamp, destination_port))
        state.port_counts[destination_port] += 1

        distinct_port_count = len(state.port_counts)
        if distinct_port_count <= self.port_threshold or state.alerting:
            return []

        state.alerting = True
        return [self._build_alert(packet, timestamp, state)]

    def _candidate_details(
        self,
        packet: PacketInfo,
    ) -> tuple[tuple[str, str], int, float] | None:
        if packet.protocol != "TCP":
            return None
        if not packet.src_ip or not packet.dst_ip:
            return None
        if (
            packet.dst_port is None
            or isinstance(packet.dst_port, bool)
            or not 1 <= packet.dst_port <= 65535
        ):
            return None
        if not isinstance(packet.tcp_flags, str):
            return None

        flags = packet.tcp_flags.upper()
        if "S" not in flags or "A" in flags:
            return None

        timestamp = self._usable_timestamp(packet.timestamp)
        if timestamp is None:
            return None

        return (packet.src_ip, packet.dst_ip), packet.dst_port, timestamp

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

    def _expire_observations(self, state: _PairState, timestamp: float) -> None:
        cutoff = timestamp - self.time_window_seconds

        while state.observations and state.observations[0][0] < cutoff:
            _, destination_port = state.observations.popleft()
            state.port_counts[destination_port] -= 1
            if state.port_counts[destination_port] == 0:
                del state.port_counts[destination_port]

        if state.alerting and len(state.port_counts) <= self.port_threshold:
            state.alerting = False

    def _build_alert(
        self,
        packet: PacketInfo,
        timestamp: float,
        state: _PairState,
    ) -> Alert:
        destination_ports = sorted(state.port_counts)
        distinct_port_count = len(destination_ports)

        return Alert(
            timestamp=datetime.fromtimestamp(timestamp, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=(
                f"Source {packet.src_ip} sent TCP SYN attempts to "
                f"{distinct_port_count} distinct ports on {packet.dst_ip} "
                f"within {self.time_window_seconds:g} seconds."
            ),
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            protocol="TCP",
            evidence={
                "source_ip": packet.src_ip,
                "destination_ip": packet.dst_ip,
                "distinct_port_count": distinct_port_count,
                "destination_ports": destination_ports,
                "port_threshold": self.port_threshold,
                "time_window_seconds": self.time_window_seconds,
            },
            mitre_attack="T1046 - Network Service Discovery",
            recommendation=(
                "Review the source host and confirm whether this destination-port "
                "probing is authorized."
            ),
        )
