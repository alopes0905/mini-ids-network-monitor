"""Detection rule orchestration for normalized packet metadata."""

from __future__ import annotations

from collections.abc import Iterable

from mini_ids.models import Alert, PacketInfo, SEVERITY_LEVELS, Severity
from mini_ids.rules import DetectionRule


class DetectionEngine:
    """Run registered detection rules and track basic processing statistics.

    Rules execute in registration order. Unexpected rule exceptions propagate
    to the caller, and statistics are updated only after all rules successfully
    process a packet. Resetting engine statistics does not reset rule state.
    """

    def __init__(self, rules: Iterable[DetectionRule] | None = None) -> None:
        self._rules = list(rules) if rules is not None else []
        self.reset_statistics()

    @property
    def rules(self) -> tuple[DetectionRule, ...]:
        """Return registered rules in execution order."""

        return tuple(self._rules)

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a rule to run after the existing rules."""

        self._rules.append(rule)

    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        """Process one packet through every rule and return generated alerts."""

        alerts: list[Alert] = []
        for rule in self._rules:
            alerts.extend(rule.process_packet(packet))

        self._packets_processed += 1
        self._alerts_generated += len(alerts)
        for alert in alerts:
            self._severity_counts[alert.severity] += 1

        return alerts

    def process_packets(self, packets: Iterable[PacketInfo]) -> list[Alert]:
        """Process an iterable of packets and return all alerts in order."""

        alerts: list[Alert] = []
        for packet in packets:
            alerts.extend(self.process_packet(packet))
        return alerts

    def get_summary(self) -> dict[str, object]:
        """Return a snapshot of cumulative engine statistics."""

        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "severity_counts": dict(self._severity_counts),
        }

    def reset_statistics(self) -> None:
        """Reset engine counters without changing registered rules or rule state."""

        self._packets_processed = 0
        self._alerts_generated = 0
        self._severity_counts: dict[Severity, int] = {
            severity: 0 for severity in SEVERITY_LEVELS
        }
