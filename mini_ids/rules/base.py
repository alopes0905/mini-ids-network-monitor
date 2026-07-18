"""Common interface for packet detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mini_ids.models import Alert, PacketInfo, Severity


class DetectionRule(ABC):
    """Contract implemented by all packet detection rules.

    Rule instances may retain state between calls to support counters and time
    windows. State storage and detection behavior belong to concrete rules.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Return the stable identifier for this rule."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the human-readable rule name."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a concise description of the rule's purpose."""

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Return the severity assigned to alerts from this rule."""

    @abstractmethod
    def process_packet(self, packet: PacketInfo) -> list[Alert]:
        """Process normalized packet metadata and return generated alerts."""
