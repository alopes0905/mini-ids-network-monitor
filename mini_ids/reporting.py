"""Aggregate traffic metadata from normalized packets."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from mini_ids.models import PacketInfo


_Key = TypeVar("_Key", str, int)


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
