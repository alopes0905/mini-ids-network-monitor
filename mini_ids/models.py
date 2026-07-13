"""Data models used by Mini IDS."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class PacketInfo:
    """Normalized packet metadata used by future parsers and detection rules.

    Expected protocol values are ``TCP``, ``UDP``, ``ICMP``, ``DNS``, and
    ``OTHER``. Parser code should normalize protocol names before creating this
    model.
    """

    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_length: int
    tcp_flags: str | None = None
    dns_query: str | None = None
    dns_response: str | None = None
    raw_summary: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a dictionary representation suitable for logs and tests."""

        return asdict(self)

    def to_json(self) -> str:
        """Return a JSON representation suitable for JSONL-style output."""

        return json.dumps(self.to_dict(), sort_keys=True)
