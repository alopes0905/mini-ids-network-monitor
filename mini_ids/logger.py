"""Structured JSON Lines persistence for Mini IDS models."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from mini_ids.models import Alert, PacketInfo


def _needs_line_separator(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False

    with path.open("rb") as existing_file:
        existing_file.seek(-1, 2)
        return existing_file.read(1) not in {b"\n", b"\r"}


def _write_jsonl(
    records: Iterable[PacketInfo | Alert],
    path: str | Path,
    *,
    append: bool,
) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    needs_separator = append and _needs_line_separator(output_path)

    with output_path.open(mode, encoding="utf-8", newline="\n") as output_file:
        for record in records:
            if needs_separator:
                output_file.write("\n")
                needs_separator = False
            output_file.write(record.to_json())
            output_file.write("\n")


def write_packet_jsonl(
    packet: PacketInfo,
    path: str | Path,
    *,
    append: bool = True,
) -> None:
    """Write one packet record to a JSONL file."""

    _write_jsonl((packet,), path, append=append)


def write_packets_jsonl(
    packets: Iterable[PacketInfo],
    path: str | Path,
    *,
    append: bool = True,
) -> None:
    """Write packet records to a JSONL file in iteration order."""

    _write_jsonl(packets, path, append=append)


def write_alert_jsonl(
    alert: Alert,
    path: str | Path,
    *,
    append: bool = True,
) -> None:
    """Write one alert record to a JSONL file."""

    _write_jsonl((alert,), path, append=append)


def write_alerts_jsonl(
    alerts: Iterable[Alert],
    path: str | Path,
    *,
    append: bool = True,
) -> None:
    """Write alert records to a JSONL file in iteration order."""

    _write_jsonl(alerts, path, append=append)
