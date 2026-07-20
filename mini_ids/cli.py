"""Command-line interface for offline Mini IDS analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mini_ids.capture import PcapReadError, read_pcap
from mini_ids.console import print_alerts, print_summary
from mini_ids.engine import DetectionEngine
from mini_ids.logger import write_alerts_jsonl, write_packets_jsonl
from mini_ids.models import PacketInfo
from mini_ids.parser import parse_packet
from mini_ids.rules import ConnectionBurstRule, PortScanRule


class OutputWriteError(Exception):
    """Raised when a requested analysis log cannot be written."""


app = typer.Typer(
    name="mini-ids",
    help="Analyze offline PCAP files with defensive detection rules.",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def cli() -> None:
    """Analyze offline PCAP files with Mini IDS."""


def _create_default_engine() -> DetectionEngine:
    return DetectionEngine(
        rules=[
            PortScanRule(),
            ConnectionBurstRule(),
        ]
    )


def analyze_pcap(
    pcap_path: Path,
    *,
    packet_log: Path | None = None,
    alert_log: Path | None = None,
    console: Console | None = None,
) -> dict[str, object]:
    """Analyze one PCAP using the default rules and return its engine summary."""

    parsed_packets: list[PacketInfo] = []
    for raw_packet in read_pcap(pcap_path):
        packet = parse_packet(raw_packet)
        if packet is not None:
            parsed_packets.append(packet)

    engine = _create_default_engine()
    alerts = engine.process_packets(parsed_packets)
    summary = engine.get_summary()

    if packet_log is not None:
        try:
            write_packets_jsonl(parsed_packets, packet_log, append=False)
        except OSError as exc:
            raise OutputWriteError(
                f"Unable to write packet log: {packet_log}: {exc}"
            ) from exc
    if alert_log is not None:
        try:
            write_alerts_jsonl(alerts, alert_log, append=False)
        except OSError as exc:
            raise OutputWriteError(
                f"Unable to write alert log: {alert_log}: {exc}"
            ) from exc

    print_alerts(alerts, console)
    print_summary(summary, console)
    return summary


@app.command()
def analyze(
    pcap: Annotated[
        Path,
        typer.Option(
            "--pcap",
            help="Path to the offline PCAP file to analyze.",
        ),
    ],
    packet_log: Annotated[
        Path | None,
        typer.Option(
            "--packet-log",
            help="Optional JSONL path for parsed packet records.",
        ),
    ] = None,
    alert_log: Annotated[
        Path | None,
        typer.Option(
            "--alert-log",
            help="Optional JSONL path for generated alert records.",
        ),
    ] = None,
) -> None:
    """Analyze an offline PCAP with the default Mini IDS rules."""

    try:
        analyze_pcap(
            pcap,
            packet_log=packet_log,
            alert_log=alert_log,
        )
    except (FileNotFoundError, PcapReadError, OutputWriteError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None


def main() -> None:
    """Run the Mini IDS command-line application."""

    app()


if __name__ == "__main__":
    main()
