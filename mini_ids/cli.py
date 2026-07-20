"""Command-line interface for offline Mini IDS analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mini_ids.capture import PcapReadError, read_pcap
from mini_ids.config import AppConfig, ConfigError, build_rules, load_config
from mini_ids.console import print_alerts, print_summary, print_traffic_summary
from mini_ids.engine import DetectionEngine
from mini_ids.logger import write_alerts_jsonl, write_packets_jsonl
from mini_ids.models import PacketInfo
from mini_ids.parser import parse_packet
from mini_ids.reporting import build_traffic_summary


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


def analyze_pcap(
    pcap_path: Path,
    *,
    config: AppConfig | None = None,
    packet_log: Path | None = None,
    alert_log: Path | None = None,
    console: Console | None = None,
) -> dict[str, object]:
    """Analyze one PCAP using configured rules and return its engine summary."""

    parsed_packets: list[PacketInfo] = []
    for raw_packet in read_pcap(pcap_path):
        packet = parse_packet(raw_packet)
        if packet is not None:
            parsed_packets.append(packet)

    active_config = config if config is not None else load_config()
    engine = DetectionEngine(build_rules(active_config))
    alerts = engine.process_packets(parsed_packets)
    summary = engine.get_summary()
    traffic_summary = build_traffic_summary(parsed_packets)

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
    print_traffic_summary(traffic_summary, console)
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
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="Optional YAML configuration for detection rules.",
        ),
    ] = None,
) -> None:
    """Analyze an offline PCAP with the configured Mini IDS rules."""

    try:
        active_config = load_config(config)
        analyze_pcap(
            pcap,
            config=active_config,
            packet_log=packet_log,
            alert_log=alert_log,
        )
    except (
        ConfigError,
        FileNotFoundError,
        PcapReadError,
        OutputWriteError,
    ) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from None


def main() -> None:
    """Run the Mini IDS command-line application."""

    app()


if __name__ == "__main__":
    main()
