"""Human-readable Rich console output for Mini IDS results."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from itertools import islice

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mini_ids.models import Alert, SEVERITY_LEVELS, Severity
from mini_ids.reporting import TrafficSummary


_SEVERITY_STYLES: dict[Severity, str] = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}
_MAX_EVIDENCE_ITEMS = 6
_MAX_COLLECTION_ITEMS = 5
_MAX_VALUE_LENGTH = 120
_MAX_PROTOCOL_ROWS = 10


def _get_console(console: Console | None) -> Console:
    return console if console is not None else Console()


def _clip_text(value: object, limit: int = _MAX_VALUE_LENGTH) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _format_evidence_value(value: object, depth: int = 0) -> str:
    if isinstance(value, Mapping):
        if depth >= 2:
            return f"<{len(value)} fields>"
        items = list(islice(value.items(), _MAX_COLLECTION_ITEMS))
        parts = [
            f"{_clip_text(key, 30)}: {_format_evidence_value(item, depth + 1)}"
            for key, item in items
        ]
        if len(value) > len(items):
            parts.append(f"... +{len(value) - len(items)}")
        return _clip_text("{" + ", ".join(parts) + "}")

    if isinstance(value, (list, tuple)):
        if depth >= 2:
            return f"<{len(value)} items>"
        items = value[:_MAX_COLLECTION_ITEMS]
        parts = [_format_evidence_value(item, depth + 1) for item in items]
        if len(value) > len(items):
            parts.append(f"... +{len(value) - len(items)}")
        return _clip_text("[" + ", ".join(parts) + "]")

    return _clip_text(value)


def _format_evidence(evidence: Mapping[str, object]) -> str:
    items = list(islice(evidence.items(), _MAX_EVIDENCE_ITEMS))
    lines = [
        f"{_clip_text(key, 40)}: {_format_evidence_value(value)}"
        for key, value in items
    ]
    if len(evidence) > len(items):
        lines.append(f"... ({len(evidence) - len(items)} more fields)")
    return "\n".join(lines)


def _format_endpoint(ip_address: str | None, port: int | None) -> str:
    if ip_address is None:
        return f"port {port}"
    if port is None:
        return ip_address
    if ":" in ip_address:
        return f"[{ip_address}]:{port}"
    return f"{ip_address}:{port}"


def print_alert(alert: Alert, console: Console | None = None) -> None:
    """Print one structured alert in a human-readable terminal format."""

    output = _get_console(console)
    severity_style = _SEVERITY_STYLES[alert.severity]
    details = Table.grid(padding=(0, 2))
    details.add_column(style="bold", no_wrap=True)
    details.add_column()
    details.add_row("Severity", Text(alert.severity, style=severity_style))
    details.add_row("Timestamp", Text(alert.timestamp))
    details.add_row("Description", Text(alert.description))

    if alert.src_ip is not None or alert.src_port is not None:
        details.add_row(
            "Source",
            Text(_format_endpoint(alert.src_ip, alert.src_port)),
        )
    if alert.dst_ip is not None or alert.dst_port is not None:
        details.add_row(
            "Destination",
            Text(_format_endpoint(alert.dst_ip, alert.dst_port)),
        )
    if alert.protocol is not None:
        details.add_row("Protocol", Text(alert.protocol))
    if alert.mitre_attack is not None:
        details.add_row("MITRE ATT&CK", Text(alert.mitre_attack))
    if alert.recommendation is not None:
        details.add_row("Recommendation", Text(alert.recommendation))
    if alert.evidence:
        details.add_row("Evidence", Text(_format_evidence(alert.evidence)))

    title = Text(f"{alert.rule_name} ({alert.rule_id})")
    output.print(
        Panel(
            details,
            title=title,
            border_style=severity_style,
            expand=False,
        )
    )


def print_alerts(
    alerts: Iterable[Alert],
    console: Console | None = None,
) -> None:
    """Print alerts in iteration order or an empty-result message."""

    output = _get_console(console)
    alert_found = False
    for alert in alerts:
        alert_found = True
        print_alert(alert, output)

    if not alert_found:
        output.print("No alerts generated.", style="dim")


def print_summary(
    summary: Mapping[str, object],
    console: Console | None = None,
) -> None:
    """Print a detection-engine summary without changing its values."""

    output = _get_console(console)
    severity_counts_value = summary.get("severity_counts", {})
    severity_counts = (
        severity_counts_value
        if isinstance(severity_counts_value, Mapping)
        else {}
    )

    table = Table(title="Detection Summary", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("Packets processed", str(summary.get("packets_processed", 0)))
    table.add_row("Alerts generated", str(summary.get("alerts_generated", 0)))
    for severity in SEVERITY_LEVELS:
        table.add_row(
            f"{severity} alerts",
            Text(
                str(severity_counts.get(severity, 0)),
                style=_SEVERITY_STYLES[severity],
            ),
        )

    output.print(table)


def print_traffic_summary(
    summary: TrafficSummary,
    console: Console | None = None,
    *,
    top_limit: int = 5,
) -> None:
    """Print bounded aggregate traffic metadata without changing the summary."""

    output = _get_console(console)
    table = Table(title="Traffic Summary", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total parsed packets", str(summary.packets_processed))
    table.add_row("DNS queries", str(summary.dns_query_count))

    ranked_protocols = sorted(
        summary.protocol_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    for protocol, count in ranked_protocols[:_MAX_PROTOCOL_ROWS]:
        table.add_row(f"Protocol {protocol}", str(count))
    if not ranked_protocols:
        table.add_row("Protocols", "None observed")
    elif len(ranked_protocols) > _MAX_PROTOCOL_ROWS:
        table.add_row(
            "Additional protocols",
            str(len(ranked_protocols) - _MAX_PROTOCOL_ROWS),
        )

    table.add_row(
        "Top sources",
        _format_ranked_counts(summary.top_sources(top_limit)),
    )
    table.add_row(
        "Top destinations",
        _format_ranked_counts(summary.top_destinations(top_limit)),
    )
    table.add_row(
        "Top destination ports",
        _format_ranked_counts(summary.top_destination_ports(top_limit)),
    )
    output.print(table)


def _format_ranked_counts(values: list[tuple[object, int]]) -> str:
    if not values:
        return "None observed"
    return ", ".join(f"{key} ({count})" for key, count in values)
