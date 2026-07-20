from copy import deepcopy
from io import StringIO

import pytest
from rich.console import Console

from mini_ids.console import (
    print_alert,
    print_alerts,
    print_summary,
    print_traffic_summary,
)
from mini_ids.models import Alert, SEVERITY_LEVELS, Severity
from mini_ids.reporting import TrafficSummary


def make_console() -> tuple[Console, StringIO]:
    stream = StringIO()
    console = Console(
        file=stream,
        color_system=None,
        force_terminal=False,
        width=120,
    )
    return console, stream


def make_alert(
    *,
    rule_id: str = "TEST-001",
    rule_name: str = "Test Detection",
    severity: Severity = "MEDIUM",
    description: str = "Suspicious activity was observed.",
    **optional_fields: object,
) -> Alert:
    return Alert(
        timestamp="2026-07-20T12:00:00Z",
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        description=description,
        **optional_fields,
    )


def make_traffic_summary() -> TrafficSummary:
    return TrafficSummary(
        packets_processed=6,
        source_packet_counts={"192.0.2.10": 4, "192.0.2.20": 2},
        destination_packet_counts={
            "198.51.100.20": 3,
            "198.51.100.53": 3,
        },
        destination_port_counts={443: 4, 53: 2},
        protocol_counts={"TCP": 4, "DNS": 2},
        dns_query_count=2,
    )


def test_prints_minimal_alert() -> None:
    console, stream = make_console()
    alert = make_alert()

    print_alert(alert, console)

    output = stream.getvalue()
    assert "MEDIUM" in output
    assert "Test Detection" in output
    assert "TEST-001" in output
    assert "2026-07-20T12:00:00Z" in output
    assert "Suspicious activity was observed." in output


def test_prints_alert_with_all_optional_fields() -> None:
    console, stream = make_console()
    alert = make_alert(
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=51000,
        dst_port=443,
        protocol="TCP",
        evidence={"attempt_count": 51},
        mitre_attack="T1046 - Network Service Discovery",
        recommendation="Review the source host.",
    )

    print_alert(alert, console)

    output = stream.getvalue()
    assert "192.0.2.10:51000" in output
    assert "198.51.100.20:443" in output
    assert "TCP" in output
    assert "attempt_count: 51" in output
    assert "T1046 - Network Service Discovery" in output
    assert "Review the source host." in output


def test_none_optional_fields_are_omitted() -> None:
    console, stream = make_console()

    print_alert(make_alert(), console)

    output = stream.getvalue()
    assert "Source" not in output
    assert "Destination" not in output
    assert "Protocol" not in output
    assert "MITRE ATT&CK" not in output
    assert "Recommendation" not in output
    assert "Evidence" not in output
    assert "None" not in output


def test_mitre_mapping_and_recommendation_appear_only_when_present() -> None:
    console, stream = make_console()
    print_alert(make_alert(), console)
    minimal_output = stream.getvalue()

    console, stream = make_console()
    print_alert(
        make_alert(
            mitre_attack="T1046 - Network Service Discovery",
            recommendation="Investigate this source.",
        ),
        console,
    )
    detailed_output = stream.getvalue()

    assert "MITRE ATT&CK" not in minimal_output
    assert "Recommendation" not in minimal_output
    assert "T1046 - Network Service Discovery" in detailed_output
    assert "Investigate this source." in detailed_output


def test_evidence_is_compact_and_bounded() -> None:
    console, stream = make_console()
    evidence = {
        f"field_{index}": list(range(20))
        for index in range(20)
    }

    print_alert(make_alert(evidence=evidence), console)

    output = stream.getvalue()
    assert "field_0" in output
    assert "... +15" in output
    assert "14 more fields" in output
    assert "field_19" not in output
    assert len(output) < 2_000


def test_nested_and_long_evidence_values_are_bounded() -> None:
    console, stream = make_console()
    evidence = {
        "nested": {
            "mapping": {"deeper": {"hidden": "value"}},
            "sequence": [[1, 2, 3]],
            "third": 3,
            "fourth": 4,
            "fifth": 5,
            "sixth": 6,
        },
        "long_value": "x" * 300,
    }

    print_alert(make_alert(evidence=evidence), console)

    output = stream.getvalue()
    assert "<1 fields>" in output
    assert "<3 items>" in output
    assert "..." in output
    assert "x" * 150 not in output


def test_port_only_and_ipv6_endpoints_are_readable() -> None:
    console, stream = make_console()

    print_alert(
        make_alert(
            src_port=51000,
            dst_ip="2001:db8::20",
            dst_port=443,
        ),
        console,
    )

    output = stream.getvalue()
    assert "port 51000" in output
    assert "[2001:db8::20]:443" in output


@pytest.mark.parametrize("severity", SEVERITY_LEVELS)
def test_all_severity_levels_are_supported(severity: Severity) -> None:
    console, stream = make_console()

    print_alert(make_alert(severity=severity), console)

    assert severity in stream.getvalue()


def test_plain_output_is_understandable_without_color() -> None:
    console, stream = make_console()

    print_alert(
        make_alert(
            severity="HIGH",
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
        ),
        console,
    )

    output = stream.getvalue()
    assert "\x1b[" not in output
    assert "HIGH" in output
    assert "Source" in output
    assert "Destination" in output


def test_dynamic_text_is_rendered_literally_not_as_rich_markup() -> None:
    console, stream = make_console()

    print_alert(
        make_alert(
            rule_name="[Rule]",
            description="Review [bold]literal text[/bold].",
            evidence={"note": "[red]untrusted label[/red]"},
        ),
        console,
    )

    output = stream.getvalue()
    assert "[Rule]" in output
    assert "[bold]literal text[/bold]" in output
    assert "[red]untrusted label[/red]" in output


def test_multiple_alerts_preserve_iterable_order() -> None:
    console, stream = make_console()
    alerts = (
        make_alert(rule_name="First Rule"),
        make_alert(rule_name="Second Rule"),
        make_alert(rule_name="Third Rule"),
    )

    print_alerts(iter(alerts), console)

    output = stream.getvalue()
    assert output.index("First Rule") < output.index("Second Rule")
    assert output.index("Second Rule") < output.index("Third Rule")


def test_empty_alert_iterable_is_handled_gracefully() -> None:
    console, stream = make_console()

    print_alerts(iter(()), console)

    assert "No alerts generated." in stream.getvalue()


def test_summary_displays_totals_and_every_severity() -> None:
    console, stream = make_console()
    summary = {
        "packets_processed": 10,
        "alerts_generated": 3,
        "severity_counts": {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 0,
        },
    }

    print_summary(summary, console)

    output = stream.getvalue()
    assert "Detection Summary" in output
    assert "Packets processed" in output
    assert "10" in output
    assert "Alerts generated" in output
    assert "3" in output
    for severity in SEVERITY_LEVELS:
        assert f"{severity} alerts" in output


def test_missing_summary_severity_keys_are_displayed_as_zero() -> None:
    console, stream = make_console()
    summary = {
        "packets_processed": 4,
        "alerts_generated": 1,
        "severity_counts": {"HIGH": 1},
    }

    print_summary(summary, console)

    output = stream.getvalue()
    assert "LOW alerts" in output
    assert "MEDIUM alerts" in output
    assert "HIGH alerts" in output
    assert "CRITICAL alerts" in output
    assert output.count("0") >= 3


def test_traffic_summary_displays_totals_protocols_and_rankings() -> None:
    console, stream = make_console()

    print_traffic_summary(make_traffic_summary(), console)

    output = stream.getvalue()
    assert "Traffic Summary" in output
    assert "Total parsed packets" in output
    assert "6" in output
    assert "DNS queries" in output
    assert "Protocol TCP" in output
    assert "Protocol DNS" in output
    assert "Top sources" in output
    assert "192.0.2.10 (4)" in output
    assert "Top destinations" in output
    assert "198.51.100.20 (3)" in output
    assert "Top destination ports" in output
    assert "443 (4)" in output


def test_empty_traffic_summary_is_clear() -> None:
    console, stream = make_console()
    summary = TrafficSummary(
        packets_processed=0,
        source_packet_counts={},
        destination_packet_counts={},
        destination_port_counts={},
        protocol_counts={},
        dns_query_count=0,
    )

    print_traffic_summary(summary, console)

    output = stream.getvalue()
    assert "Total parsed packets" in output
    assert "Protocols" in output
    assert output.count("None observed") == 4


def test_traffic_summary_output_is_bounded() -> None:
    console, stream = make_console()
    summary = TrafficSummary(
        packets_processed=20,
        source_packet_counts={
            f"192.0.2.{index}": 20 - index for index in range(20)
        },
        destination_packet_counts={
            f"198.51.100.{index}": 20 - index for index in range(20)
        },
        destination_port_counts={
            1000 + index: 20 - index for index in range(20)
        },
        protocol_counts={
            f"PROTO-{index}": 20 - index for index in range(20)
        },
        dns_query_count=0,
    )

    print_traffic_summary(summary, console)

    output = stream.getvalue()
    assert "192.0.2.0 (20)" in output
    assert "192.0.2.5 (15)" not in output
    assert "198.51.100.5 (15)" not in output
    assert "1005 (15)" not in output
    assert "Protocol PROTO-9" in output
    assert "Protocol PROTO-10" not in output
    assert "Additional protocols" in output
    assert len(output) < 3_000


def test_traffic_summary_rendering_does_not_mutate_input() -> None:
    console, _ = make_console()
    summary = make_traffic_summary()
    before = deepcopy(summary)

    print_traffic_summary(summary, console)

    assert summary == before


def test_provided_console_is_used_instead_of_standard_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    console, stream = make_console()

    print_alert(make_alert(), console)
    print_summary({}, console)
    print_traffic_summary(make_traffic_summary(), console)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "Test Detection" in stream.getvalue()
    assert "Detection Summary" in stream.getvalue()
    assert "Traffic Summary" in stream.getvalue()


def test_console_functions_do_not_mutate_inputs() -> None:
    console, _ = make_console()
    alerts = [
        make_alert(
            evidence={"ports": [22, 80, 443]},
            recommendation="Review network logs.",
        )
    ]
    summary = {
        "packets_processed": 10,
        "alerts_generated": 1,
        "severity_counts": {"MEDIUM": 1},
    }
    alerts_before = deepcopy(alerts)
    summary_before = deepcopy(summary)

    print_alert(alerts[0], console)
    print_alerts(alerts, console)
    print_summary(summary, console)

    assert alerts == alerts_before
    assert summary == summary_before
