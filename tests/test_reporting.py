import json

import pytest

from mini_ids.models import PacketInfo
from mini_ids.reporting import TrafficSummary, build_traffic_summary


BASE_TIMESTAMP = 1_720_000_000.0


def make_packet(
    *,
    source_ip: str | None = "192.0.2.10",
    destination_ip: str | None = "198.51.100.20",
    destination_port: int | None = 443,
    protocol: str = "TCP",
    dns_query: str | None = None,
) -> PacketInfo:
    return PacketInfo(
        timestamp=BASE_TIMESTAMP,
        src_ip=source_ip,
        dst_ip=destination_ip,
        src_port=51000,
        dst_port=destination_port,
        protocol=protocol,
        packet_length=74,
        dns_query=dns_query,
        raw_summary="Synthetic normalized packet",
    )


def make_summary(
    *,
    sources: dict[str, int] | None = None,
    destinations: dict[str, int] | None = None,
    ports: dict[int, int] | None = None,
) -> TrafficSummary:
    return TrafficSummary(
        packets_processed=0,
        source_packet_counts=sources or {},
        destination_packet_counts=destinations or {},
        destination_port_counts=ports or {},
        protocol_counts={},
        dns_query_count=0,
    )


def test_empty_iterable_returns_empty_summary() -> None:
    summary = build_traffic_summary([])

    assert summary == TrafficSummary(
        packets_processed=0,
        source_packet_counts={},
        destination_packet_counts={},
        destination_port_counts={},
        protocol_counts={},
        dns_query_count=0,
    )


def test_list_input_aggregates_all_supported_fields() -> None:
    packets = [
        make_packet(),
        make_packet(
            source_ip="192.0.2.10",
            destination_ip="198.51.100.30",
            destination_port=443,
        ),
        make_packet(
            source_ip="192.0.2.11",
            destination_ip="198.51.100.20",
            destination_port=53,
            protocol="UDP",
        ),
        make_packet(
            source_ip="192.0.2.10",
            destination_ip="198.51.100.53",
            destination_port=53,
            protocol="DNS",
            dns_query="example.com",
        ),
    ]

    summary = build_traffic_summary(packets)

    assert summary.packets_processed == 4
    assert summary.source_packet_counts == {
        "192.0.2.10": 3,
        "192.0.2.11": 1,
    }
    assert summary.destination_packet_counts == {
        "198.51.100.20": 2,
        "198.51.100.30": 1,
        "198.51.100.53": 1,
    }
    assert summary.destination_port_counts == {443: 2, 53: 2}
    assert summary.protocol_counts == {"TCP": 2, "UDP": 1, "DNS": 1}
    assert summary.dns_query_count == 1


def test_generator_input_is_consumed_once() -> None:
    yielded = 0

    def packets():
        nonlocal yielded
        for protocol in ("TCP", "UDP", "ICMP"):
            yielded += 1
            yield make_packet(protocol=protocol)

    summary = build_traffic_summary(packets())

    assert yielded == 3
    assert summary.packets_processed == 3
    assert summary.protocol_counts == {"TCP": 1, "UDP": 1, "ICMP": 1}


def test_other_and_unexpected_protocols_are_retained() -> None:
    summary = build_traffic_summary(
        [
            make_packet(protocol="OTHER", destination_port=None),
            make_packet(protocol="GRE", destination_port=None),
        ]
    )

    assert summary.protocol_counts == {"OTHER": 1, "GRE": 1}


def test_dns_count_requires_dns_protocol_and_non_empty_query() -> None:
    summary = build_traffic_summary(
        [
            make_packet(protocol="DNS", dns_query="example.com"),
            make_packet(protocol="DNS", dns_query=None),
            make_packet(protocol="DNS", dns_query=""),
            make_packet(protocol="UDP", dns_query="not-counted.example"),
        ]
    )

    assert summary.protocol_counts == {"DNS": 3, "UDP": 1}
    assert summary.dns_query_count == 1


def test_missing_and_empty_endpoints_do_not_create_count_keys() -> None:
    summary = build_traffic_summary(
        [
            make_packet(
                source_ip=None,
                destination_ip=None,
                destination_port=None,
                protocol="OTHER",
            ),
            make_packet(
                source_ip="",
                destination_ip="",
                destination_port=None,
                protocol="OTHER",
            ),
        ]
    )

    assert summary.packets_processed == 2
    assert summary.source_packet_counts == {}
    assert summary.destination_packet_counts == {}
    assert summary.destination_port_counts == {}


def test_destination_ports_are_counted_for_any_protocol() -> None:
    summary = build_traffic_summary(
        [
            make_packet(protocol="TCP", destination_port=443),
            make_packet(protocol="UDP", destination_port=443),
            make_packet(protocol="DNS", destination_port=53),
            make_packet(protocol="OTHER", destination_port=None),
        ]
    )

    assert summary.destination_port_counts == {443: 2, 53: 1}


def test_building_summary_does_not_mutate_packets() -> None:
    packets = [
        make_packet(protocol="DNS", dns_query="example.com"),
        make_packet(protocol="OTHER", destination_port=None),
    ]
    before = [packet.to_dict() for packet in packets]

    build_traffic_summary(iter(packets))

    assert [packet.to_dict() for packet in packets] == before


def test_to_dict_is_json_serializable_and_stringifies_port_keys() -> None:
    summary = build_traffic_summary(
        [
            make_packet(destination_port=443),
            make_packet(destination_port=53, protocol="DNS", dns_query="a.test"),
        ]
    )

    data = summary.to_dict()

    assert summary.destination_port_counts == {443: 1, 53: 1}
    assert data["destination_port_counts"] == {"443": 1, "53": 1}
    assert json.loads(json.dumps(data)) == data


def test_to_dict_returns_detached_mappings() -> None:
    summary = build_traffic_summary([make_packet()])

    data = summary.to_dict()
    sources = data["source_packet_counts"]
    assert isinstance(sources, dict)
    sources["192.0.2.99"] = 100

    assert "192.0.2.99" not in summary.source_packet_counts


def test_source_ranking_is_count_first_then_lexical() -> None:
    summary = make_summary(
        sources={
            "192.0.2.30": 2,
            "192.0.2.20": 3,
            "192.0.2.10": 3,
        }
    )

    assert summary.top_sources() == [
        ("192.0.2.10", 3),
        ("192.0.2.20", 3),
        ("192.0.2.30", 2),
    ]


def test_destination_ranking_is_count_first_then_lexical() -> None:
    summary = make_summary(
        destinations={
            "198.51.100.30": 1,
            "198.51.100.20": 2,
            "198.51.100.10": 2,
        }
    )

    assert summary.top_destinations() == [
        ("198.51.100.10", 2),
        ("198.51.100.20", 2),
        ("198.51.100.30", 1),
    ]


def test_destination_port_ranking_uses_numeric_tie_breaking() -> None:
    summary = make_summary(ports={443: 2, 8080: 1, 53: 2, 22: 1})

    assert summary.top_destination_ports() == [
        (53, 2),
        (443, 2),
        (22, 1),
        (8080, 1),
    ]


@pytest.mark.parametrize(
    "method_name",
    ["top_sources", "top_destinations", "top_destination_ports"],
)
def test_zero_limit_returns_empty_result(method_name: str) -> None:
    summary = make_summary(
        sources={"192.0.2.10": 1},
        destinations={"198.51.100.10": 1},
        ports={443: 1},
    )

    method = getattr(summary, method_name)
    assert method(0) == []


def test_limit_larger_than_available_returns_all_entries() -> None:
    summary = make_summary(sources={"192.0.2.10": 2, "192.0.2.20": 1})

    assert summary.top_sources(100) == [
        ("192.0.2.10", 2),
        ("192.0.2.20", 1),
    ]


@pytest.mark.parametrize("limit", [-1, 1.5, "5", True])
@pytest.mark.parametrize(
    "method_name",
    ["top_sources", "top_destinations", "top_destination_ports"],
)
def test_invalid_limits_raise_clear_errors(
    method_name: str,
    limit: object,
) -> None:
    summary = make_summary(
        sources={"192.0.2.10": 1},
        destinations={"198.51.100.10": 1},
        ports={443: 1},
    )
    method = getattr(summary, method_name)

    with pytest.raises(ValueError, match="non-negative integer"):
        method(limit)
