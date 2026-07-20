from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from mini_ids.config import (
    AppConfig,
    ConfigError,
    ConnectionBurstConfig,
    DNSAnomalyConfig,
    PortScanConfig,
    build_rules,
    load_config,
)
from mini_ids.rules import ConnectionBurstRule, DNSAnomalyRule, PortScanRule


EXAMPLE_CONFIG = Path("examples/config.example.yaml")


def write_config(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_none_returns_default_config() -> None:
    assert load_config() == AppConfig()


@pytest.mark.parametrize("contents", ["", "{}\n"])
def test_empty_yaml_uses_defaults(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text(contents, encoding="utf-8")

    assert load_config(path) == AppConfig()


def test_full_valid_configuration_is_normalized(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {
            "rules": {
                "port_scan": {
                    "enabled": False,
                    "port_threshold": 25,
                    "time_window_seconds": 30.5,
                },
                "connection_burst": {
                    "enabled": True,
                    "connection_threshold": 75,
                    "time_window_seconds": 90,
                },
                "dns_anomaly": {
                    "enabled": False,
                    "query_threshold": 12,
                    "unique_domain_threshold": 8,
                    "long_domain_threshold": 50,
                    "time_window_seconds": 45,
                },
            }
        },
    )

    config = load_config(path)

    assert config == AppConfig(
        port_scan=PortScanConfig(
            enabled=False,
            port_threshold=25,
            time_window_seconds=30.5,
        ),
        connection_burst=ConnectionBurstConfig(
            enabled=True,
            connection_threshold=75,
            time_window_seconds=90.0,
        ),
        dns_anomaly=DNSAnomalyConfig(
            enabled=False,
            query_threshold=12,
            unique_domain_threshold=8,
            long_domain_threshold=50,
            time_window_seconds=45.0,
        ),
    )


def test_partial_configuration_uses_defaults_for_omitted_values(
    tmp_path: Path,
) -> None:
    path = write_config(
        tmp_path,
        {"rules": {"port_scan": {"port_threshold": 4}}},
    )

    config = load_config(path)

    assert config.port_scan == PortScanConfig(port_threshold=4)
    assert config.connection_burst == ConnectionBurstConfig()
    assert config.dns_anomaly == DNSAnomalyConfig()


def test_partial_dns_configuration_uses_defaults(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {"rules": {"dns_anomaly": {"query_threshold": 8}}},
    )

    config = load_config(path)

    assert config.dns_anomaly == DNSAnomalyConfig(query_threshold=8)


def test_string_and_path_inputs_are_supported(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {"rules": {"connection_burst": {"connection_threshold": 12}}},
    )

    assert load_config(path) == load_config(str(path))


def test_normalized_config_is_immutable() -> None:
    config = load_config()

    with pytest.raises(FrozenInstanceError):
        config.port_scan = PortScanConfig(enabled=False)  # type: ignore[misc]


def test_direct_config_construction_enforces_validation() -> None:
    with pytest.raises(ConfigError, match="rules.port_scan.port_threshold"):
        PortScanConfig(port_threshold=True)  # type: ignore[arg-type]
    with pytest.raises(
        ConfigError,
        match="rules.connection_burst.time_window_seconds",
    ):
        ConnectionBurstConfig(time_window_seconds=float("inf"))
    with pytest.raises(
        ConfigError,
        match="rules.dns_anomaly.long_domain_threshold",
    ):
        DNSAnomalyConfig(long_domain_threshold=True)  # type: ignore[arg-type]


def test_example_configuration_is_valid_and_matches_defaults() -> None:
    assert load_config(EXAMPLE_CONFIG) == AppConfig()


def test_default_config_matches_current_rule_constructor_defaults() -> None:
    config = load_config()
    port_rule = PortScanRule()
    burst_rule = ConnectionBurstRule()
    dns_rule = DNSAnomalyRule()

    assert config.port_scan.port_threshold == port_rule.port_threshold
    assert config.port_scan.time_window_seconds == port_rule.time_window_seconds
    assert (
        config.connection_burst.connection_threshold
        == burst_rule.connection_threshold
    )
    assert (
        config.connection_burst.time_window_seconds
        == burst_rule.time_window_seconds
    )
    assert config.dns_anomaly.query_threshold == dns_rule.query_threshold
    assert (
        config.dns_anomaly.unique_domain_threshold
        == dns_rule.unique_domain_threshold
    )
    assert (
        config.dns_anomaly.long_domain_threshold
        == dns_rule.long_domain_threshold
    )
    assert (
        config.dns_anomaly.time_window_seconds
        == dns_rule.time_window_seconds
    )


def test_build_rules_preserves_order_and_passes_configured_values() -> None:
    config = AppConfig(
        port_scan=PortScanConfig(
            port_threshold=3,
            time_window_seconds=15.5,
        ),
        connection_burst=ConnectionBurstConfig(
            connection_threshold=7,
            time_window_seconds=25.5,
        ),
        dns_anomaly=DNSAnomalyConfig(
            query_threshold=9,
            unique_domain_threshold=6,
            long_domain_threshold=40,
            time_window_seconds=35.5,
        ),
    )

    rules = build_rules(config)

    assert [type(rule) for rule in rules] == [
        PortScanRule,
        ConnectionBurstRule,
        DNSAnomalyRule,
    ]
    port_rule = rules[0]
    burst_rule = rules[1]
    assert isinstance(port_rule, PortScanRule)
    assert port_rule.port_threshold == 3
    assert port_rule.time_window_seconds == 15.5
    assert isinstance(burst_rule, ConnectionBurstRule)
    assert burst_rule.connection_threshold == 7
    assert burst_rule.time_window_seconds == 25.5
    dns_rule = rules[2]
    assert isinstance(dns_rule, DNSAnomalyRule)
    assert dns_rule.query_threshold == 9
    assert dns_rule.unique_domain_threshold == 6
    assert dns_rule.long_domain_threshold == 40
    assert dns_rule.time_window_seconds == 35.5


@pytest.mark.parametrize(
    ("config", "expected_types"),
    [
        (
            AppConfig(port_scan=PortScanConfig(enabled=False)),
            [ConnectionBurstRule, DNSAnomalyRule],
        ),
        (
            AppConfig(
                connection_burst=ConnectionBurstConfig(enabled=False)
            ),
            [PortScanRule, DNSAnomalyRule],
        ),
        (
            AppConfig(
                port_scan=PortScanConfig(enabled=False),
                connection_burst=ConnectionBurstConfig(enabled=False),
            ),
            [DNSAnomalyRule],
        ),
        (
            AppConfig(dns_anomaly=DNSAnomalyConfig(enabled=False)),
            [PortScanRule, ConnectionBurstRule],
        ),
        (
            AppConfig(
                port_scan=PortScanConfig(enabled=False),
                connection_burst=ConnectionBurstConfig(enabled=False),
                dns_anomaly=DNSAnomalyConfig(enabled=False),
            ),
            [],
        ),
    ],
)
def test_disabled_rules_are_omitted(
    config: AppConfig,
    expected_types: list[type[object]],
) -> None:
    assert [type(rule) for rule in build_rules(config)] == expected_types


def test_missing_configuration_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "missing.yaml"

    with pytest.raises(ConfigError, match="Configuration file not found"):
        load_config(path)


def test_configuration_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Configuration path is not a file"):
        load_config(tmp_path)


def test_unreadable_configuration_preserves_exception_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = write_config(tmp_path, {})

    def deny_read(self: Path, encoding: str) -> str:
        raise PermissionError("permission denied")

    monkeypatch.setattr(Path, "read_text", deny_read)

    with pytest.raises(ConfigError, match="Unable to read") as caught:
        load_config(path)

    assert isinstance(caught.value.__cause__, PermissionError)


def test_invalid_utf8_configuration_is_a_clear_read_error(tmp_path: Path) -> None:
    path = tmp_path / "invalid-utf8.yaml"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(ConfigError, match="Unable to read") as caught:
        load_config(path)

    assert isinstance(caught.value.__cause__, UnicodeDecodeError)


def test_malformed_yaml_preserves_parser_exception_chain(tmp_path: Path) -> None:
    path = tmp_path / "malformed.yaml"
    path.write_text("rules:\n  port_scan: [\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="Unable to parse YAML") as caught:
        load_config(path)

    assert isinstance(caught.value.__cause__, yaml.YAMLError)


@pytest.mark.parametrize("root", [["rules"], "rules", 42])
def test_non_mapping_yaml_root_is_rejected(tmp_path: Path, root: object) -> None:
    path = write_config(tmp_path, root)

    with pytest.raises(ConfigError, match="configuration root must be a mapping"):
        load_config(path)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"general": {}}, "configuration root.*general"),
        ({"rules": {"unknown_rule": {}}}, "rules.*unknown_rule"),
        (
            {"rules": {"port_scan": {"unexpected": 1}}},
            "rules.port_scan.*unexpected",
        ),
        (
            {"rules": {"connection_burst": {"unexpected": 1}}},
            "rules.connection_burst.*unexpected",
        ),
        (
            {"rules": {"dns_anomaly": {"unexpected": 1}}},
            "rules.dns_anomaly.*unexpected",
        ),
    ],
)
def test_unknown_fields_are_rejected(
    tmp_path: Path,
    data: object,
    message: str,
) -> None:
    path = write_config(tmp_path, data)

    with pytest.raises(ConfigError, match=message):
        load_config(path)


@pytest.mark.parametrize(
    "section",
    ["port_scan", "connection_burst", "dns_anomaly"],
)
@pytest.mark.parametrize("value", [1, "true"])
def test_enabled_must_be_boolean(
    tmp_path: Path,
    section: str,
    value: object,
) -> None:
    path = write_config(
        tmp_path,
        {"rules": {section: {"enabled": value}}},
    )

    with pytest.raises(ConfigError, match=f"rules.{section}.enabled"):
        load_config(path)


@pytest.mark.parametrize(
    ("section", "field_name"),
    [
        ("port_scan", "port_threshold"),
        ("connection_burst", "connection_threshold"),
        ("dns_anomaly", "query_threshold"),
        ("dns_anomaly", "unique_domain_threshold"),
        ("dns_anomaly", "long_domain_threshold"),
    ],
)
@pytest.mark.parametrize("value", [True, "10", 0, -1, 1.5])
def test_thresholds_must_be_positive_integers(
    tmp_path: Path,
    section: str,
    field_name: str,
    value: object,
) -> None:
    path = write_config(
        tmp_path,
        {"rules": {section: {field_name: value}}},
    )

    with pytest.raises(ConfigError, match=f"rules.{section}.{field_name}"):
        load_config(path)


@pytest.mark.parametrize(
    "section",
    ["port_scan", "connection_burst", "dns_anomaly"],
)
@pytest.mark.parametrize(
    "value",
    ["60", True, 0, -1, float("inf"), float("nan")],
)
def test_time_windows_must_be_positive_finite_numbers(
    tmp_path: Path,
    section: str,
    value: object,
) -> None:
    path = write_config(
        tmp_path,
        {"rules": {section: {"time_window_seconds": value}}},
    )

    with pytest.raises(
        ConfigError,
        match=f"rules.{section}.time_window_seconds",
    ):
        load_config(path)
