"""Typed YAML configuration for the implemented Mini IDS rules."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mini_ids.rules import ConnectionBurstRule, DetectionRule, PortScanRule


class ConfigError(ValueError):
    """Raised when a configuration file cannot be loaded or validated."""


@dataclass(frozen=True)
class PortScanConfig:
    """Normalized settings for vertical TCP port-scan detection."""

    enabled: bool = True
    port_threshold: int = 10
    time_window_seconds: float = 60.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "enabled",
            _require_boolean(self.enabled, "rules.port_scan.enabled"),
        )
        object.__setattr__(
            self,
            "port_threshold",
            _require_positive_integer(
                self.port_threshold,
                "rules.port_scan.port_threshold",
            ),
        )
        object.__setattr__(
            self,
            "time_window_seconds",
            _require_positive_number(
                self.time_window_seconds,
                "rules.port_scan.time_window_seconds",
            ),
        )


@dataclass(frozen=True)
class ConnectionBurstConfig:
    """Normalized settings for TCP connection-burst detection."""

    enabled: bool = True
    connection_threshold: int = 50
    time_window_seconds: float = 60.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "enabled",
            _require_boolean(
                self.enabled,
                "rules.connection_burst.enabled",
            ),
        )
        object.__setattr__(
            self,
            "connection_threshold",
            _require_positive_integer(
                self.connection_threshold,
                "rules.connection_burst.connection_threshold",
            ),
        )
        object.__setattr__(
            self,
            "time_window_seconds",
            _require_positive_number(
                self.time_window_seconds,
                "rules.connection_burst.time_window_seconds",
            ),
        )


@dataclass(frozen=True)
class AppConfig:
    """Normalized configuration for all currently implemented rules."""

    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    connection_burst: ConnectionBurstConfig = field(
        default_factory=ConnectionBurstConfig
    )


def _require_mapping(value: object, field_name: str) -> Mapping[object, object]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{field_name} must be a mapping")
    return value


def _reject_unknown_fields(
    values: Mapping[object, object],
    allowed_fields: set[str],
    field_name: str,
) -> None:
    unknown_fields = [key for key in values if key not in allowed_fields]
    if unknown_fields:
        unknown = sorted(unknown_fields, key=str)[0]
        raise ConfigError(f"Unknown field in {field_name}: {unknown!r}")


def _require_boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{field_name} must be a boolean")
    return value


def _require_positive_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise ConfigError(f"{field_name} must be an integer")
    if value <= 0:
        raise ConfigError(f"{field_name} must be greater than zero")
    return value


def _require_positive_number(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{field_name} must be a number")

    normalized = float(value)
    if not math.isfinite(normalized):
        raise ConfigError(f"{field_name} must be finite")
    if normalized <= 0:
        raise ConfigError(f"{field_name} must be greater than zero")
    return normalized


def _load_port_scan_config(values: object) -> PortScanConfig:
    section = _require_mapping(values, "rules.port_scan")
    _reject_unknown_fields(
        section,
        {"enabled", "port_threshold", "time_window_seconds"},
        "rules.port_scan",
    )
    defaults = PortScanConfig()
    return PortScanConfig(
        enabled=section.get("enabled", defaults.enabled),  # type: ignore[arg-type]
        port_threshold=section.get(  # type: ignore[arg-type]
            "port_threshold",
            defaults.port_threshold,
        ),
        time_window_seconds=section.get(  # type: ignore[arg-type]
            "time_window_seconds",
            defaults.time_window_seconds,
        ),
    )


def _load_connection_burst_config(values: object) -> ConnectionBurstConfig:
    section = _require_mapping(values, "rules.connection_burst")
    _reject_unknown_fields(
        section,
        {"enabled", "connection_threshold", "time_window_seconds"},
        "rules.connection_burst",
    )
    defaults = ConnectionBurstConfig()
    return ConnectionBurstConfig(
        enabled=section.get("enabled", defaults.enabled),  # type: ignore[arg-type]
        connection_threshold=section.get(  # type: ignore[arg-type]
            "connection_threshold",
            defaults.connection_threshold,
        ),
        time_window_seconds=section.get(  # type: ignore[arg-type]
            "time_window_seconds",
            defaults.time_window_seconds,
        ),
    )


def _parse_config(data: object) -> AppConfig:
    if data is None:
        return AppConfig()

    root = _require_mapping(data, "configuration root")
    _reject_unknown_fields(root, {"rules"}, "configuration root")

    if "rules" not in root:
        return AppConfig()

    rules = _require_mapping(root["rules"], "rules")
    _reject_unknown_fields(
        rules,
        {"port_scan", "connection_burst"},
        "rules",
    )
    return AppConfig(
        port_scan=(
            _load_port_scan_config(rules["port_scan"])
            if "port_scan" in rules
            else PortScanConfig()
        ),
        connection_burst=(
            _load_connection_burst_config(rules["connection_burst"])
            if "connection_burst" in rules
            else ConnectionBurstConfig()
        ),
    )


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load and validate YAML configuration or return the defaults."""

    if path is None:
        return AppConfig()

    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")
    if not config_path.is_file():
        raise ConfigError(f"Configuration path is not a file: {config_path}")

    try:
        contents = config_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError(
            f"Unable to read configuration file: {config_path}"
        ) from exc

    try:
        data = yaml.safe_load(contents)
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Unable to parse YAML configuration: {config_path}"
        ) from exc

    return _parse_config(data)


def build_rules(config: AppConfig) -> list[DetectionRule]:
    """Build enabled detection rules in deterministic processing order."""

    rules: list[DetectionRule] = []
    if config.port_scan.enabled:
        rules.append(
            PortScanRule(
                port_threshold=config.port_scan.port_threshold,
                time_window_seconds=config.port_scan.time_window_seconds,
            )
        )
    if config.connection_burst.enabled:
        rules.append(
            ConnectionBurstRule(
                connection_threshold=(
                    config.connection_burst.connection_threshold
                ),
                time_window_seconds=(
                    config.connection_burst.time_window_seconds
                ),
            )
        )
    return rules
