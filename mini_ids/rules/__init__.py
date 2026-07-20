"""Detection rule interfaces for Mini IDS."""

from mini_ids.rules.base import DetectionRule
from mini_ids.rules.connection_burst import ConnectionBurstRule
from mini_ids.rules.dns_anomaly import DNSAnomalyRule
from mini_ids.rules.port_scan import PortScanRule

__all__ = [
    "ConnectionBurstRule",
    "DNSAnomalyRule",
    "DetectionRule",
    "PortScanRule",
]
