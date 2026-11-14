from dataclasses import dataclass

@dataclass(frozen=True)
class Thresholds:
    brute_force: int = 10
    auth_window_seconds: int = 60
    auth_pre_success: int = 5
    port_scan: int = 20
    port_window_seconds: int = 60
    traffic_bytes: int = 1_000_000
    traffic_window_seconds: int = 60
    outbound_bytes: int = 5_000_000
    distributed_auth: int = 8
    dns_query_length: int = 45
    dns_unique_queries: int = 5
    dns_window_seconds: int = 300
    correlation_window_seconds: int = 1800

THRESHOLDS = Thresholds()
