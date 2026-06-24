"""
mininmap - A lightweight Python network scanner (TCP connect scan,
host discovery, and basic service detection).

Use it as a CLI tool:
    mininmap -t 192.168.1.10 -p 1-1024

Or import it as a library:
    from mininmap import scan_host, discover_hosts, parse_ports
"""

from .scanner import (
    scan_host,
    scan_port,
    discover_hosts,
    is_host_up,
    grab_banner,
    parse_ports,
    ScanResult,
    COMMON_PORTS,
)

__version__ = "1.0.0"

__all__ = [
    "scan_host",
    "scan_port",
    "discover_hosts",
    "is_host_up",
    "grab_banner",
    "parse_ports",
    "ScanResult",
    "COMMON_PORTS",
]
