#!/usr/bin/env python3
"""
Mini Nmap - A Lightweight Network Scanner
============================================
A simplified network scanning tool built with raw Python sockets that
mimics core Nmap functionality: host discovery, TCP connect scanning,
service/banner detection, and multithreaded scanning for speed.

LEGAL / ETHICAL NOTICE:
Only scan hosts and networks you own or have explicit written permission
to test. Unauthorized scanning may violate laws such as the U.S. CFAA or
equivalent legislation in your country.

Author: You :)
"""

import socket
import sys
import argparse
import threading
import queue
import time
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------------
# Well-known ports & simple service map (mirrors nmap-services for common ones)
# ----------------------------------------------------------------------------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}

TOP_1000_FALLBACK_RANGE = range(1, 1025)  # used when --top-ports requested w/o nmap db

# Probes sent to try to coax a banner out of a service that doesn't talk first
PROTOCOL_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"",  # TLS - we won't speak plaintext to it
    25: b"EHLO mini-nmap\r\n",
    21: b"",
    22: b"",
}


class ScanResult:
    """Holds the result for a single host."""
    def __init__(self, ip, hostname=None):
        self.ip = ip
        self.hostname = hostname
        self.is_up = False
        self.open_ports = {}   # port -> {"service": str, "banner": str}
        self.closed_count = 0
        self.filtered_count = 0
        self.scan_time = 0.0


# ----------------------------------------------------------------------------
# Host Discovery
# ----------------------------------------------------------------------------
def is_host_up(ip, timeout=1.0):
    """
    Lightweight 'liveness' check without raw ICMP sockets (which need root).
    Strategy: try a TCP connect on a small set of commonly-open ports.
    If any connect succeeds OR is actively refused (RST), the host is up.
    A connect *timeout* on every probe is treated as host-down/filtered.
    """
    probe_ports = [80, 443, 22, 445, 139, 21]
    for port in probe_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                # 0 = open, 111/61 (ECONNREFUSED) = host up but port closed
                if result == 0 or result in (61, 111):
                    return True
        except (socket.timeout, OSError):
            continue
    return False


def discover_hosts(network, timeout=1.0, max_workers=50, verbose=False):
    """
    Sweep a CIDR range (e.g. 192.168.1.0/24) and return the list of
    IPs that respond. Runs concurrently for speed.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network range: {e}")
        sys.exit(1)

    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        hosts = [str(net.network_address)]

    live_hosts = []
    print(f"[*] Starting host discovery on {network} ({len(hosts)} addresses)...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(is_host_up, ip, timeout): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    live_hosts.append(ip)
                    print(f"    [+] Host up: {ip}")
                elif verbose:
                    print(f"    [-] No response: {ip}")
            except Exception as e:
                if verbose:
                    print(f"    [!] Error probing {ip}: {e}")

    print(f"[*] Discovery complete. {len(live_hosts)} host(s) up.\n")
    return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))


# ----------------------------------------------------------------------------
# TCP Connect Scan
# ----------------------------------------------------------------------------
def grab_banner(ip, port, timeout=1.5):
    """
    Attempt basic service detection by sending a protocol-appropriate probe
    and reading whatever the service sends back (or sends first, like SSH/FTP).
    """
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Many services (SSH, FTP, SMTP) greet us first - try reading immediately
            try:
                s.settimeout(0.8)
                data = s.recv(256)
                if data:
                    banner = data.decode(errors="ignore").strip()
            except socket.timeout:
                pass

            # If nothing came back, send a protocol probe and try again
            if not banner and port in PROTOCOL_PROBES and PROTOCOL_PROBES[port]:
                try:
                    s.settimeout(timeout)
                    s.sendall(PROTOCOL_PROBES[port])
                    data = s.recv(512)
                    if data:
                        banner = data.decode(errors="ignore").strip()
                except (socket.timeout, OSError):
                    pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    # Trim to first line for readability
    if banner:
        banner = banner.splitlines()[0][:120]
    return banner


def scan_port(ip, port, timeout=1.0, detect_service=True):
    """
    Perform a TCP connect() scan against a single port.
    Returns a tuple: (port, state, service_name, banner)
    state is one of: 'open', 'closed', 'filtered'
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = ""
            sock.close()
            if detect_service:
                banner = grab_banner(ip, port, timeout=min(timeout + 0.5, 2.5))
            return (port, "open", service, banner)
        elif result in (61, 111):  # ECONNREFUSED
            return (port, "closed", "", "")
        else:
            return (port, "filtered", "", "")
    except socket.timeout:
        return (port, "filtered", "", "")
    except OSError:
        return (port, "filtered", "", "")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def parse_ports(port_spec):
    """
    Parse an nmap-style port specification into a sorted list of ints.
    Supports: '80', '22,80,443', '1-1024', '1-100,443,8080-8090'
    """
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_host(ip, ports, timeout=1.0, max_workers=100, detect_service=True, verbose=False):
    """
    Scan all specified ports on a single host concurrently.
    Returns a populated ScanResult object.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = None

    result = ScanResult(ip, hostname)
    start = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, detect_service): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                port_num, state, service, banner = future.result()
                if state == "open":
                    result.open_ports[port_num] = {"service": service, "banner": banner}
                    result.is_up = True
                elif state == "closed":
                    result.closed_count += 1
                    result.is_up = True
                else:
                    result.filtered_count += 1
                if verbose and state == "open":
                    tag = f" [{banner}]" if banner else ""
                    print(f"    [+] {ip}:{port_num}/tcp open  ({service}){tag}")
            except Exception as e:
                if verbose:
                    print(f"    [!] Error scanning {ip}:{port}: {e}")

    result.scan_time = time.time() - start
    return result


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def print_report(results, total_time):
    print("\n" + "=" * 65)
    print(" MINI NMAP SCAN REPORT")
    print("=" * 65)
    print(f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Total scan time: {total_time:.2f}s")
    print("=" * 65)

    up_count = sum(1 for r in results if r.is_up)
    print(f"\n Hosts scanned: {len(results)}  |  Hosts up: {up_count}\n")

    for r in results:
        if not r.is_up and not r.open_ports:
            continue
        host_label = f"{r.ip}"
        if r.hostname:
            host_label += f" ({r.hostname})"
        print("-" * 65)
        print(f" Host: {host_label}")
        print(f" Status: {'UP' if r.is_up else 'DOWN'}   "
              f"Open: {len(r.open_ports)}   Closed: {r.closed_count}   "
              f"Filtered: {r.filtered_count}   Time: {r.scan_time:.2f}s")

        if r.open_ports:
            print(f"\n {'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'BANNER'}")
            for port in sorted(r.open_ports):
                info = r.open_ports[port]
                banner = info["banner"] if info["banner"] else "-"
                print(f" {str(port)+'/tcp':<10}{'open':<10}{info['service']:<15}{banner}")
        else:
            print(" No open ports found.")
        print()

    print("=" * 65)
    print(" Scan finished.")
    print("=" * 65)


def save_report(results, total_time, filepath):
    with open(filepath, "w") as f:
        f.write("MINI NMAP SCAN REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total scan time: {total_time:.2f}s\n")
        f.write("=" * 65 + "\n\n")
        for r in results:
            if not r.is_up and not r.open_ports:
                continue
            host_label = f"{r.ip}" + (f" ({r.hostname})" if r.hostname else "")
            f.write(f"Host: {host_label}\n")
            f.write(f"Status: {'UP' if r.is_up else 'DOWN'} | "
                    f"Open: {len(r.open_ports)} | Closed: {r.closed_count} | "
                    f"Filtered: {r.filtered_count} | Time: {r.scan_time:.2f}s\n")
            for port in sorted(r.open_ports):
                info = r.open_ports[port]
                f.write(f"  {port}/tcp open {info['service']} {info['banner']}\n")
            f.write("\n")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="mininmap",
        description="Mini Nmap - A lightweight Python network scanner "
                     "(host discovery + TCP connect scan + service detection)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single host, top common ports
  mininmap -t 192.168.1.10

  # Scan a specific port range
  mininmap -t 192.168.1.10 -p 1-1024

  # Scan specific ports
  mininmap -t 192.168.1.10 -p 22,80,443,8080

  # Discover live hosts on a subnet, then scan each one
  mininmap -t 192.168.1.0/24 --discover -p 1-1000

  # Faster scan with more threads, no banner grabbing
  mininmap -t 192.168.1.10 -p 1-65535 --threads 300 --no-service

  # Save results to a file
  mininmap -t 192.168.1.10 -o results.txt

LEGAL: Only scan systems you own or are authorized to test.
"""
    )
    parser.add_argument("-t", "--target", required=True,
                         help="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan: '80', '22,80,443', '1-1024' (default: 1-1024)")
    parser.add_argument("--top", action="store_true",
                         help="Scan only the common/well-known ports list instead of -p range")
    parser.add_argument("--discover", action="store_true",
                         help="Treat target as a network range and discover live hosts first")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Max concurrent threads per host scan (default: 100)")
    parser.add_argument("--no-service", action="store_true",
                         help="Disable banner grabbing / service detection (faster)")
    parser.add_argument("-o", "--output", help="Save report to a text file")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Verbose output (show progress as ports/hosts are found)")
    return parser


def resolve_target(target):
    """Resolve a hostname to an IP if needed; pass through IPs/CIDRs untouched."""
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve target: {target}")
        sys.exit(1)


def main():
    """Entry point used both by `python3 -m mininmap.scanner` and by the
    installed `mininmap` console command (see pyproject.toml)."""
    try:
        _run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting.")
        sys.exit(1)


def _run():
    parser = build_arg_parser()
    args = parser.parse_args()

    print(r"""
   __  ____       _   _    __                 
  /  |/  (_)__  (_) / |  / /__ _  ___  ___ ____
 / /|_/ / / _ \/ /  | |/ / _ `/ _ \/ _ `/ _ \
/_/  /_/_/_//_/_/   |___/\_,_/\___/\_,_/_//_/
        TCP Connect Scanner & Service Detector
""")

    target = resolve_target(args.target)

    # Determine port list
    if args.top:
        ports = sorted(COMMON_PORTS.keys())
    else:
        ports = parse_ports(args.ports)

    overall_start = time.time()

    # Decide whether we're scanning one host or sweeping a network
    is_network = "/" in target
    if args.discover or (is_network and "/" in target):
        hosts_to_scan = discover_hosts(target, timeout=args.timeout, verbose=args.verbose)
        if not hosts_to_scan:
            print("[!] No live hosts found. Exiting.")
            sys.exit(0)
    elif is_network:
        net = ipaddress.ip_network(target, strict=False)
        hosts_to_scan = [str(ip) for ip in net.hosts()]
    else:
        hosts_to_scan = [target]

    results = []
    for ip in hosts_to_scan:
        print(f"[*] Scanning {ip} -> {len(ports)} ports "
              f"({'service detection on' if not args.no_service else 'service detection off'})...")
        res = scan_host(
            ip, ports,
            timeout=args.timeout,
            max_workers=args.threads,
            detect_service=not args.no_service,
            verbose=args.verbose,
        )
        results.append(res)

    total_time = time.time() - overall_start
    print_report(results, total_time)

    if args.output:
        save_report(results, total_time, args.output)
        print(f"\n[*] Report saved to: {args.output}")


# Note: entry point is defined in pyproject.toml -> console_scripts,
# which calls mininmap.scanner:main directly. The __main__ guard below
# still lets you run `python3 -m mininmap.scanner` directly if you want.
if __name__ == "__main__":
    main()
