# mininmap

A lightweight Python network scanner — host discovery, TCP connect scanning,
and basic service detection. Inspired by Nmap, built with the Python standard
library (no third-party dependencies).

> **Legal notice:** Only scan hosts/networks you own or have explicit written
> permission to test. Unauthorized scanning may be illegal in your jurisdiction
> (e.g. the U.S. Computer Fraud and Abuse Act).

## Install

From this directory:

```bash
pip install -e .
```

This installs the package and creates a `mininmap` command on your PATH.
The `-e` (editable) flag means changes to the source are picked up immediately
without reinstalling — handy for development.

To uninstall:

```bash
pip uninstall mininmap
```

## Usage (CLI)

Once installed, run it like any system command — no need for `python3 file.py`:

```bash
# Scan a single host, default port range (1-1024)
mininmap -t 192.168.1.10

# Scan a specific port range
mininmap -t 192.168.1.10 -p 1-1024

# Scan specific ports
mininmap -t 192.168.1.10 -p 22,80,443,8080

# Discover live hosts on a subnet, then scan each
mininmap -t 192.168.1.0/24 --discover -p 1-1000

# Only common/well-known ports, skip banner grabbing (faster)
mininmap -t 192.168.1.10 --top --no-service

# More threads, save report to file
mininmap -t 192.168.1.10 -p 1-65535 --threads 300 -o results.txt

# Full option list
mininmap --help
```

## Usage (as a Python library)

Since it's a proper package, you can also `import` it in your own scripts:

```python
from mininmap import scan_host, discover_hosts, parse_ports

# Discover live hosts on a subnet
live_hosts = discover_hosts("192.168.1.0/24")

# Scan one host
ports = parse_ports("1-1024")
result = scan_host("192.168.1.10", ports)

print(f"{result.ip} is {'up' if result.is_up else 'down'}")
for port, info in result.open_ports.items():
    print(f"  {port}/tcp open - {info['service']} - {info['banner']}")
```

## Project layout

```
mininmap_pkg/
├── pyproject.toml        # packaging config + console_scripts entry point
├── README.md
└── mininmap/
    ├── __init__.py        # public API exports
    └── scanner.py         # all scanning logic + CLI argparse code
```

## Optional: build a standalone single-file binary

If you want to hand this to someone without Python installed, package it
with PyInstaller instead:

```bash
pip install pyinstaller
pyinstaller --onefile --name mininmap mininmap/scanner.py
```

This produces a standalone executable in `dist/mininmap` (or `dist/mininmap.exe`
on Windows) that runs without needing Python or pip on the target machine.
