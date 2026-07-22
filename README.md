# Port Scanner

A real multithreaded TCP port scanner built in pure Python — no external
scanning libraries, no simulated results. It performs actual TCP connect
scans against real sockets.

> ⚠️ **Only scan hosts you own or have explicit written authorization to
> scan.** Unauthorized port scanning may be illegal depending on your
> jurisdiction and the target's policies. This tool is built and tested
> against `127.0.0.1` (your own machine) by default.

## What it actually does

- Performs a real **TCP connect scan** (`connect_ex`) against each port —
  the same fundamental technique tools like Nmap use for TCP connect scans
- Uses a **thread pool** (configurable, default 100 threads) to scan large
  port ranges quickly instead of one port at a time
- Maps common ports to their typical services (SSH, HTTP, HTTPS, MySQL,
  RDP, etc.)
- Optionally attempts **banner grabbing** — reading the first bytes a
  service sends back, which can reveal software/version info
- Outputs a formatted report or raw JSON

## Installation

```bash
git clone https://github.com/Almabkhan/port-scanner
cd port-scanner
```

No external dependencies are required to run the scanner itself (it only
uses Python's standard library). `pytest` is only needed to run the tests.

## Usage

**Scan the default range (ports 1–1024) on your own machine:**

```bash
python port_scanner.py 127.0.0.1
```

**Scan a specific range:**

```bash
python port_scanner.py 127.0.0.1 --ports 1-65535 --threads 200
```

**Scan specific ports:**

```bash
python port_scanner.py 127.0.0.1 --ports 22,80,443,3306
```

**Grab service banners on open ports:**

```bash
python port_scanner.py 127.0.0.1 --ports 1-1024 --banners
```

**Get raw JSON output** (useful for piping into other tools):

```bash
python port_scanner.py 127.0.0.1 --ports 1-1024 --json
```

## Example output

```text
============================================================
  PORT SCAN REPORT
============================================================
  Target       : 127.0.0.1 (127.0.0.1)
  Ports scanned: 1024
  Time taken   : 0.08s
  Open ports   : 0
------------------------------------------------------------
  No open ports found in the scanned range.
============================================================
```

## How it works (worth understanding, not just running)

1. **`parse_ports`** turns a spec like `"22,80,1000-1010"` into a clean,
   deduplicated, sorted list of ports.
2. Every port to scan is placed in a thread-safe `queue.Queue`.
3. A pool of worker threads pulls ports from the queue and attempts a TCP
   connection with `socket.connect_ex()`. A return value of `0` means the
   port accepted the connection (open); anything else means closed,
   filtered, or unreachable.
4. If `--banners` is set, the scanner keeps the connection open briefly to
   read any data the service sends immediately after connecting (many
   services like SSH and FTP announce themselves this way).
5. Results are collected in a shared list (protected by a lock) and sorted
   by port number before being printed.

## Running the tests

```bash
pip install pytest
python -m pytest test_port_scanner.py -v
```

12 tests cover port-spec parsing and a **real scan against a real local TCP
server** spun up during the test run — the tests verify the scanner
correctly identifies an actually-open port and does not falsely report a
closed one.

## Project structure

```text
port-scanner/
├── port_scanner.py       # main application
├── test_port_scanner.py  # unit tests (includes a real local scan test)
├── requirements.txt
└── README.md
```

## Limitations / possible extensions

- Only performs TCP connect scans (no SYN/stealth scanning, which requires
  raw sockets and elevated privileges)
- No UDP scanning
- Service detection is port-number-based, not fingerprint-based — a
  service running on a non-standard port won't be identified by name
- Could be extended with OS fingerprinting, a `-v` verbose mode, or CSV
  export
