"""
Unit tests for port_scanner.py
Run with: python -m pytest test_port_scanner.py -v

These tests use real sockets against 127.0.0.1 (localhost) — no external
network access or authorization concerns, since scanning your own machine
is always safe and legal.
"""

import socket
import threading
import time
import unittest

from port_scanner import parse_ports, run_scan, COMMON_PORTS


class TestParsePorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_comma_separated_ports(self):
        self.assertEqual(parse_ports("80,443,22"), [22, 80, 443])

    def test_port_range(self):
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_mixed_range_and_list(self):
        self.assertEqual(parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_duplicate_ports_deduplicated(self):
        self.assertEqual(parse_ports("80,80,443"), [80, 443])

    def test_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_invalid_range_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("100-50")


class TestRealScan(unittest.TestCase):
    """
    Spins up a real local TCP server on an ephemeral port and verifies the
    scanner correctly detects it as open, and detects a closed port as closed.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.server.bind(("127.0.0.1", 0))  # OS assigns a free port
        cls.port = cls.server.getsockname()[1]
        cls.server.listen(5)
        cls.running = True

        def accept_loop():
            while cls.running:
                cls.server.settimeout(0.5)
                try:
                    conn, _ = cls.server.accept()
                    conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break

        cls.thread = threading.Thread(target=accept_loop, daemon=True)
        cls.thread.start()
        time.sleep(0.2)  # let the server start accepting

    @classmethod
    def tearDownClass(cls):
        cls.running = False
        cls.server.close()
        cls.thread.join(timeout=2)

    def test_detects_open_local_port(self):
        result = run_scan("127.0.0.1", [self.port], thread_count=1, timeout=1.0, grab_banners=False)
        open_ports = [r["port"] for r in result["open_ports"]]
        self.assertIn(self.port, open_ports)

    def test_closed_port_not_reported_open(self):
        # Port 1 is almost never open and requires root to bind on most systems,
        # making it a reliable "closed" test port.
        result = run_scan("127.0.0.1", [1], thread_count=1, timeout=0.5, grab_banners=False)
        open_ports = [r["port"] for r in result["open_ports"]]
        self.assertNotIn(1, open_ports)

    def test_scan_returns_expected_structure(self):
        result = run_scan("127.0.0.1", [self.port], thread_count=1, timeout=1.0, grab_banners=False)
        self.assertIn("target", result)
        self.assertIn("ip", result)
        self.assertIn("ports_scanned", result)
        self.assertIn("open_ports", result)
        self.assertIn("elapsed_seconds", result)

    def test_invalid_host_raises(self):
        with self.assertRaises(ValueError):
            run_scan("this-host-should-not-exist.invalid", [80], thread_count=1, timeout=0.5, grab_banners=False)


class TestCommonPorts(unittest.TestCase):
    def test_known_services_mapped(self):
        self.assertEqual(COMMON_PORTS[22], "SSH")
        self.assertEqual(COMMON_PORTS[80], "HTTP")
        self.assertEqual(COMMON_PORTS[443], "HTTPS")


if __name__ == "__main__":
    unittest.main()
