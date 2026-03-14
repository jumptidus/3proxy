import os
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "3proxy"


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(f"expected {size} bytes, got EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_dual_port():
    while True:
        port = free_port(socket.SOCK_STREAM)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        return port


def local_ipv4():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 53))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def wait_for_port(port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not become ready")


def encode_socks5_udp(host, port, payload):
    return b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port) + payload


def decode_socks5_udp(packet):
    if len(packet) < 10 or packet[:3] != b"\x00\x00\x00" or packet[3] != 1:
        raise ValueError("unexpected SOCKS5 UDP packet")
    host = socket.inet_ntoa(packet[4:8])
    port = struct.unpack("!H", packet[8:10])[0]
    return host, port, packet[10:]


def build_dns_query(name, request_id):
    header = struct.pack("!HHHHHH", request_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def build_dns_answer(query, ip_text):
    request_id = query[:2]
    question = query[12:]
    header = request_id + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(ip_text)
    return header + question + answer


class TcpEchoServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)

    def _serve(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _handle(conn):
        with conn:
            while True:
                data = conn.recv(65535)
                if not data:
                    return
                conn.sendall(data)


class UdpEchoServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)

    def _serve(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            self.sock.sendto(data, addr)


class FakeDnsServer:
    def __init__(self, ip_text):
        self.ip_text = ip_text
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.sock.close()
        self.thread.join(timeout=2)

    def _serve(self):
        while not self.stop_event.is_set():
            try:
                query, addr = self.sock.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            self.sock.sendto(build_dns_answer(query, self.ip_text), addr)


class UpstreamParentServer:
    def __init__(self, bind_host, port, echo_port, dns_port):
        self.bind_host = bind_host
        self.port = port
        self.echo_port = echo_port
        self.dns_port = dns_port
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_sock.bind((self.bind_host, self.port))
        self.tcp_sock.listen()
        self.tcp_sock.settimeout(0.2)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind((self.bind_host, self.port))
        self.udp_sock.settimeout(0.2)
        self.stop_event = threading.Event()
        self.tcp_thread = threading.Thread(target=self._serve_tcp, daemon=True)
        self.udp_thread = threading.Thread(target=self._serve_udp, daemon=True)
        self.udp_messages = 0
        self.tcp_commands = []
        self.last_udp_source = None
        self.last_tcp_peer = None
        self.inject_mismatch_once = False
        self.mismatch_payload = b""
        self.mismatch_injections = 0
        self._lock = threading.Lock()

    def start(self):
        self.tcp_thread.start()
        self.udp_thread.start()

    def stop(self):
        self.stop_event.set()
        self.tcp_sock.close()
        self.udp_sock.close()
        self.tcp_thread.join(timeout=2)
        self.udp_thread.join(timeout=2)

    def configure_mismatch(self, payload):
        with self._lock:
            self.inject_mismatch_once = True
            self.mismatch_payload = payload

    def _serve_tcp(self):
        while not self.stop_event.is_set():
            try:
                conn, addr = self.tcp_sock.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle_tcp, args=(conn, addr), daemon=True).start()

    def _handle_tcp(self, conn, addr):
        with conn:
            self.last_tcp_peer = addr
            version, nmethods = recv_exact(conn, 2)
            methods = recv_exact(conn, nmethods)
            if version != 5 or 0 not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x00")
            version, command, _, atyp = recv_exact(conn, 4)
            if version != 5 or atyp != 1:
                conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            host = socket.inet_ntoa(recv_exact(conn, 4))
            port = struct.unpack("!H", recv_exact(conn, 2))[0]
            self.tcp_commands.append(command)
            if command != 1:
                conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            upstream = socket.create_connection((host, port), timeout=2)
            with upstream:
                bind_host, bind_port = upstream.getsockname()
                conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(bind_host) + struct.pack("!H", bind_port))
                self._relay(conn, upstream)

    def _serve_udp(self):
        while not self.stop_event.is_set():
            try:
                packet, addr = self.udp_sock.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            self.udp_messages += 1
            self.last_udp_source = addr
            host, port, payload = decode_socks5_udp(packet)
            with self._lock:
                inject_mismatch = self.inject_mismatch_once
                mismatch_payload = self.mismatch_payload
                self.inject_mismatch_once = False
            if inject_mismatch:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fake:
                    fake.sendto(encode_socks5_udp(host, port, mismatch_payload), addr)
                self.mismatch_injections += 1
                time.sleep(0.1)
            response = self._dispatch_udp(host, port, payload)
            self.udp_sock.sendto(encode_socks5_udp(host, port, response), addr)

    def _dispatch_udp(self, host, port, payload):
        target = (host, port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.sendto(payload, target)
            response, _ = sock.recvfrom(65535)
            return response

    @staticmethod
    def _relay(left, right):
        sockets = [left, right]
        for sock in sockets:
            sock.setblocking(False)
        while True:
            readable, _, _ = select.select(sockets, [], [], 2)
            if not readable:
                continue
            for source in readable:
                try:
                    data = source.recv(65535)
                except BlockingIOError:
                    continue
                if not data:
                    return
                target = right if source is left else left
                target.sendall(data)


class Socks5Client:
    @staticmethod
    def _negotiate(sock):
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise AssertionError("SOCKS5 method negotiation failed")

    @classmethod
    def connect(cls, host, port, target_host, target_port):
        sock = socket.create_connection((host, port), timeout=2)
        cls._negotiate(sock)
        request = b"\x05\x01\x00\x01" + socket.inet_aton(target_host) + struct.pack("!H", target_port)
        sock.sendall(request)
        reply = recv_exact(sock, 10)
        if reply[:2] != b"\x05\x00":
            raise AssertionError(f"SOCKS5 CONNECT failed: {reply!r}")
        return sock

    @classmethod
    def udp_associate(cls, host, port):
        tcp = socket.create_connection((host, port), timeout=2)
        cls._negotiate(tcp)
        request = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
        tcp.sendall(request)
        reply = recv_exact(tcp, 10)
        if reply[:2] != b"\x05\x00":
            raise AssertionError(f"SOCKS5 UDP ASSOCIATE failed: {reply!r}")
        relay_host = socket.inet_ntoa(reply[4:8])
        relay_port = struct.unpack("!H", reply[8:10])[0]
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(1)
        return tcp, udp, (relay_host, relay_port)


class ParentUdpIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.log_path = Path(cls.tempdir.name) / "3proxy.log"
        cls.echo = TcpEchoServer()
        cls.echo.start()
        cls.udp_echo = UdpEchoServer()
        cls.udp_echo.start()
        cls.dns = FakeDnsServer("203.0.113.7")
        cls.dns.start()
        cls.parent_host = local_ipv4()
        cls.parent_port = free_dual_port()
        cls.parent = UpstreamParentServer("0.0.0.0", cls.parent_port, cls.udp_echo.port, cls.dns.port)
        cls.parent.start()
        cls.proxy_port = free_port(socket.SOCK_STREAM)
        cls.config_path = Path(cls.tempdir.name) / "3proxy.cfg"
        cls.config_path.write_text(
            "\n".join(
                [
                    f"log {cls.log_path}",
                    "auth iponly",
                    "allow *",
                    f"parent 1000 extip {cls.parent_host} 0",
                    f"parent 1000 socks5 {cls.parent_host} {cls.parent_port}",
                    f"socks -p{cls.proxy_port} -i127.0.0.1 -N127.0.0.1",
                    "",
                ]
            ),
            encoding="ascii",
        )
        cls.proxy_output = Path(cls.tempdir.name) / "3proxy.stdout"
        cls.proxy_stream = cls.proxy_output.open("w+", encoding="utf-8")
        cls.proxy = subprocess.Popen(
            [str(BIN), str(cls.config_path)],
            cwd=ROOT,
            stdout=cls.proxy_stream,
            stderr=subprocess.STDOUT,
        )
        wait_for_port(cls.proxy_port)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "proxy"):
            cls.proxy.terminate()
            try:
                cls.proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proxy.kill()
                cls.proxy.wait(timeout=5)
        if hasattr(cls, "proxy_stream"):
            cls.proxy_stream.close()
        if hasattr(cls, "parent"):
            cls.parent.stop()
        if hasattr(cls, "dns"):
            cls.dns.stop()
        if hasattr(cls, "udp_echo"):
            cls.udp_echo.stop()
        if hasattr(cls, "echo"):
            cls.echo.stop()
        if hasattr(cls, "tempdir"):
            cls.tempdir.cleanup()

    def tearDown(self):
        if self.proxy.poll() is not None:
            self.proxy_stream.flush()
            output = self.proxy_output.read_text(encoding="utf-8", errors="replace")
            self.fail(f"3proxy exited unexpectedly with code {self.proxy.returncode}:\n{output}")

    def test_01_udp_echo_parent_forwarding_and_mismatch_drop(self):
        self.parent.configure_mismatch(b"forged-payload")
        tcp, udp, relay = Socks5Client.udp_associate("127.0.0.1", self.proxy_port)
        try:
            payload = b"echo-through-parent"
            udp.sendto(encode_socks5_udp("127.0.0.1", self.udp_echo.port, payload), relay)
            packet, _ = udp.recvfrom(65535)
            host, port, echoed = decode_socks5_udp(packet)
            self.assertEqual((host, port), ("127.0.0.1", self.udp_echo.port))
            self.assertEqual(echoed, payload)
            self.assertEqual(self.parent.tcp_commands, [])
            self.assertEqual(self.parent.last_udp_source[0], self.parent_host)
            self.assertEqual(self.parent.mismatch_injections, 1)
            udp.settimeout(0.2)
            with self.assertRaises(socket.timeout):
                udp.recvfrom(65535)
        finally:
            udp.close()
            tcp.close()

    def test_02_udp_dns_roundtrip(self):
        tcp, udp, relay = Socks5Client.udp_associate("127.0.0.1", self.proxy_port)
        try:
            query = build_dns_query("example.test", 0x1234)
            udp.sendto(encode_socks5_udp("127.0.0.1", self.dns.port, query), relay)
            packet, _ = udp.recvfrom(65535)
            host, port, response = decode_socks5_udp(packet)
            self.assertEqual((host, port), ("127.0.0.1", self.dns.port))
            self.assertEqual(response[:2], query[:2])
            self.assertEqual(response[-4:], socket.inet_aton("203.0.113.7"))
        finally:
            udp.close()
            tcp.close()

    def test_03_udp_association_stops_after_control_close(self):
        tcp, udp, relay = Socks5Client.udp_associate("127.0.0.1", self.proxy_port)
        try:
            udp.sendto(encode_socks5_udp("127.0.0.1", self.udp_echo.port, b"first-pass"), relay)
            packet, _ = udp.recvfrom(65535)
            self.assertEqual(decode_socks5_udp(packet)[2], b"first-pass")
            tcp.close()
            time.sleep(0.3)
            udp.settimeout(0.4)
            udp.sendto(encode_socks5_udp("127.0.0.1", self.udp_echo.port, b"after-close"), relay)
            with self.assertRaises(socket.timeout):
                udp.recvfrom(65535)
        finally:
            udp.close()

    def test_04_tcp_connect_still_uses_parent_socks5(self):
        sock = Socks5Client.connect("127.0.0.1", self.proxy_port, "127.0.0.1", self.echo.port)
        try:
            sock.sendall(b"connect-regression-check")
            self.assertEqual(recv_exact(sock, len(b"connect-regression-check")), b"connect-regression-check")
        finally:
            sock.close()
        self.assertIn(1, self.parent.tcp_commands)
        self.assertEqual(self.parent.last_tcp_peer[0], self.parent_host)

    def test_05_mismatch_drop_is_logged(self):
        deadline = time.time() + 2
        while time.time() < deadline:
            if self.log_path.exists() and "source mismatch" in self.log_path.read_text(encoding="utf-8", errors="replace"):
                return
            time.sleep(0.1)
        log_text = self.log_path.read_text(encoding="utf-8", errors="replace")
        self.fail(f"expected mismatch log entry, got:\n{log_text}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
