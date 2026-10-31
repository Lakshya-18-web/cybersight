"""The egress proxy allows only the configured hosts and ports, refuses private and literal addresses, bounds tunnels and fails closed. Local sockets only: no internet."""
import socket
import socketserver
import threading
import unittest

from week5.egress import proxy


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(1024)
            if not data:
                return
            self.request.sendall(b"echo:" + data)


class Pure(unittest.TestCase):
    ALLOW = ("generativelanguage.googleapis.com", "api.abuseipdb.com")

    def code(self, authority, ports=(443,)):
        try:
            proxy.parse_target(authority, self.ALLOW, ports)
        except proxy.Refused as r:
            return r.code
        return "ok"

    def test_allowed_hosts_pass_and_everything_else_is_refused(self):
        self.assertEqual(self.code("generativelanguage.googleapis.com:443"), "ok")
        self.assertEqual(self.code("API.AbuseIPDB.com.:443"), "ok")
        for bad, code in (("example.com:443", "host_not_allowed"), ("evil.generativelanguage.googleapis.com:443", "host_not_allowed"), ("googleapis.com:443", "host_not_allowed"),
                          ("api.abuseipdb.com:80", "port_not_allowed"), ("api.abuseipdb.com:8443", "port_not_allowed"), ("1.2.3.4:443", "ip_literal"), ("127.0.0.1:443", "ip_literal"),
                          ("api.abuseipdb.com", "bad_target"), ("api.abuseipdb.com:x", "bad_target"), ("user@api.abuseipdb.com:443", "bad_target"), ("api.abuseipdb.com/x:443", "bad_target"),
                          ("[::1]:443", "bad_target"), ("", "bad_target"), ("localhost:443", "bad_target"), ("api.abuseipdb.com :443", "bad_target"), ("a" * 400 + ":443", "bad_target")):
            self.assertEqual(self.code(bad), code, bad)

    def test_an_empty_allow_list_allows_nothing(self):
        with self.assertRaises(proxy.Refused):
            proxy.parse_target("api.abuseipdb.com:443", (), (443,))

    def test_allow_list_parsing_rejects_wildcards_and_addresses(self):
        self.assertEqual(proxy.parse_allow(" A.example.com, b.example.com ,,a.example.com"), ("a.example.com", "b.example.com"))
        for bad in ("*.example.com", "1.2.3.4", "http://a.example.com", "a.example.com/x", "localhost"):
            with self.assertRaises(ValueError):
                proxy.parse_allow(bad)
        self.assertEqual(proxy.parse_allow(""), ())

    def test_public_address_check(self):
        for a in ("8.8.8.8", "142.250.80.42", "2607:f8b0:4004:c07::5f"):
            self.assertTrue(proxy.is_public(a), a)
        for a in ("127.0.0.1", "10.0.0.5", "172.16.1.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "not-an-ip"):
            self.assertFalse(proxy.is_public(a), a)

    def test_environment_defaults(self):
        c = proxy.Config.from_env({})
        self.assertEqual((c.allow, c.ports), (proxy.DEFAULT_ALLOW, (443,)))
        c = proxy.Config.from_env({"WEEK5_EGRESS_ALLOW": "", "WEEK5_EGRESS_PORTS": "443,8443"})
        self.assertEqual((c.allow, c.ports), ((), (443, 8443)))
        with self.assertRaises(ValueError):
            proxy.Config.from_env({"WEEK5_EGRESS_PORTS": "0"})


class Live(unittest.TestCase):
    def setUp(self):
        self.echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        self.echo.daemon_threads = True
        threading.Thread(target=self.echo.serve_forever, daemon=True).start()
        self.logs = []
        self.resolved = {"allowed.example.com": ["127.0.0.1"], "rebind.example.com": ["10.1.2.3"], "mixed.example.com": ["8.8.8.8", "10.0.0.1"]}
        self.port = self.echo.server_address[1]
        self.start(allow=("allowed.example.com", "rebind.example.com", "mixed.example.com"), ports=(self.port,), allow_private=True)
        self.addCleanup(self.echo.shutdown)
        self.addCleanup(self.echo.server_close)

    def start(self, **kw):
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
        cfg = proxy.Config(resolver=lambda h, p: self.resolved[h], log=self.logs.append, **kw)
        self.cfg = cfg
        self.server = proxy.make_server(cfg, "127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close()))

    def exchange(self, payload, read=True):
        s = socket.create_connection(("127.0.0.1", self.server.server_address[1]), timeout=5)
        self.addCleanup(s.close)
        s.sendall(payload)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            pass
        return s, data

    def connect(self, authority):
        return self.exchange(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (authority, authority)).encode())

    def test_an_allowed_tunnel_carries_bytes_both_ways_and_logs_only_the_host(self):
        s, head = self.connect("allowed.example.com:%d" % self.port)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"), head)
        s.sendall(b"hello")
        self.assertEqual(s.recv(100), b"echo:hello")
        s.close()
        for _ in range(50):
            if any("egress allow" in l for l in self.logs):
                break
            threading.Event().wait(0.05)
        line = [l for l in self.logs if "egress allow" in l][0]
        self.assertIn("host=allowed.example.com", line)
        self.assertNotIn("hello", line)
        self.assertEqual(self.cfg.counts["allowed"], 1)

    def test_a_host_not_on_the_list_is_refused_and_never_resolved(self):
        s, head = self.connect("not-listed.example.com:%d" % self.port)
        self.assertTrue(head.startswith(b"HTTP/1.1 403"), head)
        self.assertEqual(self.cfg.counts["refused"], 1)

    def test_plain_http_forwarding_and_other_methods_are_refused(self):
        for req in (b"GET http://allowed.example.com/ HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n", b"POST / HTTP/1.1\r\n\r\n", b"GET /healthz2 HTTP/1.1\r\n\r\n"):
            s, head = self.exchange(req)
            self.assertTrue(head.startswith(b"HTTP/1.1 405"), (req, head))

    def test_health_check_answers_without_listing_the_allow_list(self):
        s, head = self.exchange(b"GET /healthz HTTP/1.1\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 200"))
        self.assertNotIn(b"example.com", head)

    def test_private_resolution_is_refused_when_not_in_test_mode(self):
        self.start(allow=("allowed.example.com", "rebind.example.com", "mixed.example.com"), ports=(self.port,), allow_private=False)
        for host in ("allowed.example.com", "rebind.example.com", "mixed.example.com"):
            s, head = self.connect("%s:%d" % (host, self.port))
            self.assertTrue(head.startswith(b"HTTP/1.1 403"), (host, head))
        self.assertTrue(any("non_public_address" in l for l in self.logs))

    def test_a_resolver_failure_is_a_clean_502(self):
        def boom(h, p):
            raise OSError("dns down")
        self.cfg.resolver = boom
        s, head = self.connect("allowed.example.com:%d" % self.port)
        self.assertTrue(head.startswith(b"HTTP/1.1 502"), head)

    def test_oversized_headers_are_refused(self):
        s, head = self.exchange(b"CONNECT allowed.example.com:1 HTTP/1.1\r\nX: " + b"a" * 9000)
        self.assertTrue(head.startswith(b"HTTP/1.1 431"), head)

    def test_tunnel_count_is_bounded(self):
        self.start(allow=("allowed.example.com",), ports=(self.port,), allow_private=True, max_tunnels=1)
        s1, head1 = self.connect("allowed.example.com:%d" % self.port)
        self.assertTrue(head1.startswith(b"HTTP/1.1 200"))
        s2, head2 = self.connect("allowed.example.com:%d" % self.port)
        self.assertTrue(head2.startswith(b"HTTP/1.1 503"), head2)
        s1.close()

    def test_an_empty_allow_list_refuses_everything(self):
        self.start(allow=(), ports=(self.port,), allow_private=True)
        s, head = self.connect("allowed.example.com:%d" % self.port)
        self.assertTrue(head.startswith(b"HTTP/1.1 403"), head)

    def test_idle_tunnels_are_closed(self):
        self.start(allow=("allowed.example.com",), ports=(self.port,), allow_private=True, idle_timeout=0.3)
        s, head = self.connect("allowed.example.com:%d" % self.port)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"))
        s.settimeout(5)
        self.assertEqual(s.recv(10), b"")          # the proxy closed it


if __name__ == "__main__":
    unittest.main()
