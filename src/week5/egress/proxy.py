"""Allow-list egress proxy: the only way out of the model/enrichment network.

What it does
  * Speaks HTTP CONNECT only (HTTPS tunnels). Plain HTTP proxying (absolute-URI requests) is refused.
  * Allows a tunnel only when the requested host is on the allow-list (exact host names; no wildcards) AND the port is on the port list (443 by default).
  * Resolves the host itself and refuses an answer that points at a private, loopback, link-local, multicast or reserved address (blocks DNS-rebinding style tricks and internal targets).
    It then connects to the address it checked, not to a second lookup.
  * Refuses IP-address literals, userinfo, and anything that is not host:port.
  * Never reads inside the tunnel (TLS stays end to end), so it cannot log or alter secrets; it logs the host, the verdict and byte counts only.
  * Bounds everything: concurrent tunnels, connect time, idle time, total tunnel time and header size.
  * Fails closed: an empty allow-list allows nothing; any error closes the connection.
  * GET /healthz answers 200 "ok" (no allow-list detail) so a container health check works.

Configuration (environment, all optional except the list itself having at least one entry to be useful)
  WEEK5_EGRESS_ALLOW        comma-separated host names, e.g. generativelanguage.googleapis.com,api.abuseipdb.com
  WEEK5_EGRESS_PORTS        comma-separated ports (default 443)
  WEEK5_EGRESS_LISTEN       host:port to listen on (default 0.0.0.0:3128)
  WEEK5_EGRESS_MAX_TUNNELS  concurrent tunnels (default 32)

Run:  python -m week5.egress.proxy
"""
import ipaddress
import os
import re
import select
import socket
import socketserver
import sys
import threading
import time

DEFAULT_ALLOW = ("generativelanguage.googleapis.com", "api.abuseipdb.com")
DEFAULT_PORTS = (443,)
MAX_HEADER_BYTES = 8192
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 60.0
MAX_TUNNEL_SECONDS = 300.0
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class Refused(Exception):
    def __init__(self, status, reason, code):
        super().__init__(code)
        self.status, self.reason, self.code = status, reason, code


def parse_allow(text):
    hosts = []
    for part in (text or "").split(","):
        h = part.strip().lower().rstrip(".")
        if not h:
            continue
        if not HOST_RE.match(h):
            raise ValueError("not a plain host name in WEEK5_EGRESS_ALLOW: " + repr(h))
        hosts.append(h)
    return tuple(dict.fromkeys(hosts))


def parse_ports(text):
    if not text or not text.strip():
        return DEFAULT_PORTS
    ports = []
    for part in text.split(","):
        p = int(part.strip())
        if not 1 <= p <= 65535:
            raise ValueError("port out of range")
        ports.append(p)
    return tuple(ports)


def is_public(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified or not ip.is_global)


def parse_target(authority, allow, ports):
    """'host:port' -> (host, port) or Refused. Pure, so it is tested without sockets."""
    if not authority or len(authority) > 300 or "@" in authority or "/" in authority or " " in authority or "[" in authority:
        raise Refused(400, "Bad Request", "bad_target")
    host, sep, port_text = authority.rpartition(":")
    if not sep or not port_text.isdigit():
        raise Refused(400, "Bad Request", "bad_target")
    host = host.lower().rstrip(".")
    port = int(port_text)
    try:
        ipaddress.ip_address(host)
        raise Refused(403, "Forbidden", "ip_literal")
    except ValueError:
        pass
    if not HOST_RE.match(host):
        raise Refused(400, "Bad Request", "bad_target")
    if host not in allow:
        raise Refused(403, "Forbidden", "host_not_allowed")
    if port not in ports:
        raise Refused(403, "Forbidden", "port_not_allowed")
    return host, port


class Config:
    def __init__(self, allow=(), ports=DEFAULT_PORTS, max_tunnels=32, resolver=None, allow_private=False, connect_timeout=CONNECT_TIMEOUT, idle_timeout=IDLE_TIMEOUT,
                 max_tunnel_seconds=MAX_TUNNEL_SECONDS, log=None):
        self.allow, self.ports, self.max_tunnels = tuple(allow), tuple(ports), int(max_tunnels)
        self.resolver = resolver or self.system_resolver
        self.allow_private = allow_private          # tests only: lets the tunnel reach 127.0.0.1
        self.connect_timeout, self.idle_timeout, self.max_tunnel_seconds = connect_timeout, idle_timeout, max_tunnel_seconds
        self.log = log or (lambda line: print(line, file=sys.stderr, flush=True))
        self.slots = threading.BoundedSemaphore(self.max_tunnels)
        self.counts = {"allowed": 0, "refused": 0, "errors": 0}
        self.lock = threading.Lock()

    @staticmethod
    def system_resolver(host, port):
        return sorted({info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})

    def count(self, key):
        with self.lock:
            self.counts[key] += 1

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        raw = env.get("WEEK5_EGRESS_ALLOW")
        return cls(allow=parse_allow(raw) if raw is not None else DEFAULT_ALLOW, ports=parse_ports(env.get("WEEK5_EGRESS_PORTS")), max_tunnels=int(env.get("WEEK5_EGRESS_MAX_TUNNELS") or 32))


class Handler(socketserver.BaseRequestHandler):
    config = None

    def reply(self, status, reason, extra=""):
        body = reason + "\n"
        head = "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n" % (status, reason, len(body), extra)
        try:
            self.request.sendall((head + body).encode("ascii"))
        except OSError:
            pass

    def read_head(self):
        self.request.settimeout(self.config.connect_timeout)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(1024)
            if not chunk:
                raise Refused(400, "Bad Request", "incomplete")
            data += chunk
            if len(data) > MAX_HEADER_BYTES:
                raise Refused(431, "Request Header Fields Too Large", "header_too_large")
        return data.split(b"\r\n\r\n", 1)[0].decode("latin-1")

    def handle(self):
        cfg = self.config
        host = "-"
        try:
            head = self.read_head()
            first = head.split("\r\n", 1)[0].split(" ")
            if len(first) == 3 and first[0] == "GET" and first[1] == "/healthz":
                return self.reply(200, "ok")
            if len(first) != 3 or first[0] != "CONNECT":
                raise Refused(405, "Method Not Allowed", "not_connect")
            host, port = parse_target(first[1], cfg.allow, cfg.ports)
            if not cfg.slots.acquire(blocking=False):
                raise Refused(503, "Service Unavailable", "too_many_tunnels")
            try:
                upstream = self.open_upstream(host, port)
                try:
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    sent, received = self.pump(upstream)
                finally:
                    upstream.close()
            finally:
                cfg.slots.release()
            cfg.count("allowed")
            cfg.log("egress allow host=%s port=%d up=%d down=%d" % (host, port, sent, received))
        except Refused as r:
            cfg.count("refused")
            cfg.log("egress refuse host=%s code=%s" % (host if host != "-" else "?", r.code))
            self.reply(r.status, r.reason)
        except Exception as error:          # any failure closes the connection; only the type is logged
            cfg.count("errors")
            cfg.log("egress error host=%s type=%s" % (host, type(error).__name__))
            self.reply(502, "Bad Gateway")

    def open_upstream(self, host, port):
        cfg = self.config
        try:
            addresses = cfg.resolver(host, port)
        except OSError:
            raise Refused(502, "Bad Gateway", "resolve_failed")
        if not addresses:
            raise Refused(502, "Bad Gateway", "resolve_failed")
        if not cfg.allow_private and not all(is_public(a) for a in addresses):
            raise Refused(403, "Forbidden", "non_public_address")          # one bad answer refuses the whole name
        last = None
        for address in addresses:
            try:
                return socket.create_connection((address, port), timeout=cfg.connect_timeout)
            except OSError as error:
                last = error
        raise Refused(502, "Bad Gateway", "connect_failed:" + type(last).__name__)

    def pump(self, upstream):
        cfg = self.config
        sockets = [self.request, upstream]
        sent = received = 0
        start = last = time.monotonic()
        for s in sockets:
            s.setblocking(False)
        while True:
            now = time.monotonic()
            if now - start > cfg.max_tunnel_seconds or now - last > cfg.idle_timeout:
                break
            ready, _, broken = select.select(sockets, [], sockets, 1.0)
            if broken:
                break
            for s in ready:
                other = upstream if s is self.request else self.request
                try:
                    data = s.recv(16384)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return sent, received
                if not data:
                    return sent, received
                last = time.monotonic()
                try:
                    other.setblocking(True)
                    other.settimeout(cfg.idle_timeout)
                    other.sendall(data)
                    other.setblocking(False)
                except OSError:
                    return sent, received
                if s is self.request:
                    sent += len(data)
                else:
                    received += len(data)
        return sent, received


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


def make_server(config, host="0.0.0.0", port=3128):
    handler = type("BoundHandler", (Handler,), {"config": config})
    return Server((host, port), handler)


def main(argv=None):
    cfg = Config.from_env()
    listen = os.environ.get("WEEK5_EGRESS_LISTEN", "0.0.0.0:3128")
    host, _, port = listen.rpartition(":")
    server = make_server(cfg, host or "0.0.0.0", int(port))
    cfg.log("egress proxy listening on %s; allowed hosts: %s; ports: %s" % (listen, ", ".join(cfg.allow) or "(none: everything is refused)", ",".join(map(str, cfg.ports))))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
