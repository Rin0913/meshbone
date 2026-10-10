"""The HTTPS gateway: TLS on the hubs' fourth cluster IP, each name proxied to a backend inside
the mesh. HTTP/1.1 always; a connection that upgrades (WebSockets) becomes a plain two-way pipe;
HTTP/2 when the h2 package is there (ALPN decides). Certificates come from the mesh's own CA or
from an ACME account (see store.https_material)."""

import contextlib, http.client, importlib.util, os, select, socket, ssl, tempfile, urllib.parse
from concurrent.futures import ThreadPoolExecutor

from . import settings, store

HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
IDLE = 600  # seconds a pipe or an HTTP/2 connection may stay quiet


def protocols():
    """What the gateway offers in ALPN: HTTP/2 only where the h2 package is installed."""
    return ["h2", "http/1.1"] if importlib.util.find_spec("h2") else ["http/1.1"]


def read_head(conn):
    """One HTTP/1.1 request head from a socket -> (method, target, version, headers, leftover body bytes)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        part = conn.recv(65536)
        if not part or len(buf) > 65536:
            return None
        buf += part
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError:
        return None
    headers = []
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers.append((k.strip(), v.strip()))
    return method, target, version, headers, rest


def header(headers, name, default=""):
    return next((v for k, v in headers if k.lower() == name), default)


def forwarded(headers, u, host, peer, keep=()):
    """The request headers for the backend: hop-by-hop ones dropped (except those in `keep`),
    the backend's Host, and X-Forwarded-* saying where it really came from."""
    out = [(k, v) for k, v in headers if (k.lower() not in HOP or k.lower() in keep) and k.lower() != "host"]
    return out + [
        ("Host", u.netloc),
        ("X-Forwarded-For", peer),
        ("X-Forwarded-Proto", "https"),
        ("X-Forwarded-Host", host),
    ]


def backend_path(u, target):
    return (u.path.rstrip("/") + target) if u.path.rstrip("/") else target


def fetch(u, method, target, headers, body):
    """One request to the backend -> (connection, response); the caller streams the body."""
    cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    kw = {"context": ssl._create_unverified_context()} if u.scheme == "https" else {}
    back = cls(u.hostname, u.port, timeout=60, **kw)
    back.request(method, backend_path(u, target), body=body, headers=dict(headers))
    return back, back.getresponse()


def connect_raw(u):
    """A plain socket to the backend (TLS-wrapped for an https backend), for a pipe."""
    s = socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), timeout=30)
    if u.scheme == "https":
        s = ssl._create_unverified_context().wrap_socket(s, server_hostname=u.hostname)
    return s


def pipe(a, b):
    """Copy bytes both ways until one side closes or nothing moves for IDLE seconds."""
    a.settimeout(None)
    b.settimeout(None)
    for s in (a, b):
        with contextlib.suppress(OSError):
            s.setblocking(True)
    while True:
        ready, _, _ = select.select([a, b], [], [], IDLE)
        if not ready:
            return
        for s in ready:
            try:
                data = s.recv(65536)
            except OSError:
                return
            if not data:
                return
            (b if s is a else a).sendall(data)


def reply_plain(conn, status, text):
    body = (text + "\n").encode()
    with contextlib.suppress(OSError):
        conn.sendall(
            f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )


def serve_one(conn, routes, peer=""):
    """Answer what comes over an open (already TLS-wrapped) connection by relaying it to the backend
    its name belongs to. HTTP/2 if ALPN chose it; else one HTTP/1.1 request, with the connection
    closed afterwards - unless the request upgrades (WebSockets), when both sides are piped together
    for as long as they talk."""
    if getattr(conn, "selected_alpn_protocol", lambda: None)() == "h2":
        return serve_h2(conn, routes, peer)
    try:
        got = read_head(conn)
        if not got:
            return
        method, target, version, headers, rest = got
        host = header(headers, "host").split(":")[0].lower()
        backend = routes.get(host)
        if not backend:
            return reply_plain(conn, "404 Not Found", f"no such service: {host or '(no host)'}")
        u = urllib.parse.urlsplit(backend)
        if "upgrade" in header(headers, "connection").lower() and header(headers, "upgrade"):
            out = forwarded(headers, u, host, peer, keep=("connection", "upgrade"))
            back = connect_raw(u)
            head = f"{method} {backend_path(u, target)} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in out)
            back.sendall(head.encode("latin-1") + b"\r\n" + rest)
            try:
                pipe(conn, back)  # the backend's 101 and everything after it go straight through
            finally:
                back.close()
            return
        length = int(header(headers, "content-length", 0) or 0)
        body = rest[:length]
        while len(body) < length:
            part = conn.recv(min(65536, length - len(body)))
            if not part:
                break
            body += part
        back, resp = fetch(u, method, target, forwarded(headers, u, host, peer) + [("Connection", "close")], body)
        reply = [f"HTTP/1.1 {resp.status} {resp.reason}"]
        for k, v in resp.getheaders():
            if k.lower() not in HOP and k.lower() != "content-length":
                reply.append(f"{k}: {v}")
        reply.append("Connection: close")
        conn.sendall(("\r\n".join(reply) + "\r\n\r\n").encode("latin-1"))
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            conn.sendall(chunk)
        back.close()
    except (OSError, http.client.HTTPException, ValueError) as e:
        reply_plain(conn, "502 Bad Gateway", f"the service behind {peer and 'this name'} did not answer: {e}")


def serve_h2(conn, routes, peer=""):
    """An HTTP/2 connection: each stream is one request to the backend, answered in turn, with the
    body sent as the client's flow-control window allows."""
    from h2 import events as ev
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.exceptions import ProtocolError

    h = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
    h.initiate_connection()
    conn.settimeout(IDLE)
    streams, ready, closed = {}, [], set()

    def take(data):
        """Feed what the client sent to h2, collecting whole requests and noting reset streams."""
        for e in h.receive_data(data):
            if isinstance(e, ev.RequestReceived):
                streams[e.stream_id] = {"headers": e.headers, "body": bytearray()}
            elif isinstance(e, ev.DataReceived) and e.stream_id in streams:
                streams[e.stream_id]["body"] += e.data
                h.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
            elif isinstance(e, ev.StreamEnded) and e.stream_id in streams:
                ready.append((e.stream_id, streams.pop(e.stream_id)))
            elif isinstance(e, ev.StreamReset):
                streams.pop(e.stream_id, None)
                closed.add(e.stream_id)
            elif isinstance(e, ev.ConnectionTerminated):
                return False
        return True

    def flush():
        data = h.data_to_send()
        if data:
            conn.sendall(data)

    def send_body(sid, resp):
        while sid not in closed:
            chunk = resp.read(65536)
            if not chunk:
                break
            pos = 0
            while pos < len(chunk) and sid not in closed:
                while h.local_flow_control_window(sid) == 0 and sid not in closed:
                    data = conn.recv(65536)  # a window update is wanted; other requests queue up meanwhile
                    if not data or not take(data):
                        return False
                    flush()
                if sid in closed:
                    break
                n = min(h.local_flow_control_window(sid), h.max_outbound_frame_size, len(chunk) - pos)
                h.send_data(sid, chunk[pos : pos + n])
                pos += n
                flush()
        if sid not in closed:
            h.end_stream(sid)
            flush()
        return True

    def answer(sid, req):
        hdr = {k.lower(): v for k, v in req["headers"]}
        host = (hdr.get(":authority") or hdr.get("host", "")).split(":")[0].lower()
        backend = routes.get(host)
        plain = [(k, v) for k, v in req["headers"] if not k.startswith(":")]
        if not backend:
            body = f"no such service: {host or '(no host)'}\n".encode()
            h.send_headers(
                sid, [(":status", "404"), ("content-type", "text/plain"), ("content-length", str(len(body)))]
            )
            h.send_data(sid, body, end_stream=True)
            flush()
            return True
        u = urllib.parse.urlsplit(backend)
        try:
            back, resp = fetch(
                u, hdr.get(":method", "GET"), hdr.get(":path", "/"), forwarded(plain, u, host, peer), bytes(req["body"])
            )
        except (OSError, http.client.HTTPException, ValueError) as e:
            body = f"the service behind this name did not answer: {e}\n".encode()
            h.send_headers(
                sid, [(":status", "502"), ("content-type", "text/plain"), ("content-length", str(len(body)))]
            )
            h.send_data(sid, body, end_stream=True)
            flush()
            return True
        try:
            out = [(":status", str(resp.status))] + [
                (k.lower(), v) for k, v in resp.getheaders() if k.lower() not in HOP and k.lower() != "content-length"
            ]
            if sid in closed:
                return True
            h.send_headers(sid, out)
            flush()
            return send_body(sid, resp)
        finally:
            back.close()

    try:
        flush()
        while True:
            data = conn.recv(65536)
            if not data or not take(data):
                return
            flush()
            while ready:
                if not answer(*ready.pop(0)):
                    return
    except (OSError, ProtocolError, ValueError):
        pass
    finally:
        with contextlib.suppress(Exception):
            h.close_connection()
            flush()


def gateway_loop(address):
    """The gateway process: TLS with the mesh's certificate, one thread per connection,
    routes and certificate re-read when the mesh's settings change."""
    mesh = store.local()["mesh"]
    cache = {"stamp": None, "ctx": None, "routes": {}}

    def current():
        try:
            stamp = os.stat(f"{settings.DIR}/conf.json").st_mtime_ns
        except OSError:
            stamp = None
        if stamp != cache["stamp"]:
            cert, key = store.https_material(mesh)
            if cert and key:
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                    f.write(cert + key)
                    path = f.name
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.load_cert_chain(path)
                    ctx.set_alpn_protocols(protocols())
                finally:
                    os.remove(path)
                cache["ctx"] = ctx
            cache["routes"] = store.https_routes(mesh)
            cache["stamp"] = stamp
        return cache

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND
    listener.bind((address, settings.HTTPS_PORT))
    listener.listen(32)

    def one(raw, peer):
        c = current()
        try:
            if not c["ctx"]:
                raw.close()
                return
            raw.settimeout(30)
            with c["ctx"].wrap_socket(raw, server_side=True) as conn:
                serve_one(conn, c["routes"], peer)
        except (OSError, ssl.SSLError):
            pass
        finally:
            with contextlib.suppress(OSError):
                raw.close()

    with ThreadPoolExecutor(settings.PARALLEL) as pool:
        while True:
            select.select([listener], [], [])
            raw, addr = listener.accept()
            pool.submit(one, raw, addr[0])


def cmd_httpsd():
    """The gateway process, on hubs; started by `sync`, kept alive by systemd."""
    gateway_loop(str(store.https_vip(store.local()["mesh"])))
