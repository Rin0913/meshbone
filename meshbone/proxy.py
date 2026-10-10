"""The HTTPS gateway: TLS on the hubs' fourth cluster IP, each name proxied to a backend inside
the mesh. Certificates come from the mesh's own CA (see store.ca and store.https_material)."""

import contextlib, http.client, os, select, socket, ssl, tempfile, urllib.parse
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


def serve_one(conn, routes, peer=""):
    """Answer one request on an open (already TLS-wrapped) connection by relaying it to the
    backend the Host header names. Hop-by-hop headers are dropped, X-Forwarded-* added, and the
    answer streamed back with the connection closed afterwards."""
    try:
        got = read_head(conn)
        if not got:
            return
        method, target, version, headers, rest = got
        host = next((v for k, v in headers if k.lower() == "host"), "").split(":")[0].lower()
        backend = routes.get(host)
        if not backend:
            body = f"no such service: {host or '(no host)'}\n".encode()
            conn.sendall(
                f"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            return
        u = urllib.parse.urlsplit(backend)
        length = int(next((v for k, v in headers if k.lower() == "content-length"), 0) or 0)
        body = rest[:length]
        while len(body) < length:
            part = conn.recv(min(65536, length - len(body)))
            if not part:
                break
            body += part
        out = [(k, v) for k, v in headers if k.lower() not in HOP and k.lower() != "host"]
        out += [
            ("Host", u.netloc),
            ("X-Forwarded-For", peer),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", host),
            ("Connection", "close"),
        ]
        path = (u.path.rstrip("/") + target) if u.path.rstrip("/") else target
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        kw = {"context": ssl._create_unverified_context()} if u.scheme == "https" else {}
        back = cls(u.hostname, u.port, timeout=60, **kw)
        back.request(method, path, body=body, headers=dict(out))
        resp = back.getresponse()
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
        with contextlib.suppress(OSError):
            body = f"the service behind {peer and 'this name'} did not answer: {e}\n".encode()
            conn.sendall(
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )


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
