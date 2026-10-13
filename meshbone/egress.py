"""An HTTP proxy on chosen nodes: the mesh's way out through that node's own connection.

`meshbone proxy NODE` switches it on; the node then listens on its mesh address (port 3128 by
default) and wants a user name and password. Settings live in the mesh's `egress` entry; the hash
of each password is there for the nodes to check against, the password itself is kept encrypted
under the admin key so that an admin node can show it again."""

import base64, contextlib, hashlib, hmac, ipaddress, os, secrets, select, socket, sys
from concurrent.futures import ThreadPoolExecutor

from . import proxy, settings, store

RECHECK = 5  # seconds between looks at the settings while idle
CONNECT_TIMEOUT = 15


def password_hash(salt, password):
    return hashlib.sha256(salt.encode() + b"\0" + password.encode()).hexdigest()


def accepts(entry, header):
    """Whether a Proxy-Authorization header carries this entry's user and password."""
    kind, _, blob = (header or "").partition(" ")
    if kind.lower() != "basic":
        return False
    try:
        user, _, password = base64.b64decode(blob.strip()).decode().partition(":")
    except (ValueError, UnicodeDecodeError):
        return False
    ok_user = hmac.compare_digest(user.encode(), entry["user"].encode())
    ok_pass = hmac.compare_digest(password_hash(entry["salt"], password), entry["hash"])
    return ok_user and ok_pass


def denied(ip):
    """Addresses the proxy never connects to: the node itself and what is only meaningful on it."""
    a = ipaddress.ip_address(ip)
    return a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast


def reply(conn, status, text="", extra=()):
    body = (text + "\n").encode() if text else b""
    head = f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in extra
    )
    with contextlib.suppress(OSError):
        conn.sendall(head.encode() + b"\r\n" + body)


def open_to(host, port):
    """A connected socket to host:port, or an error that says why not (for the 502 text)."""
    last = OSError("no address")
    for family, kind, proto, _, addr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        if denied(addr[0]):
            last = PermissionError(f"{host} is not allowed ({addr[0]})")
            continue
        s = socket.socket(family, kind, proto)
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect(addr)
            return s
        except OSError as e:
            s.close()
            last = e
    raise last


def serve_client(conn, entry, peer=""):
    """One proxied request or tunnel on an accepted connection."""
    try:
        conn.settimeout(30)
        got = proxy.read_head(conn)
        if not got:
            return
        method, target, version, headers, rest = got
        if not accepts(entry, proxy.header(headers, "proxy-authorization")):
            return reply(
                conn,
                "407 Proxy Authentication Required",
                "credentials needed",
                [("Proxy-Authenticate", 'Basic realm="meshbone"')],
            )
        try:
            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                back = open_to(host.strip("[]"), int(port or 443))
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                head = rest
            else:
                from urllib.parse import urlsplit

                u = urlsplit(target)
                if u.scheme != "http" or not u.hostname:
                    return reply(conn, "400 Bad Request", "a proxy request carries an absolute http:// URL")
                back = open_to(u.hostname, u.port or 80)
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                out = [(k, v) for k, v in headers if k.lower() not in proxy.HOP and not k.lower().startswith("proxy-")]
                out += [("Connection", "close")]
                head = (f"{method} {path} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in out) + "\r\n").encode(
                    "latin-1"
                ) + rest
        except (OSError, ValueError) as e:
            return reply(conn, "502 Bad Gateway", f"{target}: {e}")
        try:
            if head:
                back.sendall(head)
            proxy.pipe(conn, back)
        finally:
            back.close()
    except OSError:
        pass


def own_entry(mesh, name):
    return store.egress_settings().get(name)


def proxy_loop(name):
    """The proxy process: listens on this node's mesh address and exits (to be started again by
    systemd) when its own settings change, so a new port or password takes effect."""
    loc = store.local()
    mesh = loc["mesh"]
    entry = own_entry(mesh, name)
    if not entry:
        sys.exit(f"{name} is not set up as a proxy")
    nodes = store.load()
    me = nodes[loc["pub"]]
    address = str(store.router_ip(mesh, me["id"]))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND: the address may come up after us
    listener.bind((address, entry["port"]))
    listener.listen(64)
    with ThreadPoolExecutor(settings.PARALLEL * 4) as pool:
        while True:
            ready, _, _ = select.select([listener], [], [], RECHECK)
            if own_entry(mesh, name) != entry:
                os._exit(0)  # systemd's Restart=always brings us back with the new settings
            if ready:
                raw, addr = listener.accept()
                pool.submit(serve_client, raw, entry, addr[0])


def cmd_proxyd():
    """The proxy process, started by `sync` on the nodes that have it switched on."""
    loc = store.local()
    proxy_loop(store.load()[loc["pub"]]["name"])


def endpoint(mesh, name, entry, with_password=None):
    """URLs for a proxy: by name under the zone, and by mesh address."""
    node = store.by_name(store.load(), name)[1]
    zone = store.dns_settings(mesh)["zone"]
    auth = f"{entry['user']}:{with_password}@" if with_password else ""
    return (
        f"http://{auth}{name.lower()}.{zone}:{entry['port']}",
        f"http://{auth}{store.router_ip(mesh, node['id'])}:{entry['port']}",
    )


def new_password():
    return secrets.token_urlsafe(24)


def entry_for(user, port, password):
    salt = base64.b64encode(os.urandom(12)).decode()
    return {
        "user": user,
        "port": port,
        "salt": salt,
        "hash": password_hash(salt, password),
        "secret": store.password_box().encrypt(password.encode()).decode(),
    }


def password_of(entry):
    """The password, on a node that holds the admin key; None elsewhere."""
    try:
        return store.password_box().decrypt(entry["secret"].encode()).decode()
    except (OSError, KeyError, ValueError):
        return None
