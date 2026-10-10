#!/usr/bin/env python3
"""meshbone - WireGuard mesh backbone without a controller.

Every node has one WireGuard interface (mb0) and, if it is a hub, one UDP
port. Which peer carries which prefix is computed on every node from a signed
directory, so there is no routing daemon and no single machine to lose.

Roles
  hub      public host: other nodes dial its --endpoint (HOST:PORT; one
           forwarded UDP port is enough) and it relays between them.
           A hub holds no authority over the mesh.
  client   node behind NAT. Stays linked to every hub, sends through the one
           with the best ping and moves to another within seconds if it dies.
  admin    any node that holds admin.key. The directory is signed with that
           key, so only admin nodes can add, change or revoke nodes - keep it
           off the exposed machines.
  subnet   a network announced into the mesh by a hub or client acting as gateway.
  cluster IP  an address several nodes hold at once (anycast): traffic goes to
           one that is alive. Every hub holds the first two: .1 is the mesh
           map, traffic graphs and JSON API, .2 the Prometheus /metrics
           (both http, port 7948, read-only).

Addresses come from the mesh range (default 10.253.254.0/23, first /24 for
hubs, the rest for clients); cluster IPs from 10.253.253.0/24.

Any machine
  meshbone install              packages + /usr/local/sbin/meshbone, nothing else
  meshbone create [--endpoint HOST:PORT] [--name N] [--subnet CIDR]... [--mesh NAME] [--net CIDR] [--cluster-net CIDR]
                                this machine becomes the first node and the first admin
  meshbone join FILE [--once]   FILE is the mesh config written by `invite`;
                                --once keeps everything in /run (gone after reboot or `leave`)
  meshbone local [--listen-port N] [--mtu N] [--nat on|off]
                                this machine's own network settings (also accepted by create, join and deploy)
  meshbone promote --endpoint HOST:PORT   ask to become a hub at this stable public address
  meshbone cost NAME MS         local penalty in ms for sending via hub NAME (0 = automatic)
  meshbone status | leave | upgrade

Managing (the commands below, or http://10.253.253.1:7948/admin on any node)
  Changes are signed. A node that holds admin.key signs directly. Anywhere else you paste the
  admin key into the page - it stays in the browser, which signs a token of limited life for
  that node - or type it when a command asks.
  meshbone passwd               change the management page's password, on every admin node
  meshbone update URL [--ref REF] | --file PATH | --rollback
                                fetch a version (https://github.com/OWNER/REPO at a branch, tag or commit),
                                install and health-check it here first, then sign it and let every node
                                do the same; a node that fails keeps its old version and logs why
  meshbone invite NAME [--endpoint HOST:PORT] [--subnet CIDR]... [--vip IP]... [--cost MS] [--admin] [-o FILE]
  meshbone deploy NAME --remote 'USER[:PASSWORD]@HOST[;USER[:PASSWORD]@HOST]...' [invite options] [--once]
                                invite + install + join over ssh, through any number of jump hosts
  (invite, deploy and set also take --desc TEXT and --label L...; invite and deploy take --ip ADDRESS.
   Giving a node an endpoint makes it a hub once a client has reached it there; --endpoint '' makes
   it a client again. A mesh always keeps at least one hub.)
  meshbone set NAME [--endpoint HOST:PORT] [--subnet CIDR]... [--no-subnet] [--vip IP]... [--no-vip] [--cost MS]
  meshbone simple NAME [--hub HUB] [--qr] [-o FILE]
                                a client for a phone or any device that only runs plain WireGuard:
                                writes a standard config (and shows a QR code); run it again to re-export
  meshbone approve NAME         accept a `promote` request
  meshbone policy [--default allow|deny] [--add FROM TO allow|deny [--ports P] [--at N]] [--del N] [--clear]
                                the firewall: who may open connections to whom across the mesh. FROM and TO
                                are groups: a label, @name, nodes, hubs, clients, subnets, LABEL+net, any,
                                or an address. First matching rule decides.
  meshbone revoke NAME

The file is laid out as model, view, controller - see the banners below.
"""


import argparse, base64, contextlib, fcntl, hashlib, hmac, html, io, json, os, random, re
import secrets, shlex, shutil, socket, sqlite3, subprocess, sys, tarfile, tempfile, time, urllib.parse, urllib.request, zlib
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network, collapse_addresses


VERSION = 6
IFACE = "mb0"
DEFAULT_PORT = 51820
GOSSIP_PORT = 7947  # TCP, reachable only from mesh addresses
ADMIN_PORT = 7948  # HTTP: the mesh map on every hub, plus /admin on the admin nodes
FRESH = 180  # a WireGuard peer with a handshake this recent (s) counts as reachable
VERIFY_WAIT = 20  # how long join waits for the first handshakes (s)
CONFIRM_WAIT = 60  # how long a new hub has to be reached from outside before it is demoted again (s)
UPDATE_SETTLE = 10  # seconds a freshly upgraded node gets before its health is judged
MESH_TABLE = 7948  # routing table (and rule priority) for packets that arrive from the mesh
SESSIONS = "/run/meshbone-sessions"  # web sessions that hold a token; gone at reboot
SESSION_MAX = 12 * 3600  # the longest a token may be valid (s)
SESSION = None  # (key, delegation) while a command or request may sign changes without the admin key file
ISSUED = {}  # private keys of simple clients created by this process: name -> key
KEEP_FINE = 2 * 86400  # traffic history: per-minute buckets this long, 10-minute buckets after that
KEEP_ALL = 90 * 86400
PARALLEL = 16
SBIN = "/usr/local/sbin/meshbone"
KEY_RE = r"[A-Za-z0-9+/]{43}="
NAME_RE = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}"
ENDPOINT_RE = r"(|(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):\d{1,5})"
LABEL_RE = r"[A-Za-z0-9][A-Za-z0-9_.:=/-]{0,47}"


# ==============================================================================
# MODEL - the mesh as data and rules: the signed directory, what nodes report about
# themselves, traffic history, versions. Nothing here draws a page or reads argv.
# ==============================================================================


def set_mode(once):
    global ONCE, DIR, UNIT_DIR, BIN
    ONCE = once
    if once:
        DIR, UNIT_DIR, BIN = "/run/meshbone", "/run/systemd/system", "/run/meshbone/meshbone"
    else:
        DIR, UNIT_DIR, BIN = "/etc/meshbone", "/etc/systemd/system", SBIN


set_mode(os.path.exists("/run/meshbone/node.json"))


def joined():
    return any(os.path.exists(f"{d}/node.json") for d in ("/etc/meshbone", "/run/meshbone"))


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def read(name):
    with open(f"{DIR}/{name}") as f:
        return f.read().strip()


def write(path, text, mode=0o600):
    tmp = path + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_json(name, default):
    try:
        return json.loads(read(name))
    except (FileNotFoundError, ValueError):
        return default


@contextlib.contextmanager
def locked():
    with open(f"{DIR}/lock", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def local():
    """This node's identity, secrets and own settings: {mesh, key, pub, cost[, wants, listen_port, mtu]}."""
    return json.loads(read("node.json"))


def load():
    """The mesh directory: {pubkey: {name, id, endpoint, subnets, vips, cost, seq, sig[, gone]}}.
    Every entry is signed with the admin key."""
    return json.loads(read("nodes.json"))


def save(nodes):
    write(f"{DIR}/nodes.json", json.dumps(nodes, indent=1, sort_keys=True))


def load_nets():
    """What each node reports about itself: {pubkey: {nets, wants, sees, rtt, primary, admin, seq}} -
    the local networks it sits on, the endpoint it asks to be a hub at, the ids of the nodes a
    hub currently reaches, its ping to each hub, the hub it sends through and whether it is an
    admin node. Each record is written by its own node and is not signed: it feeds the map and
    hub selection, never authority."""
    return json.loads(read("nets.json"))


def save_nets(nets):
    write(f"{DIR}/nets.json", json.dumps(nets, indent=1, sort_keys=True))


def load_conf():
    """Mesh-wide settings, each signed with the admin key: {name: {value, seq, sig}}."""
    return read_json("conf.json", {})


def state():
    return {"v": VERSION, "nodes": load(), "nets": load_nets(), "conf": load_conf()}


def live(nodes):
    """Nodes that are part of the mesh. Should two ever be given the same id (invited on
    two admin nodes in the same instant), everyone deterministically keeps the smaller key."""
    out, taken = {}, set()
    for pk in sorted(nodes):
        n = nodes[pk]
        if not n.get("gone") and n["id"] not in taken:
            taken.add(n["id"])
            out[pk] = n
    return out


def by_name(nodes, name):
    hits = [(pk, n) for pk, n in live(nodes).items() if n["name"] == name]
    if not hits:
        sys.exit(f"no node named {name}")
    return hits[0]


def mesh_net(mesh):
    return IPv4Network(mesh["net"])


def cluster_net(mesh):
    return IPv4Network(mesh["cluster_net"])


def admin_vip(mesh):
    return cluster_net(mesh).network_address + 1


def metrics_vip(mesh):
    return cluster_net(mesh).network_address + 2


def router_ip(mesh, node_id):
    return mesh_net(mesh).network_address + node_id


def held_vips(mesh, node):
    """A node's cluster IPs; every hub also holds the two service addresses (map and metrics)."""
    return node["vips"] + ([str(admin_vip(mesh)), str(metrics_vip(mesh))] if node["endpoint"] else [])


def prefixes(mesh, node):
    """Everything a node owns: its address, its cluster IPs, the subnets behind it."""
    return [IPv4Network(f"{ip}/32") for ip in [router_ip(mesh, node["id"])] + held_vips(mesh, node)] + [
        IPv4Network(s) for s in node["subnets"]
    ]


def id_pool(mesh, hub):
    """A node's id is its offset in the mesh range: invited hubs get one from the first /24,
    clients from the rest. (A client promoted to hub keeps its address.)"""
    ids = range(1, 255) if hub else range(256, mesh_net(mesh).num_addresses)
    return [i for i in ids if i % 256 not in (0, 255)]


def next_seq(old=0):
    # wall clock, but never going backwards for a record: a Lamport clock with readable values
    return max(int(time.time()), old + 1)


def listed(values):
    """Every item of a list a person typed, whether they separated them with commas, spaces, or by
    repeating the option: ['a,b', 'c d'] -> ['a', 'b', 'c', 'd'], in order, without repeats."""
    values = [values] if isinstance(values, str) else values
    return list(dict.fromkeys(item for value in values for item in re.split(r"[\s,]+", value) if item))


def carve(net, holes):
    """A network without the parts that are `holes` -> list of networks."""
    out = [net]
    for hole in holes:
        out = [
            piece
            for n in out
            for piece in ([] if n.subnet_of(hole) else n.address_exclude(hole) if hole.subnet_of(n) else [n])
        ]
    return out


def norm_endpoint(text):
    """'' | HOST | HOST:PORT | [v6]:PORT -> '' or 'HOST:PORT'."""
    m = re.fullmatch(r"(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?", text or "")
    if text and (not m or not 0 < int(m[2] or DEFAULT_PORT) < 65536):
        sys.exit(f"bad endpoint {text!r}: use HOST or HOST:PORT")
    return f"{m[1]}:{m[2] or DEFAULT_PORT}" if text else ""


def valid_mesh(mesh):
    try:
        assert re.fullmatch(NAME_RE, mesh["name"]) and re.fullmatch(KEY_RE, mesh["psk"])
        net, cluster = IPv4Network(mesh["net"]), IPv4Network(mesh["cluster_net"])
        assert 20 <= net.prefixlen <= 23 and 20 <= cluster.prefixlen <= 29 and not net.overlaps(cluster)
        assert re.fullmatch(r"[0-9a-f]{64}", mesh["admin"]) and len(base64.b64decode(mesh["admin_pub"])) == 32
        return True
    except Exception:
        return False


def canonical(nets):
    return all(isinstance(s, str) and str(IPv4Network(s)) == s for s in nets)


def ed25519():
    # imported late so that `install` can fetch the package first
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519


def signable(pk, n):
    # the WireGuard key is part of what is signed, or an entry could be re-used under another key
    return json.dumps({**{k: v for k, v in n.items() if k != "sig"}, "pk": pk}, sort_keys=True).encode()


def authority():
    """Who signs a change right now -> (Ed25519 private key, delegation or None).

    Either this machine holds the admin key, or a web session presented a token:
    the admin key's signature under a short-lived session key that lives only on
    the node serving that session. On a terminal the key can also be typed in.
    """
    global SESSION
    if SESSION:
        return SESSION
    load_key = ed25519().Ed25519PrivateKey.from_private_bytes
    if os.path.exists(f"{DIR}/admin.key"):
        return load_key(base64.b64decode(read("admin.key"))), None
    if not sys.stdin.isatty():
        sys.exit("this machine holds no admin key: use the management page with your key, or an admin node")
    import getpass
    from cryptography.hazmat.primitives import serialization as ser

    try:
        key = load_key(base64.b64decode(getpass.getpass("admin key: ").strip()))
        mine = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        assert base64.b64encode(mine).decode() == local()["mesh"]["admin_pub"]
    except Exception:
        sys.exit("that is not this mesh's admin key")
    SESSION = (key, None)
    return SESSION


def seal(record, message):
    """Sign a record in place; `message(record)` is what the signature covers."""
    key, by = authority()
    record.pop("by", None)
    if by:
        record["by"] = by
        if not by["nbf"] <= record["seq"] <= by["exp"]:
            sys.exit("this change falls outside the token's validity; log in again")
    record["sig"] = base64.b64encode(key.sign(message(record))).decode()
    return record


def sealed(mesh, record, message):
    """Was this record signed by the admin key, or under a token the admin key issued that was
    valid at the record's time? Raises if not."""
    load_pub = ed25519().Ed25519PublicKey.from_public_bytes
    root, by, sig = load_pub(base64.b64decode(mesh["admin_pub"])), record.get("by"), base64.b64decode(record["sig"])
    if by is None:
        return root.verify(sig, message)
    assert set(by) == {"key", "nbf", "exp", "sig"} and type(by["nbf"]) is int and type(by["exp"]) is int
    assert 0 < by["exp"] - by["nbf"] <= SESSION_MAX + 120 and by["nbf"] <= record["seq"] <= by["exp"]
    root.verify(base64.b64decode(by["sig"]), session_message(mesh, by["key"], by["nbf"], by["exp"]))
    load_pub(base64.b64decode(by["key"])).verify(sig, message)


def session_message(mesh, pub, nbf, exp):
    """What the admin key signs to issue a token: this session key, on this mesh, for this long."""
    return f"meshbone-session\n{mesh['name']}\n{mesh['admin_pub']}\n{pub}\n{nbf}\n{exp}".encode()


def sign(pk, n):
    return seal(n, lambda r: signable(pk, r))


def valid(mesh, pk, n):
    """A directory entry is only accepted if the admin key signed it, directly or through a token."""
    try:
        assert wellformed(pk, n)
        sealed(mesh, n, signable(pk, n))
        return True
    except Exception:
        return False


def wellformed(pk, n):
    """Entries end up in the WireGuard config, so reject anything malformed."""
    try:
        assert re.fullmatch(KEY_RE, pk) and re.fullmatch(NAME_RE, n["name"])
        assert type(n["seq"]) is int and type(n["id"]) is int and 1 <= n["id"] < 4096
        assert type(n["cost"]) is int and 0 <= n["cost"] <= 10000
        assert re.fullmatch(ENDPOINT_RE, n["endpoint"])
        assert canonical(n["subnets"])
        assert all(isinstance(v, str) and str(IPv4Address(v)) == v for v in n["vips"])
        assert isinstance(n.get("desc", ""), str) and len(n.get("desc", "")) <= 200 and n.get("desc", "").isprintable()
        assert type(n.get("simple", False)) is bool
        assert len(n.get("labels", [])) <= 16 and all(
            isinstance(l, str) and re.fullmatch(LABEL_RE, l) for l in n.get("labels", [])
        )
        return True
    except Exception:
        return False


def valid_nets(pk, r):
    try:
        assert re.fullmatch(KEY_RE, pk) and type(r["seq"]) is int and len(json.dumps(r)) < 16384
        assert len(r["nets"]) <= 64 and canonical(r["nets"])
        assert re.fullmatch(ENDPOINT_RE, r.get("wants", ""))
        assert all(type(i) is int for i in r.get("sees", [])) and len(r.get("sees", [])) < 4096
        assert all(k.isdigit() and type(v) is int for k, v in r.get("rtt", {}).items()) and len(r.get("rtt", {})) < 256
        assert type(r.get("primary", 0)) in (int, type(None)) and type(r.get("admin", False)) is bool
        assert isinstance(r.get("code", ""), str) and isinstance(r.get("update") or {}, dict)
        return True
    except Exception:
        return False


def conf_signable(name, r):
    covered = {"conf": name, "value": r["value"], "seq": r["seq"]}
    if "by" in r:
        covered["by"] = r["by"]
    return json.dumps(covered, sort_keys=True).encode()


def valid_conf(mesh, name, r):
    try:
        assert re.fullmatch(r"[a-z0-9_]{1,40}", name) and type(r["seq"]) is int
        assert isinstance(r["value"], str) and len(r["value"]) < 32768
        sealed(mesh, r, conf_signable(name, r))
        return True
    except Exception:
        return False


def checked(mesh, nodes, nets, pk, n, keep=()):
    """Vet an entry an admin is about to write; exits with a message instead of saving garbage.
    Subnets the node already had (`keep`) are not re-examined, so a conflict that appeared
    later elsewhere does not block unrelated edits."""
    try:
        n["subnets"] = [str(IPv4Network(s)) for s in listed(n["subnets"])]
        n["vips"] = [str(IPv4Address(v)) for v in listed(n["vips"])]
    except ValueError as e:
        sys.exit(f"bad address: {e}")
    if "labels" in n:
        n["labels"] = listed(n["labels"])
    n["endpoint"] = norm_endpoint(n["endpoint"])
    if not wellformed(pk, n) or not n["id"] < mesh_net(mesh).num_addresses:
        sys.exit("bad name, endpoint, cost, description (200 printable characters) or label (letters, digits, _.:=/-)")
    others = {k: o for k, o in live(nodes).items() if k != pk}
    if any(o["name"] == n["name"] for o in others.values()):
        sys.exit(f"name {n['name']} is already taken")
    for v in map(IPv4Address, n["vips"]):
        if v not in cluster_net(mesh) or v in (admin_vip(mesh), metrics_vip(mesh)):
            sys.exit(
                f"{v} is not a free address in the cluster range {mesh['cluster_net']} "
                f"({admin_vip(mesh)} and {metrics_vip(mesh)} belong to the hubs: map and metrics)"
            )
    # A network may *contain* something more specific that exists elsewhere - the more specific one
    # keeps winning, on every node - but it may not be, or lie inside, what somebody already has.
    for s in (IPv4Network(s) for s in n["subnets"] if s not in keep):
        for reserved in (mesh_net(mesh), cluster_net(mesh)):
            if s.subnet_of(reserved):
                sys.exit(f"{s} lies inside the mesh's own range {reserved}")
        for k, o in others.items():
            for t in o["subnets"]:
                if s.subnet_of(IPv4Network(t)):
                    sys.exit(f"{s} is already covered by {t}, announced by {o['name']}")
            for t in nets.get(k, {}).get("nets", []):
                if s.subnet_of(IPv4Network(t)):
                    sys.exit(f"{s} is, or lies inside, {t}: a local network of {o['name']} (not announced)")
    return n


def rank(record):
    # last writer wins; equal seqs are broken by content so every replica picks the same winner
    return (record["seq"], json.dumps(record, sort_keys=True)) if record else (-1, "")


def lww(mine, incoming, ok):
    changed = False
    if isinstance(incoming, dict):
        for k, v in incoming.items():
            try:
                newer = rank(v) > rank(mine.get(k))
            except (TypeError, KeyError):
                continue
            if newer and ok(k, v):  # in this order: signatures are only checked for news
                mine[k], changed = v, True
    return changed


def merge(msg, only=None):
    """Fold a peer's state into ours. True if anything changed.

    Both maps are last-writer-wins per key, so merging is commutative and
    idempotent and replicas converge whatever order messages arrive in.
    Directory entries are taken from anyone because each carries the admin
    signature. Self-reported records are not signed: a client peer (`only`)
    may update just its own, hubs relay everyone's.
    """
    if not isinstance(msg, dict) or msg.get("v") != VERSION:
        return False
    mesh, nodes, nets = local()["mesh"], load(), load_nets()
    theirs = msg.get("nets")
    if only:
        theirs = {only: theirs[only]} if isinstance(theirs, dict) and only in theirs else {}
    conf = load_conf()
    a = lww(nodes, msg.get("nodes"), lambda pk, n: valid(mesh, pk, n))
    b = lww(nets, theirs, valid_nets)
    c = lww(conf, msg.get("conf"), lambda name, r: valid_conf(mesh, name, r))
    if a:
        save(nodes)
    if b:
        save_nets(nets)
    if c:
        write(f"{DIR}/conf.json", json.dumps(conf, indent=1, sort_keys=True))
    return a or b or c


def conf_put(name, value):
    """Store one mesh-wide setting, signed (call it under the lock)."""
    conf = load_conf()
    conf[name] = seal(
        {"value": value, "seq": next_seq(conf.get(name, {}).get("seq", 0))}, lambda r: conf_signable(name, r)
    )
    write(f"{DIR}/conf.json", json.dumps(conf, indent=1, sort_keys=True))


def session_file(sid):
    return f"{SESSIONS}/{sid}.json" if re.fullmatch(r"[\w-]{10,60}", sid or "") else None


def session_open(peer):
    """Start a web session for the browser at address `peer` -> (session id, session public key).
    It can do nothing until the browser returns a token for that key."""
    from cryptography.hazmat.primitives import serialization as ser

    os.makedirs(SESSIONS, mode=0o700, exist_ok=True)
    now = time.time()
    for name in os.listdir(SESSIONS):  # forget sessions that have run out or were never completed
        try:
            with open(f"{SESSIONS}/{name}") as f:
                s = json.load(f)
            over = now > s.get("exp", s["born"] + 600)
        except (OSError, ValueError, KeyError):
            over = True
        if over:
            with contextlib.suppress(OSError):
                os.remove(f"{SESSIONS}/{name}")
    key = ed25519().Ed25519PrivateKey.generate()
    private = key.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    public = base64.b64encode(key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
    sid = secrets.token_urlsafe(24)
    write(
        session_file(sid),
        json.dumps({"key": base64.b64encode(private).decode(), "pub": public, "peer": peer, "born": int(now)}),
    )
    return sid, public


def session_grant(mesh, sid, peer, nbf, exp, sig):
    """Accept the token the browser made for a session, if the admin key really signed it."""
    try:
        with open(session_file(sid)) as f:
            s = json.load(f)
        now = time.time()
        assert s["peer"] == peer and "by" not in s
        assert nbf <= now + 120 and now < exp and 0 < exp - nbf <= SESSION_MAX + 120
        root = ed25519().Ed25519PublicKey.from_public_bytes(base64.b64decode(mesh["admin_pub"]))
        root.verify(base64.b64decode(sig), session_message(mesh, s["pub"], nbf, exp))
    except Exception:
        return False
    s.update(by={"key": s["pub"], "nbf": nbf, "exp": exp, "sig": sig}, exp=exp)
    write(session_file(sid), json.dumps(s))
    return True


def session_use(sid, peer):
    """A session that holds a token still in force, asked for from the same address -> (key, delegation, expiry)."""
    try:
        with open(session_file(sid)) as f:
            s = json.load(f)
        assert s["peer"] == peer and time.time() < s["exp"]
        return ed25519().Ed25519PrivateKey.from_private_bytes(base64.b64decode(s["key"])), s["by"], s["exp"]
    except Exception:
        return None


def session_close(sid):
    with contextlib.suppress(OSError, TypeError):
        os.remove(session_file(sid))


def admin():
    """State for a directory-changing command; exits unless changes can be signed here and now."""
    authority()
    return local(), load(), load_nets()


def pair_psk(loc, peer):
    """The preshared key for one link. It is derived from the mesh secret *and* the two nodes'
    own key exchange, so it differs per pair and no third node - mesh member or not - can
    compute it; WireGuard then refuses any handshake that does not know it."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    shared = X25519PrivateKey.from_private_bytes(base64.b64decode(loc["key"])).exchange(
        X25519PublicKey.from_public_bytes(base64.b64decode(peer))
    )
    return base64.b64encode(
        hmac.new(base64.b64decode(loc["mesh"]["psk"]), b"meshbone link psk" + shared, "sha256").digest()
    ).decode()


def plan(loc, nodes, nets, rtt, seen, previous=None):
    """Which peer carries which prefix -> ({peer: [prefixes]}, primary hub).

    WireGuard sends a packet to the one peer whose AllowedIPs cover it and drops
    packets that arrive from a peer with a source outside them, so this table is
    the routing table and the anti-spoofing filter at once - and it is derived
    from the signed directory, not from anything a neighbour claims.

    A hub hands every prefix to its owner. A client keeps each hub's own prefixes
    on that hub and sends everything else through its primary hub: the reachable
    one with the best ping (plus cost), unless that hub does not currently see
    the destination and another one does.
    """
    mesh, mypk, alive = loc["mesh"], loc["pub"], live(nodes)
    hub = bool(alive[mypk]["endpoint"])
    peers = {pk: n for pk, n in alive.items() if pk != mypk and (hub or n["endpoint"])}
    table = {pk: [] for pk in peers}
    if not peers:
        return table, None
    owners = {}
    for pk, n in alive.items():
        for p in prefixes(mesh, n):
            owners.setdefault(p, []).append(pk)
    if hub:
        for p, own in owners.items():
            if mypk not in own:  # among several holders of a cluster IP: the one heard from last
                table[min(own, key=lambda pk: (seen.get(pk, float("inf")), pk))].append(p)
        return table, None

    def score(pk):
        return rtt.get(pk, 0) + peers[pk]["cost"] + loc["cost"].get(peers[pk]["name"], 0)

    up = [pk for pk in peers if pk in rtt] or list(peers)  # nothing answers yet: try them all
    primary = min(up, key=lambda pk: (score(pk), pk))
    if previous in up and score(previous) <= score(primary) + 5:
        primary = previous  # do not flap between hubs that are about equally good
    for p, own in owners.items():
        if mypk in own:
            continue
        direct = [pk for pk in own if pk in up]
        if direct:  # the destination is a reachable hub itself
            table[min(direct, key=lambda pk: (score(pk), pk))].append(p)
        elif all(pk in peers for pk in own):  # only on hubs that are down; keeps their address probed
            table[own[0]].append(p)
        else:
            ids = {alive[pk]["id"] for pk in own}
            via = [h for h in up if ids & set(nets.get(h, {}).get("sees", []))]
            table[primary if primary in via or not via else min(via, key=lambda pk: (score(pk), pk))].append(p)
    return table, primary


def password_box():
    # only admin nodes can read the password record: it is encrypted under the admin key
    from cryptography.fernet import Fernet

    return Fernet(
        base64.urlsafe_b64encode(hashlib.sha256(b"meshbone password" + base64.b64decode(read("admin.key"))).digest())
    )


def check_password(password):
    r = load_conf().get("admin_pw")
    if not r:  # still the one printed by `create`
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), local()["mesh"]["admin"])
    try:
        raw = password_box().decrypt(r["value"].encode())
    except Exception:
        return False
    return hmac.compare_digest(hashlib.scrypt(password.encode(), salt=raw[:16], n=2**14, r=8, p=1, dklen=32), raw[16:])


def simple_config(name, hub=None, key=None):
    """A standard WireGuard config for a simple client -> (text, hub used, all hub names).

    Plain WireGuard cannot choose between hubs, so the device sends everything through
    one of them; pick another and import again if that hub is ever down. The config
    lists the networks known right now - it does not follow later changes by itself.
    The device's key is `key` if it was just created here, else the copy the admin
    nodes keep.
    """
    loc, nodes, nets = admin()
    mesh, alive = loc["mesh"], live(nodes)
    pk, n = by_name(nodes, name)
    if not n.get("simple"):
        sys.exit(f"{name} is not a simple client")
    try:
        key = key or password_box().decrypt(load_conf()[f"simple_{n['id']}"]["value"].encode()).decode()
    except Exception:
        sys.exit(f"the key of {name} is only kept on nodes that hold the admin key; elsewhere its config is shown once")
    hubs = {
        h["name"]: (k, h)
        for k, h in sorted(alive.items(), key=lambda kv: (kv[1]["cost"], kv[1]["id"]))
        if h["endpoint"]
    }
    if hub not in hubs:
        if hub:
            sys.exit(f"{hub} is not a hub")
        if not hubs:
            sys.exit("the mesh has no hub to connect to")
        hub = next((h for h, (k, o) in hubs.items() if n["id"] in nets.get(k, {}).get("sees", [])), next(iter(hubs)))
    hub_pk, h = hubs[hub]
    reach = [mesh["net"], mesh["cluster_net"]] + sorted({s for o in alive.values() for s in o["subnets"]})
    text = (
        f"# mesh {mesh['name']}: {name} via {hub}\n[Interface]\nPrivateKey = {key}\n"
        f"Address = {router_ip(mesh, n['id'])}/32\n\n[Peer]\nPublicKey = {hub_pk}\n"
        f"PresharedKey = {pair_psk({'key': key, 'mesh': mesh}, hub_pk)}\nEndpoint = {h['endpoint']}\n"
        f"AllowedIPs = {', '.join(reach)}\nPersistentKeepalive = 25\n"
    )
    return text, hub, list(hubs)


def parse_chain(text):
    """'user:password@host;user@host2;host3' -> [(ssh destination, password or None)].
    The older 'user@host:user@host2' spelling (no passwords) still works."""
    text = re.sub(r"^ssh(://|:?\s+)", "", text.strip())  # "ssh user@host" and "ssh: user@host" mean the same
    legacy = ";" not in text and ("@" in text.split(":")[0] or "@" not in text)
    chain = []
    for part in text.split(":" if legacy else ";"):
        cred, _, host = part.strip().rpartition("@")
        user, _, password = cred.partition(":")
        dest = f"{user}@{host}" if user else host
        if not re.fullmatch(r"([\w.-]+@)?[\w.-]+", dest):
            sys.exit(
                "--remote is USER[:PASSWORD]@HOST[;USER[:PASSWORD]@HOST]... (ports and options belong in ssh_config)"
            )
        chain.append((dest, password or None))
    return chain


def stats_db():
    """Traffic and latency history. Every row belongs to the hub that measured it (reporter):
    what it received from and sent to one peer in one time bucket, and the ping across that link."""
    db = sqlite3.connect(f"{DIR}/stats.db", timeout=10)
    db.executescript(
        "CREATE TABLE IF NOT EXISTS link(reporter INT, peer INT, ts INT, rx INT, tx INT, ms INT, "
        "PRIMARY KEY(reporter, peer, ts)) WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS total(reporter INT, peer INT, rx INT, tx INT, PRIMARY KEY(reporter, peer)) WITHOUT ROWID;"
    )
    return db


def stats_upkeep(db):
    """Once an hour: fold minutes that are old into 10-minute buckets and drop what is too old.
    Every holder of a copy does the same arithmetic, so the copies stay alike."""
    bucket = int(time.time()) // 60 * 60
    if bucket % 3600:
        return
    cut = bucket - KEEP_FINE
    db.execute(
        "INSERT INTO link SELECT reporter, peer, ts / 600 * 600, sum(rx), sum(tx), CAST(avg(ms) AS INT) FROM link "
        "WHERE ts < ? AND ts % 600 != 0 GROUP BY 1, 2, 3 ON CONFLICT(reporter, peer, ts) DO UPDATE SET "
        "rx = rx + excluded.rx, tx = tx + excluded.tx",
        (cut,),
    )
    db.execute("DELETE FROM link WHERE ts < ? AND ts % 600 != 0", (cut,))
    db.execute("DELETE FROM link WHERE ts < ?", (bucket - KEEP_ALL,))


def keeps_stats(me):
    """Does this node hold the traffic history? Hubs measure it; every node that serves the
    pages keeps a copy, so the graphs look the same whichever of them answers."""
    return bool(me["endpoint"]) or os.path.exists(f"{DIR}/admin.key")


def stats_cursors():
    """{reporter id: newest bucket we hold from it}"""
    try:
        db = stats_db()
        out = dict(db.execute("SELECT reporter, max(ts) FROM link GROUP BY reporter").fetchall())
        db.close()
        return out
    except sqlite3.Error:
        return {}


def stats_export(my_id, since):
    try:
        db = stats_db()
        out = {
            "stats": db.execute(
                "SELECT peer, ts, rx, tx, ms FROM link WHERE reporter = ? AND ts >= ? ORDER BY ts LIMIT 3000",
                (my_id, since),
            ).fetchall(),
            "totals": db.execute("SELECT peer, rx, tx FROM total WHERE reporter = ?", (my_id,)).fetchall(),
        }
        db.close()
        return out
    except sqlite3.Error:
        return {}


def stats_import(reporter, got):
    """Take another hub's own measurements; it can only speak for itself."""
    ints = lambda row, n: isinstance(row, list) and len(row) == n and all(type(v) is int or v is None for v in row)
    try:
        db = stats_db()
        db.executemany(
            "INSERT OR REPLACE INTO link VALUES (?, ?, ?, ?, ?, ?)",
            [(reporter, *r) for r in got.get("stats", []) if ints(r, 5) and None not in r[:4]],
        )
        db.executemany(
            "INSERT OR REPLACE INTO total VALUES (?, ?, ?, ?)",
            [(reporter, *r) for r in got.get("totals", []) if ints(r, 3) and None not in r],
        )
        stats_upkeep(db)
        db.commit()
        db.close()
    except (sqlite3.Error, TypeError) as e:
        log(f"stats: {e}")


def traffic_totals():
    """[(hub id, peer id, bytes received, bytes sent)] since counting began."""
    try:
        db = stats_db()
        totals = db.execute("SELECT reporter, peer, rx, tx FROM total").fetchall()
        db.close()
        return totals
    except sqlite3.Error:
        return []


def api_nodes(query):
    topo = topology()["nodes"]
    want = query.get("label", [])
    return [
        n
        for n in topo
        if all(l in n["labels"] for l in want)
        and query.get("role", ["hub" if n["hub"] else "client"])[0] == ("hub" if n["hub"] else "client")
        and query.get("name", [n["name"]])[0] == n["name"]
    ]


def api_traffic(query):
    now = int(time.time())
    try:
        to = int(query.get("to", [now])[0])
        frm = int(query.get("from", [to - 21600])[0])
        step = int(query.get("step", [0])[0])
    except ValueError:
        frm, to, step = now - 21600, now, 0
    frm, to = max(0, min(frm, to - 60)), max(to, 60)
    fine = 60 if frm >= now - KEEP_FINE else 600  # older data only exists in 10-minute buckets
    step = max(fine, -(-max(step, (to - frm) // 240) // fine) * fine)
    alive = live(load())
    hubs = {n["id"] for n in alive.values() if n["endpoint"]}
    links = {}
    try:
        db = stats_db()
        for reporter, peer, t, rx, tx, ms in db.execute(
            "SELECT reporter, peer, ts / ? * ?, sum(rx), sum(tx), CAST(avg(ms) AS INT) FROM link "
            "WHERE ts >= ? AND ts <= ? GROUP BY 1, 2, 3 ORDER BY 3",
            (step, step, frm, to),
        ):  # <=: the bucket still filling counts
            links.setdefault((reporter, peer), []).append([t, rx, tx, ms])
        db.close()
        for reporter, peer in list(links):  # two hubs both count their link: show it once
            if peer in hubs and reporter > peer and (peer, reporter) in links:
                del links[(reporter, peer)]
    except sqlite3.Error as e:
        log(f"stats: {e}")
    return {
        "from": frm,
        "to": to,
        "step": step,
        "names": {n["id"]: n["name"] for n in alive.values()},
        "links": [{"reporter": r, "peer": p, "points": pts} for (r, p), pts in sorted(links.items())],
    }


def rows():
    """One dict per live node: the directory entry plus role, ip, eff (cost with the local
    override), wants (pending hub request) and link - how *this machine* reaches it."""
    loc, nodes, nets = local(), load(), load_nets()
    seen, st, alive = handshakes(), read_json("state.json", {}), live(nodes)
    hub = bool(nodes[loc["pub"]]["endpoint"])
    for pk, n in sorted(alive.items(), key=lambda kv: kv[1]["id"]):
        if pk == loc["pub"]:
            link = "this machine"
        elif hub or n["endpoint"]:
            link = "linked" if seen.get(pk, FRESH) < FRESH else "no link"
            if pk in st.get("rtt", {}):
                link += f", ping {st['rtt'][pk]:.0f} ms"
            if pk == st.get("primary"):
                link += ", sending through it"
        else:
            link = "via " + alive.get(st.get("primary"), {"name": "a hub"})["name"]
        wants = nets.get(pk, {}).get("wants", "")
        yield {
            **n,
            "role": "hub" if n["endpoint"] else "client",
            "ip": str(router_ip(loc["mesh"], n["id"])),
            "link": link,
            "eff": max(n["cost"], loc["cost"].get(n["name"], 0)),
            "wants": wants if wants != n["endpoint"] else "",
        }


def topology():
    """The whole mesh as its nodes report it: every node, and every link with state and latency."""
    loc, nodes, nets = local(), load(), load_nets()
    mesh, alive = loc["mesh"], live(nodes)
    out = {"nodes": [], "links": []}
    try:  # bytes over the last hour, as counted by the hub end: {(hub id, peer id): (received, sent)}
        db = stats_db()
        hour = {
            (r, p): (rx, tx)
            for r, p, rx, tx in db.execute(
                "SELECT reporter, peer, sum(rx), sum(tx) FROM link WHERE ts >= ? GROUP BY 1, 2",
                (int(time.time()) - 3600,),
            )
        }
        db.close()
    except sqlite3.Error:
        hour = {}
    for pk, n in sorted(alive.items(), key=lambda kv: kv[1]["id"]):
        mine = nets.get(pk, {})
        out["nodes"].append(
            {
                "id": n["id"],
                "name": n["name"],
                "hub": bool(n["endpoint"]),
                "me": pk == loc["pub"],
                "ip": str(router_ip(mesh, n["id"])),
                "endpoint": n["endpoint"],
                "subnets": n["subnets"],
                "vips": n["vips"],
                "admin": bool(mine.get("admin")),
                "labels": n.get("labels", []),
                "desc": n.get("desc", ""),
                "simple": bool(n.get("simple")),
            }
        )
        for hpk, h in alive.items():
            if not h["endpoint"] or hpk == pk or (n["endpoint"] and pk > hpk):  # hub pairs once
                continue
            theirs = nets.get(hpk, {})
            ms = mine.get("rtt", {}).get(str(h["id"]), theirs.get("rtt", {}).get(str(n["id"])))
            to_hub, from_hub = hour.get((h["id"], n["id"]), hour.get((n["id"], h["id"]), (None, None))[::-1])
            out["links"].append(
                {
                    "a": n["id"],
                    "b": h["id"],
                    "ms": ms,
                    "to_hub_1h": to_hub,
                    "from_hub_1h": from_hub,
                    "up": n["id"] in theirs.get("sees", []) or h["id"] in mine.get("sees", []),
                    "primary": not n["endpoint"]
                    and (
                        mine.get("primary") == h["id"]  # a simple client has one hub
                        or bool(n.get("simple"))
                        and n["id"] in theirs.get("sees", [])
                    ),
                }
            )
    return out


def warnings():
    """Things in the directory an operator should look at."""
    nodes, nets = load(), load_nets()
    alive, out = live(nodes), []
    for pk, n in nodes.items():
        if not n.get("gone") and pk not in alive:
            out.append(f"{n['name']} was given an id that is already in use; revoke it and invite it again")
    for pk, n in alive.items():
        for s in n["subnets"]:
            for k, o in alive.items():
                for t in nets.get(k, {}).get("nets", []) if k != pk else []:
                    if IPv4Network(s).subnet_of(IPv4Network(t)):
                        out.append(f"subnet {s} of {n['name']} lies inside {t}, a local network of {o['name']}")
    return out


def code_sha(path=None):
    """The version of a copy of this program: the SHA-256 of the file ('' if it is not there)."""
    try:
        with open(path or BIN, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


def release():
    """The version the admins published for the whole mesh -> {sha, source, time}, or None."""
    try:
        r = json.loads(load_conf()["release"]["value"])
        return r if re.fullmatch(r"[0-9a-f]{64}", str(r.get("sha"))) else None
    except (KeyError, ValueError, AttributeError):
        return None


def release_path(sha):
    return f"{DIR}/releases/{sha}.py"


def audit(event, **detail):
    """Append one line to this node's update log."""
    line = json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, **detail})
    with open(f"{DIR}/audit.log", "a") as f:
        f.write(line + "\n")
    log(f"audit: {line}")


def audit_tail(count=25):
    try:
        with open(f"{DIR}/audit.log") as f:
            return [json.loads(line) for line in f.readlines()[-count:]]
    except (OSError, ValueError):
        return []


def update_report():
    """How the last update went on this node, short enough to tell the mesh."""
    u = read_json("update.json", {})
    return (
        {"sha": str(u["sha"])[:12], "ok": bool(u.get("ok")), "why": str(u.get("why", ""))[:160]} if "sha" in u else None
    )


def wanted_code():
    """The published version, if this node neither runs it nor holds its file yet."""
    r = release()
    return r["sha"] if r and r["sha"] != code_sha() and not os.path.exists(release_path(r["sha"])) else None


def offer_code(sha):
    """A version's file for a peer that asks, compressed -> text or None."""
    path = release_path(sha) if os.path.exists(release_path(sha)) else BIN if code_sha() == sha else None
    if not path:
        return None
    with open(path, "rb") as f:
        return base64.b64encode(zlib.compress(f.read())).decode()


def store_code(sha, blob):
    """Keep a version's file received from a peer - only if it is exactly what the signed release names."""
    try:
        data = zlib.decompressobj().decompress(base64.b64decode(blob), 8 << 20)
    except Exception:
        return False
    if hashlib.sha256(data).hexdigest() != sha:
        return False
    os.makedirs(f"{DIR}/releases", mode=0o700, exist_ok=True)
    with open(os.open(release_path(sha) + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)
    os.replace(release_path(sha) + ".tmp", release_path(sha))
    return True


def software():
    """Everything the management page shows about versions: what runs where, the release, the log."""
    loc, nets, state_ = local(), load_nets(), read_json("update.json", {})
    return {
        "running": code_sha(),
        "release": release(),
        "previous": state_.get("was", "") if os.path.exists(release_path(state_.get("was", "-"))) else "",
        "nodes": [
            {
                "name": n["name"],
                "code": nets.get(pk, {}).get("code", ""),
                "update": nets.get(pk, {}).get("update") or {},
            }
            for pk, n in sorted(live(load()).items(), key=lambda kv: kv[1]["id"])
            if not n.get("simple")
        ],
        "log": audit_tail(),
        "mesh": loc["mesh"]["name"],
    }


def policy():
    """The mesh's firewall policy -> {"default": "allow" | "deny", "rules": [{from, to, ports, action}]}.
    Without one, everything is allowed."""
    try:
        p = json.loads(load_conf()["policy"]["value"])
        assert p["default"] in ("allow", "deny") and isinstance(p["rules"], list)
        return p
    except (KeyError, ValueError, AssertionError, TypeError):
        return {"default": "allow", "rules": []}


def parse_ports(text):
    """'tcp/22,443 udp/53 tcp/8000-8100' -> {"tcp": ["22", "443", "8000-8100"], "udp": ["53"]}; '' -> {} (all traffic)."""
    out = {}
    for item in text.split():
        proto, _, ports = item.partition("/")
        ok = (
            proto in ("tcp", "udp")
            and ports
            and all(
                re.fullmatch(r"\d{1,5}(-\d{1,5})?", p) and all(0 < int(n) < 65536 for n in p.split("-"))
                for p in ports.split(",")
            )
        )
        if not ok:
            sys.exit(f"cannot read ports {item!r}: write tcp/22, udp/53, tcp/80,443 or tcp/8000-8100")
        out.setdefault(proto, []).extend(ports.split(","))
    return out


def members(selector, mesh, alive):
    """The addresses a policy selector stands for -> list of networks, or None for everything.

    any                 everything
    nodes hubs clients  the addresses of all nodes / of the hubs / of the clients
    subnets             every network announced behind a node
    LABEL               the addresses of the nodes carrying that label - a group
    @NAME               the addresses of one node
    LABEL+net @NAME+net nodes+net ...   the networks behind those nodes instead
    10.1.1.0/24         a literal address or network
    """
    if selector == "any":
        return None
    try:
        return [IPv4Network(selector, strict=False)]
    except ValueError:
        pass
    name, plus, part = selector.partition("+")
    if name == "subnets" and not plus:
        name, part = "nodes", "net"
    if part not in ("", "net") or (plus and not part):
        sys.exit(f"cannot read selector {selector!r}")
    if name in ("nodes", "hubs", "clients"):
        chosen = [n for n in alive.values() if name == "nodes" or (name == "hubs") == bool(n["endpoint"])]
    elif name.startswith("@"):
        chosen = [n for n in alive.values() if n["name"] == name[1:]]
    elif re.fullmatch(LABEL_RE, name):
        chosen = [n for n in alive.values() if name in n.get("labels", [])]
    else:
        sys.exit(f"cannot read selector {selector!r}")
    nets = []
    for n in chosen:
        if part:
            for s in n["subnets"]:  # a wide announced network still does not make mesh nodes "subnet hosts"
                nets += carve(IPv4Network(s), [mesh_net(mesh), cluster_net(mesh)])
        else:
            nets += [IPv4Network(f"{ip}/32") for ip in [router_ip(mesh, n["id"])] + held_vips(mesh, n)]
    return list(collapse_addresses(nets))


def policy_ruleset(mesh, alive, pol):
    """The policy as nftables chains -> text, or '' when everything is allowed anyway.

    It judges new connections that enter or leave through the mesh interface: on the node they
    are for, on the hub that relays them, and on the gateway of a subnet. Answers to connections
    that were allowed always pass, and so do ping and the mesh's own two ports between nodes -
    a policy cannot cut the mesh's control traffic or the management page off.
    """
    if pol["default"] == "allow" and not pol["rules"]:
        return ""

    def match(field, nets):
        each = [str(n.network_address) if n.prefixlen == 32 else str(n) for n in nets or []]
        return f"ip {field} {{ {', '.join(each)} }} " if nets is not None else ""

    lines = [
        "ct state established,related accept",
        "meta l4proto icmp accept",
        f"{match('saddr', members('nodes', mesh, alive))}tcp dport {{ {GOSSIP_PORT}, {ADMIN_PORT} }} accept",
    ]
    for r in pol["rules"]:
        src, dst = members(r["from"], mesh, alive), members(r["to"], mesh, alive)
        if src == [] or dst == []:
            continue  # nobody answers to that selector right now
        verdict = "accept" if r["action"] == "allow" else "drop"
        for proto, ports in list(parse_ports(r.get("ports", "")).items()) or [(None, None)]:
            dport = f"{proto} dport {{ {', '.join(ports)} }} " if proto else ""
            lines.append(f"{match('saddr', src)}{match('daddr', dst)}{dport}counter {verdict}")
    if pol["default"] == "deny":
        lines.append("counter drop")
    rules = "\n".join("    " + line for line in lines)
    return (
        f"  chain mesh {{\n{rules}\n  }}\n"
        f'  chain input {{ type filter hook input priority 0; policy accept; iifname "{IFACE}" jump mesh; }}\n'
        f'  chain forward {{ type filter hook forward priority 0; policy accept; iifname "{IFACE}" jump mesh; '
        f'iifname != "{IFACE}" oifname "{IFACE}" jump mesh; }}\n'
    )


def gateway_ruleset(mesh, me, nat):
    """What makes a node a working gateway for the networks it announces -> nftables text, or ''.

    The hosts in such a network know nothing about the mesh: they would send their answers to
    their own default router, and the connection would never complete. So whatever comes out of
    the mesh for an announced network leaves the gateway with the gateway's own address there
    (masquerade); answers then come back to it and it hands them on. `meshbone local --nat off`
    is for networks whose router already has a route back to the mesh.
    """
    nets = [str(piece) for s in me["subnets"] for piece in carve(IPv4Network(s), [mesh_net(mesh), cluster_net(mesh)])]
    if not nets or not nat:
        return ""
    return (
        f'  chain gateway {{ type nat hook postrouting priority 100; policy accept; iifname "{IFACE}" '
        f'oifname != "{IFACE}" ip daddr {{ {", ".join(nets)} }} masquerade; }}\n'
    )


def mesh_table(*chains):
    """Our own nftables table holding these chains -> text that replaces it in one step, or None if empty."""
    body = "".join(chains)
    return f"table inet meshbone\ndelete table inet meshbone\ntable inet meshbone {{\n{body}}}\n" if body else None


# ==============================================================================
# MODEL, the machine side - reading and changing this host: WireGuard, routes, firewall,
# systemd units, ssh, and the wire protocol to other nodes.
# ==============================================================================


def run(*cmd, input=None, check=True):
    kw = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kw).stdout


def ip_json(*args):
    """`ip -j ...` as a list. Empty when there is nothing to list - or when an older ip answers a
    question about something that does not exist yet with words instead of JSON."""
    try:
        found = json.loads(run("ip", "-j", *args, check=False) or "[]")
        return found if isinstance(found, list) else []
    except ValueError:
        return []


def local_nets():
    """IPv4 networks this machine is directly attached to, outside the mesh."""
    out = set()
    for link in ip_json("-4", "addr", "show", "scope", "global"):
        if link["ifname"] in (IFACE, "mbvip"):
            continue
        for a in link.get("addr_info", []):
            if a.get("family") == "inet" and a["prefixlen"] < 32:
                out.add(str(IPv4Network(f"{a['local']}/{a['prefixlen']}", strict=False)))
    return sorted(out)[:64]


def sync_vips(want):
    """Hold exactly these cluster IPs on a dummy interface so local services can bind them."""
    links = ip_json("-4", "addr", "show", "dev", "mbvip")
    have = {a["local"] for l in links for a in l.get("addr_info", [])}
    if want and not links:
        run("ip", "link", "add", "mbvip", "type", "dummy", check=False)
        run("ip", "link", "set", "mbvip", "up", check=False)
    for ip in want - have:
        run("ip", "addr", "add", f"{ip}/32", "dev", "mbvip", check=False)
    for ip in have - want:
        run("ip", "addr", "del", f"{ip}/32", "dev", "mbvip", check=False)


def sync_routes(want, src):
    """Route exactly these prefixes into the mesh. Returns the ones this host already sends elsewhere.

    Packets that arrive *from* the mesh are looked up in a table of our own first, so relaying -
    a hub handing traffic on, a gateway receiving it - never depends on what else the host
    routes. For traffic the machine itself originates, the prefixes go into the main table,
    but only where nothing else claims them: a route somebody put there stays.
    """

    def held(*where):
        out = set()
        for r in ip_json("-4", "route", "show", *where):
            with contextlib.suppress(ValueError, KeyError, TypeError):
                out.add(IPv4Network(r["dst"]))
        return out

    ours = held("dev", IFACE, "table", str(MESH_TABLE))
    for p in want - ours:
        run("ip", "route", "replace", str(p), "dev", IFACE, "table", str(MESH_TABLE), check=False)
    for p in ours - want:
        run("ip", "route", "del", str(p), "table", str(MESH_TABLE), check=False)
    if not ip_json("rule", "show", "pref", str(MESH_TABLE)):
        run("ip", "rule", "add", "iif", IFACE, "lookup", str(MESH_TABLE), "pref", str(MESH_TABLE), check=False)

    main, elsewhere = held("dev", IFACE), set()
    for p in want - main:
        try:
            run("ip", "route", "add", str(p), "dev", IFACE, "src", str(src))
        except subprocess.CalledProcessError:
            elsewhere.add(p)  # already routed some other way on this machine: leave that alone
    for p in main - want:
        run("ip", "route", "del", str(p), "dev", IFACE, check=False)
    return sorted(str(p) for p in elsewhere)


def firewall(want):
    """Keep exactly our iptables rules in place (for hosts whose policy is DROP, e.g. with Docker)."""
    if not shutil.which("iptables"):
        return
    had = read_json("fw.json", [])
    for rule in had:
        if rule not in want:
            run("iptables", "-D", *rule, check=False)
    for rule in want:
        try:
            run("iptables", "-C", *rule)
        except subprocess.CalledProcessError:
            run("iptables", "-I", *rule, check=False)
    if had != want:
        write(f"{DIR}/fw.json", json.dumps(want))


def apply_table(text):
    """Load our nftables table (firewall policy, gateway NAT), or remove it. The table is ours alone; whatever other
    firewall the host has stays as it is, and both have to let a packet through."""
    path = f"{DIR}/policy.nft"
    if text is None:
        if os.path.exists(path):
            run("nft", "delete", "table", "inet", "meshbone", check=False)
            os.remove(path)
        return
    if not shutil.which("nft"):
        for cmd in (["apt-get", "install", "-y", "-q", "nftables"], ["dnf", "install", "-y", "nftables"]):
            if shutil.which(cmd[0]):
                subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True)
    try:
        in_place = os.path.exists(path) and read("policy.nft") == text.strip()
        if in_place and run("nft", "list", "table", "inet", "meshbone", check=False):
            return
        run("nft", "-f", "-", input=text)
        write(path, text)
    except (OSError, subprocess.CalledProcessError) as e:
        log(f"nftables table NOT applied (firewall policy, gateway NAT): {getattr(e, 'stderr', '') or e}")


def resolve(host, port):
    """host -> 'ip:port', or None while DNS is unavailable (e.g. early at boot)."""
    try:
        family, _, _, _, addr = socket.getaddrinfo(host.strip("[]"), port, type=socket.SOCK_DGRAM)[0]
    except OSError:
        return None
    return f"[{addr[0]}]:{port}" if family == socket.AF_INET6 else f"{addr[0]}:{port}"


def loosen_rp_filter():
    # the way out and the way back can use different hubs; strict reverse-path filtering would drop that
    try:
        path = "/proc/sys/net/ipv4/conf/all/rp_filter"
        if open(path).read().strip() == "1":
            open(path, "w").write("2")
    except OSError:
        pass


def handshakes():
    """{pubkey: seconds since the last WireGuard handshake}, for peers that ever had one."""
    out = {}
    for line in run("wg", "show", IFACE, "latest-handshakes", check=False).splitlines():
        pk, _, ts = line.partition("\t")
        if ts.strip().isdigit() and int(ts):
            out[pk] = time.time() - int(ts)
    return out


def probe(mesh, hubs):
    """{pubkey: rtt in ms} for the hubs that answer a ping through the tunnel."""

    def one(item):
        out = run(
            "ping",
            "-n",
            "-c",
            "2",
            "-i",
            "0.2",
            "-W",
            "1",
            "-I",
            IFACE,
            str(router_ip(mesh, item[1]["id"])),
            check=False,
        )
        times = [float(t) for t in re.findall(r"time=([\d.]+)", out)]
        return item[0], min(times) if times else None

    with ThreadPoolExecutor(PARALLEL) as pool:
        return {pk: rtt for pk, rtt in pool.map(one, hubs.items()) if rtt is not None}


def record_stats(my_id, alive, nets, rtt):
    """On a hub: add what crossed each link since the last run. Must never get in the tunnel's way."""
    try:
        last, now, bucket = read_json("counters.json", {}), {}, int(time.time()) // 60 * 60
        db = stats_db()
        for line in run("wg", "show", IFACE, "transfer", check=False).splitlines():
            pk, rx, tx = line.split("\t")
            if pk not in alive:
                continue
            now[pk] = [int(rx), int(tx)]
            was = last.get(pk, now[pk])  # a peer seen for the first time starts counting from here
            got, sent = (c - w if c >= w else c for c, w in zip(now[pk], was))  # counters restart with the interface
            ms = round(rtt[pk]) if pk in rtt else nets.get(pk, {}).get("rtt", {}).get(str(my_id))
            db.execute(
                "INSERT INTO link VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(reporter, peer, ts) DO UPDATE SET "
                "rx = rx + excluded.rx, tx = tx + excluded.tx, ms = excluded.ms",
                (my_id, alive[pk]["id"], bucket, got, sent, ms),
            )
            db.execute(
                "INSERT INTO total VALUES (?, ?, ?, ?) ON CONFLICT(reporter, peer) DO UPDATE SET "
                "rx = rx + excluded.rx, tx = tx + excluded.tx",
                (my_id, alive[pk]["id"], got, sent),
            )
        stats_upkeep(db)
        db.commit()
        db.close()
        write(f"{DIR}/counters.json", json.dumps(now))
    except (sqlite3.Error, ValueError) as e:
        log(f"stats: {e}")


def reconcile():
    """Make the WireGuard link, routes, cluster IPs and firewall match the directory. Idempotent."""
    loc, nodes, nets = local(), load(), load_nets()
    mesh, mypk, me = loc["mesh"], loc["pub"], nodes[loc["pub"]]
    alive = live(nodes)
    hub, active = bool(me["endpoint"]), mypk in alive
    my_ip = router_ip(mesh, me["id"])
    attached = local_nets()
    seen = handshakes()
    was = read_json("state.json", {})
    rtt = probe(mesh, {pk: n for pk, n in alive.items() if n["endpoint"] and pk != mypk}) if active else {}
    table, primary = plan(loc, nodes, nets, rtt, seen, was.get("primary")) if active else ({}, None)

    old = nets.get(mypk, {})
    ms = {str(alive[pk]["id"]): round(v) for pk, v in rtt.items()}
    told = old.get("rtt", {})
    if ms.keys() == told.keys() and all(abs(v - told[k]) <= max(3, v // 4) for k, v in ms.items()):
        ms = told  # ordinary jitter is not news worth telling the whole mesh
    report = {
        "nets": attached,
        "wants": loc.get("wants", ""),
        "rtt": ms,
        "sees": sorted(alive[pk]["id"] for pk in table if seen.get(pk, FRESH) < FRESH) if hub else [],
        "primary": alive[primary]["id"] if primary else None,
        "admin": os.path.exists(f"{DIR}/admin.key"),
        "code": code_sha()[:12],
        "update": update_report(),
    }
    if {k: v for k, v in old.items() if k != "seq"} != report:
        nets[mypk] = {**report, "seq": next_seq(nets.get(mypk, {}).get("seq", 0))}
        save_nets(nets)  # travels with the next gossip round

    sync_vips(set(held_vips(mesh, me)) if active else set())
    if not active:  # revoked: take everything down
        run("ip", "link", "del", IFACE, check=False)
        run("ip", "rule", "del", "pref", str(MESH_TABLE), check=False)
        firewall([])
        apply_table(None)
        for unit in ("meshbone-serve.socket", "meshbone-admin.socket"):
            run("systemctl", "stop", unit, check=False)
        return

    loosen_rp_filter()
    if hub or me["subnets"]:
        run("sysctl", "-qw", "net.ipv4.ip_forward=1", check=False)
    port = loc.get("listen_port") or (int(me["endpoint"].rpartition(":")[2]) if hub else None)
    conf = f"[Interface]\nPrivateKey = {loc['key']}\n" + (f"ListenPort = {port}\n" if port else "")
    underlay = []  # public addresses of the hubs we dial
    for pk, carried in sorted(table.items()):
        n = alive[pk]
        conf += (
            f"[Peer]\nPublicKey = {pk}\nPresharedKey = {pair_psk(loc, pk)}\n"
            f"AllowedIPs = {', '.join(str(p) for p in sorted(carried))}\n"
        )
        if n["endpoint"]:
            host, _, peer_port = n["endpoint"].rpartition(":")
            endpoint = resolve(host, int(peer_port))  # on DNS failure keep whatever endpoint wg has
            with contextlib.suppress(ValueError, AttributeError):
                underlay.append(IPv4Address(endpoint.rpartition(":")[0]))
            conf += (f"Endpoint = {endpoint}\n" if endpoint else "") + "PersistentKeepalive = 25\n"
    try:
        if not run("ip", "-j", "link", "show", "dev", IFACE, check=False):
            run("ip", "link", "add", IFACE, "type", "wireguard")
        run("wg", "syncconf", IFACE, "/dev/stdin", input=conf)
        run("ip", "addr", "replace", f"{my_ip}/32", "dev", IFACE)
        run("ip", "link", "set", "dev", IFACE, "mtu", str(loc.get("mtu") or 1420), "up")
        run("sysctl", "-qw", f"net.ipv4.conf.{IFACE}.rp_filter=2", check=False)
    except subprocess.CalledProcessError as e:
        log(f"{IFACE}: {e.stderr.strip()}")
    # Send the mesh ranges and other nodes' subnets into the tunnel. Not a subnet that lies within a
    # network this machine is attached to (the local one wins), and not one that contains a hub's
    # public address (the tunnel would try to carry itself). A subnet that merely *contains* a local
    # network is fine: the kernel prefers the more specific local route.
    routes = {mesh_net(mesh), cluster_net(mesh)} | {
        IPv4Network(s)
        for pk, n in alive.items()
        if pk != mypk
        for s in n["subnets"]
        if not any(IPv4Network(s).subnet_of(IPv4Network(l)) for l in attached)
        and not any(u in IPv4Network(s) for u in underlay)
    }
    elsewhere = sync_routes(routes, my_ip)
    if hub:
        record_stats(me["id"], alive, nets, rtt)

    serves_admin = hub or os.path.exists(f"{DIR}/admin.key")  # hubs: the map; admin nodes: also /admin
    rules = [["INPUT", "-i", IFACE, "-p", "tcp", "--dport", str(GOSSIP_PORT), "-j", "ACCEPT"]]
    if serves_admin:
        rules.append(["INPUT", "-i", IFACE, "-p", "tcp", "--dport", str(ADMIN_PORT), "-j", "ACCEPT"])
    if port:
        rules.append(["INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    if hub or me["subnets"]:
        rules += [["FORWARD", "-i", IFACE, "-j", "ACCEPT"], ["FORWARD", "-o", IFACE, "-j", "ACCEPT"]]
    firewall(rules)
    apply_table(mesh_table(policy_ruleset(mesh, alive, policy()), gateway_ruleset(mesh, me, loc.get("nat", True))))
    if {"primary": primary, "rtt": rtt, "elsewhere": elsewhere} != was:
        write(f"{DIR}/state.json", json.dumps({"primary": primary, "rtt": rtt, "elsewhere": elsewhere}))
    run("systemctl", "start", "meshbone-serve.socket", check=False)
    run("systemctl", "start" if serves_admin else "stop", "meshbone-admin.socket", check=False)


UNITS = {
    "meshbone.service": """[Unit]
Description=meshbone: reconcile links and sync the mesh directory
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={py} {bin} sync
TimeoutStartSec=120
""",
    "meshbone.timer": """[Unit]
Description=meshbone periodic sync

[Timer]
OnBootSec=3
OnCalendar=*:*:0/15
AccuracySec=1
RandomizedDelaySec=3

[Install]
WantedBy=timers.target
""",
    # the sockets are started and stopped by `meshbone sync`, only the timer is enabled
    "meshbone-serve.socket": """[Unit]
Description=meshbone directory exchange

[Socket]
ListenStream=0.0.0.0:{port}
Accept=yes
MaxConnections=32
IPAddressDeny=any
IPAddressAllow={net}
""",
    "meshbone-serve@.service": """[Unit]
Description=meshbone directory exchange (per connection)

[Service]
ExecStart={py} {bin} serve
StandardInput=socket
StandardOutput=journal
StandardError=journal
RuntimeMaxSec=60
""",
    "meshbone-admin.socket": """[Unit]
Description=meshbone admin page

[Socket]
ListenStream=0.0.0.0:{aport}
Accept=yes
MaxConnections=16
IPAddressDeny=any
IPAddressAllow={net} 127.0.0.0/8
""",
    "meshbone-admin@.service": """[Unit]
Description=meshbone admin page (per connection)

[Service]
ExecStart={py} {bin} admin
StandardInput=socket
StandardOutput=journal
StandardError=journal
RuntimeMaxSec=300
""",
}


def install_packages():
    try:
        ed25519()
        if shutil.which("wg"):
            return
    except ImportError:
        pass
    if shutil.which("apt-get"):
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(["apt-get", "update", "-q"], env=env)
        subprocess.run(
            ["apt-get", "install", "-y", "-q", "wireguard-tools", "python3-cryptography"], env=env, check=True
        )
    elif shutil.which("dnf"):
        subprocess.run(["dnf", "install", "-y", "wireguard-tools", "python3-cryptography"], check=True)
    else:
        sys.exit("unsupported package manager: install wireguard-tools and python3-cryptography, then re-run")


def install_self(dst):
    src = os.path.realpath(__file__)
    if src != dst:
        shutil.copy(src, dst)
        os.chmod(dst, 0o755)


def install_units():
    install_self(BIN)
    mesh = local()["mesh"]
    for name, text in UNITS.items():
        # sys.executable: /run is mounted noexec, so --once can't exec the script directly
        write(
            f"{UNIT_DIR}/{name}",
            text.format(
                py=sys.executable, bin=BIN, port=GOSSIP_PORT, net=mesh["net"], vip=admin_vip(mesh), aport=ADMIN_PORT
            ),
            0o644,
        )
    run("systemctl", "daemon-reload")
    run("systemctl", *(["start"] if ONCE else ["enable", "--now"]), "meshbone.timer")


def exchange(mesh, peer, msg):
    """Send our state to a peer over the mesh and return its state."""
    with socket.create_connection((str(router_ip(mesh, peer["id"])), GOSSIP_PORT), timeout=3) as s:
        s.sendall(json.dumps(msg).encode() + b"\n")
        return json.loads(s.makefile("rb").readline(8 << 20))


def deploy_key():
    """This node's own ssh identity, for logins it starts by itself -> (private key file, public key line).
    Made the first time it is needed; the public line is what a target has to accept."""
    path = f"{DIR}/deploy_key"
    if not os.path.exists(path):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"meshbone@{socket.gethostname()}", "-f", path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
        )
    with open(path + ".pub") as f:
        return path, f.read().strip()


@contextlib.contextmanager
def ssh_session(hops, identity=None):
    """Yields the argv prefix for ssh, with the identity that fits who is asking:

    - a private key handed over for this one deploy, if there is one;
    - else, for a person at a terminal (sudo), their own ssh: agent, keys, config, known_hosts;
    - else - the management page, on whichever node serves it - that node's own deploy key.

    Passwords in the destination are answered by an askpass helper, so they never appear on a
    command line. Whatever is written for the session is removed when it ends.
    """
    person = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
    person = None if person == "root" else person
    front, ssh = (["sudo", "-u", person] if person else []), ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    known = dict(sorted(((d, p) for d, p in hops if p), key=lambda kv: -len(kv[0])))
    box = tempfile.mkdtemp(prefix="meshbone-ssh-")
    try:
        if identity:
            write(f"{box}/key", identity.replace("\r\n", "\n").strip() + "\n")
            ssh += ["-i", f"{box}/key", "-o", "IdentitiesOnly=yes"]
        elif not person and os.geteuid() == 0:
            ssh += ["-i", deploy_key()[0]]
        if known:
            write(
                f"{box}/askpass",
                "#!/usr/bin/env python3\nimport sys\nfor who, password in %r.items():\n"
                "    if who in sys.argv[1]:\n        print(password)\n        break\n" % known,
                0o700,
            )
            front += ["env", f"SSH_ASKPASS={box}/askpass", "SSH_ASKPASS_REQUIRE=force"]
            ssh += ["-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=publickey,password"]
        if person:
            for path in [box] + [os.path.join(box, name) for name in os.listdir(box)]:
                shutil.chown(path, person)
        yield front + ssh
    finally:
        shutil.rmtree(box, ignore_errors=True)


def remote_argv(base, chain, command, jump, tty=False):
    """argv that runs a shell command on the last host of an ssh chain.

    jump: every hop is authenticated from this machine (ssh -J). Otherwise each
    hop logs in to the next one with its own keys, the way one would by hand -
    which is what works when only the jump host is authorized on the inner one.
    """
    opts = ["-t"] if tty else []
    if jump:
        return [*base, *opts, "-J", ",".join(chain[:-1]), chain[-1], command]
    for hop in reversed(chain[1:]):
        command = shlex.join(["ssh", *opts, hop, command])
    return [*base, *opts, chain[0], command]


def qr(text, kind):
    """A QR code of text: kind 'SVG' for a page, 'ansiutf8' for a terminal. None without qrencode."""
    if not shutil.which("qrencode"):
        installer = [["apt-get", "install", "-y", "-q", "qrencode"], ["dnf", "install", "-y", "qrencode"]]
        for cmd in installer:
            if shutil.which(cmd[0]):
                subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True)
    try:
        return run("qrencode", "-t", kind, "-m", "2", "-o", "-", input=text)
    except (OSError, subprocess.CalledProcessError):
        return None


def script(path, *args, timeout=240):
    """Run another copy of this program -> (succeeded, the end of what it said)."""
    try:
        r = subprocess.run(
            [sys.executable, path, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode == 0, (r.stdout + r.stderr).strip()[-600:]
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def reachable():
    """Is this node in touch with the mesh right now? A hub: with any peer. A client: with any hub."""
    loc, alive = local(), live(load())
    if loc["pub"] not in alive:
        return False
    others = {pk: n for pk, n in alive.items() if pk != loc["pub"]}
    if alive[loc["pub"]]["endpoint"]:
        return not others or any(age < FRESH for pk, age in handshakes().items() if pk in others)
    hubs = {pk: n for pk, n in others.items() if n["endpoint"]}
    return not hubs or bool(probe(loc["mesh"], hubs))


def fetch_source(url, ref):
    """meshbone.py from a GitHub repository (https://github.com/OWNER/REPO, at a branch, tag or
    commit) or from a direct https link -> (bytes, where exactly it came from)."""
    m = re.fullmatch(r"https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?", url)
    if m:
        url = (
            f"https://raw.githubusercontent.com/{m[1]}/{m[2]}/{urllib.parse.quote(ref or 'main', safe='')}/meshbone.py"
        )
    elif not url.startswith("https://"):
        sys.exit("the source must be https://github.com/OWNER/REPO or a direct https:// link to meshbone.py")
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read(8 << 20), url
    except (OSError, ValueError) as e:
        sys.exit(f"cannot fetch {url}: {e}")


# ==============================================================================
# VIEW - turning model data into something to look at: HTML pages, Prometheus text,
# terminal output. Views only format what they are given; they read and change nothing.
# ==============================================================================


PAGE_STYLE = """<style>
:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1c1c1a;--muted:#6f6f68;--line:#deded7;--ok:#2f7d4f;--bad:#c2413a;--hub:#2d5fa8;--client:#8a8a80;--s1:#2a78d6;--s2:#eb6834}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecece6;--muted:#9a9a90;--line:#34342f;--ok:#5fbf85;--bad:#f07a70;--hub:#7fa9ea;--client:#8f8f86;--s1:#3987e5;--s2:#d95926}}
body{font:14px/1.45 system-ui,sans-serif;margin:0;padding:20px;background:var(--bg);color:var(--fg);max-width:1100px;margin-inline:auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}h3{font-size:14px;margin:0}p{margin:4px 0;color:var(--muted)}a{color:var(--hub)}
nav{margin:0 0 14px;display:flex;gap:16px;flex-wrap:wrap}nav b{color:var(--fg)}
canvas{width:100%;display:block}#map{border:1px solid var(--line);border-radius:8px;margin:14px 0 6px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 10px;text-align:left;white-space:nowrap}
th{font-weight:600;color:var(--muted);font-size:12px}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}code,td.m{font-family:ui-monospace,monospace;font-size:13px}
input{font:inherit;padding:3px 5px;width:10em}input[name=cost]{width:4em}input.w{width:16em}button{font:inherit;padding:3px 10px}button.on{font-weight:600;border-color:var(--fg)}
pre{padding:10px;border:1px solid var(--line);border-radius:6px;white-space:pre-wrap}.key span,.tag{display:inline-block;margin-right:16px}
.tag{margin-right:4px;padding:0 6px;border:1px solid var(--line);border-radius:10px;font-size:12px}
.bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0}.bar span{color:var(--muted);margin-left:10px}.bar input{width:13em}
.chart{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:12px 0;position:relative}.chart p{font-size:12px}
.k{display:inline-block;width:14px;height:0;border-top:2px solid;vertical-align:middle;margin:0 5px 0 12px}
#tip{position:fixed;pointer-events:none;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 9px;font-size:12px;box-shadow:0 2px 8px #0003;display:none}
#tip b{font-variant-numeric:tabular-nums}form.grid{display:flex;gap:6px;flex-wrap:wrap}
</style>"""


MAP_SCRIPT = """<script>
const T = __DATA__, cv = document.getElementById('map'), g = cv.getContext('2d');
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function draw() {
  const W = cv.clientWidth, H = Math.max(380, Math.min(680, W * 0.62)), k = devicePixelRatio || 1;
  cv.width = W * k; cv.height = H * k; cv.style.height = H + 'px'; g.setTransform(k, 0, 0, k, 0, 0); g.clearRect(0, 0, W, H);
  const hubs = T.nodes.filter(n => n.hub), pos = {}, cx = W / 2, cy = H / 2;
  const sendsVia = n => { const l = T.links.find(l => l.a === n.id && l.primary); return l ? hubs.findIndex(h => h.id === l.b) : hubs.length; };
  const clients = T.nodes.filter(n => !n.hub).sort((a, b) => sendsVia(a) - sendsVia(b) || a.id - b.id);
  const r1 = hubs.length > 1 ? Math.min(W, H) * 0.24 : 0;
  hubs.forEach((n, i) => { const a = 2 * Math.PI * i / hubs.length - Math.PI / 2; pos[n.id] = [cx + r1 * Math.cos(a), cy + r1 * Math.sin(a)]; });
  clients.forEach((n, i) => { const a = 2 * Math.PI * (i + 0.5) / clients.length - Math.PI / 2; pos[n.id] = [cx + W * 0.36 * Math.cos(a), cy + H * 0.33 * Math.sin(a)]; });
  g.textAlign = 'center'; g.textBaseline = 'middle';
  for (const l of T.links) {                       // links first, nodes on top
    const [x1, y1] = pos[l.a], [x2, y2] = pos[l.b], hubLink = hubs.some(h => h.id === l.a);
    g.beginPath(); g.moveTo(x1, y1); g.lineTo(x2, y2);
    g.strokeStyle = css(l.up ? '--ok' : '--bad'); g.setLineDash(l.up ? [] : [5, 5]);
    g.lineWidth = l.up && (hubLink || l.primary) ? 2.5 : 1; g.globalAlpha = !l.up ? 0.4 : !hubLink && !l.primary ? 0.45 : 1; g.stroke();
    g.globalAlpha = 1; g.setLineDash([]);
    if (l.up && l.ms != null) {                   // the ping sits near the client end, clear of the middle
      g.font = '12px system-ui, sans-serif';
      const label = l.ms + ' ms', t = hubLink ? 0.5 : 0.3, mx = x1 + (x2 - x1) * t, my = y1 + (y2 - y1) * t, w = g.measureText(label).width + 8;
      g.fillStyle = css('--bg'); g.fillRect(mx - w / 2, my - 8, w, 16); g.fillStyle = css('--fg'); g.fillText(label, mx, my);
    }
  }
  for (const n of T.nodes) {
    const [x, y] = pos[n.id], r = n.hub ? 15 : 9, linked = n.hub || T.links.some(l => l.a === n.id && l.up);
    g.beginPath(); g.arc(x, y, r, 0, 2 * Math.PI); g.fillStyle = css(n.hub ? '--hub' : linked ? '--client' : '--bg'); g.fill();
    g.lineWidth = n.me ? 3 : 1.5; g.strokeStyle = css(n.me ? '--fg' : n.hub ? '--hub' : '--client'); g.stroke();
    if (n.admin) { g.beginPath(); g.arc(x, y, r + 4, 0, 2 * Math.PI); g.lineWidth = 1; g.setLineDash([2, 3]); g.strokeStyle = css('--fg'); g.stroke(); g.setLineDash([]); }
    const up = y < cy - 1 ? -1 : 1, lines = [n.name, n.ip].concat(n.subnets.map(s => 'net ' + s), n.vips.map(v => 'vip ' + v));
    lines.forEach((t, i) => {
      g.font = (i ? '11px ui-monospace, monospace' : '600 13px system-ui, sans-serif');
      const ty = y + up * (r + 13) + (up > 0 ? i : i - lines.length + 1) * 14, w = g.measureText(t).width + 6;
      g.fillStyle = css('--bg'); g.globalAlpha = 0.85; g.fillRect(x - w / 2, ty - 7, w, 14); g.globalAlpha = 1;
      g.fillStyle = css(i ? '--muted' : '--fg'); g.fillText(t, x, ty);
    });
  }
}
draw(); addEventListener('resize', draw); matchMedia('(prefers-color-scheme: dark)').addEventListener('change', draw);
</script>"""


TRAFFIC_SCRIPT = """<script>
const $ = s => document.querySelector(s), css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const PRESETS = [['1 h', 3600], ['6 h', 21600], ['24 h', 86400], ['7 d', 604800], ['30 d', 2592000], ['90 d', 7776000]];
let range = {span: 3600}, D = null, charts = [];
const rate = v => { v = Math.abs(v); const u = ['b/s', 'kb/s', 'Mb/s', 'Gb/s']; let i = 0; while (v >= 1000 && i < 3) { v /= 1000; i++; } return (v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i]; };
const size = v => { const u = ['B', 'kB', 'MB', 'GB', 'TB']; let i = 0; while (v >= 1000 && i < 4) { v /= 1000; i++; } return (v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i]; };
const clock = (t, long) => { const d = new Date(t * 1000), p = n => String(n).padStart(2, '0'), hm = p(d.getHours()) + ':' + p(d.getMinutes());
  return long || D.to - D.from > 86400 ? (d.getMonth() + 1) + '/' + d.getDate() + ' ' + hm : hm; };
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };
const local = t => { const d = new Date(t * 1000 - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); };

function bar() {
  const b = $('#bar'); b.textContent = '';
  for (const [name, span] of PRESETS) {
    const x = el('button', name, range.span === span ? 'on' : ''); x.onclick = () => { range = {span}; load(); }; b.append(x);
  }
  const f = el('input'), t = el('input'), go = el('button', 'show'); f.type = t.type = 'datetime-local';
  if (D) { f.value = local(D.from); t.value = local(D.to); }
  go.onclick = () => { const a = Date.parse(f.value) / 1000, z = Date.parse(t.value) / 1000; if (a < z) { range = {from: a, to: z}; load(); } };
  b.append(el('span', 'or from'), f, el('span', 'to'), t, go);
}

async function load() {
  const now = Math.floor(Date.now() / 1000), to = range.to || now, from = range.from || to - range.span;
  D = await (await fetch('/api/traffic?from=' + from + '&to=' + to)).json();
  const first = Math.min(...D.links.flatMap(l => l.points.map(p => p[0])));   // history may be younger than the window
  D.since = isFinite(first) && first - D.from > (D.to - D.from) * 0.2 ? first : null; if (D.since) D.from = D.since - D.step;
  bar(); render();
}

function render() {
  const sum = $('#sum'), box = $('#charts'); sum.textContent = ''; box.textContent = ''; charts = [];
  $('#note').textContent = D.links.length ? 'one point = ' + (D.step >= 3600 ? D.step / 3600 + ' h' : D.step / 60 + ' min') + ' average' + (D.since ? ' \u00b7 nothing was recorded before ' + clock(D.since, true) + ', so the charts start there' : '') : 'no traffic recorded in this period';
  const head = el('tr'); ['link', 'to the hub', 'from the hub', 'peak', 'average ping'].forEach((h, i) => head.append(el('th', h, i ? 'n' : ''))); sum.append(head);
  const rows = D.links.map(l => {
    const a = D.names[l.peer] || '#' + l.peer, b = D.names[l.reporter] || '#' + l.reporter, bps = l.points.map(p => [p[0], p[1] * 8 / D.step, p[2] * 8 / D.step]);
    const rx = l.points.reduce((s, p) => s + p[1], 0), tx = l.points.reduce((s, p) => s + p[2], 0), ms = l.points.filter(p => p[3] != null);
    return {a, b, bps, rx, tx, peak: Math.max(0, ...bps.map(p => Math.max(p[1], p[2]))), ms: ms.length ? ms.reduce((s, p) => s + p[3], 0) / ms.length : null};
  }).sort((x, y) => y.rx + y.tx - x.rx - x.tx);
  for (const r of rows) {
    const tr = el('tr'); tr.append(el('td', r.a + ' \\u21c4 ' + r.b), el('td', size(r.rx), 'n'), el('td', size(r.tx), 'n'), el('td', rate(r.peak), 'n'), el('td', r.ms == null ? '-' : r.ms.toFixed(0) + ' ms', 'n')); sum.append(tr);
    const card = el('div', null, 'chart'), cv = el('canvas'), key = el('p');
    const k1 = el('i', null, 'k'), k2 = el('i', null, 'k'); k1.style.borderColor = css('--s1'); k2.style.borderColor = css('--s2');
    key.append(k1, r.a + ' \\u2192 ' + r.b + ' (' + size(r.rx) + ')', k2, r.b + ' \\u2192 ' + r.a + ' (' + size(r.tx) + ')');
    card.append(el('h3', r.a + ' \\u21c4 ' + r.b), key, cv); box.append(card); charts.push([cv, r]);
  }
  charts.forEach(c => draw(...c));
}

function draw(cv, r, hover) {
  const W = cv.clientWidth, H = 190, k = devicePixelRatio || 1, g = cv.getContext('2d'), L = 62, R = 8, T = 8, B = 22;
  cv.width = W * k; cv.height = H * k; cv.style.height = H + 'px'; g.setTransform(k, 0, 0, k, 0, 0); g.clearRect(0, 0, W, H);
  let top = Math.max(1000, r.peak), mag = Math.pow(10, Math.floor(Math.log10(top))); top = Math.ceil(top / mag) * mag;   // a clean axis maximum
  const mid = T + (H - T - B) / 2, x = t => L + (t - D.from) / (D.to - D.from) * (W - L - R), y = v => mid - v / top * (H - T - B) / 2;
  g.font = '11px system-ui, sans-serif'; g.textBaseline = 'middle'; g.lineWidth = 1;
  for (const v of [top, top / 2, 0, -top / 2, -top]) {            // one axis: up is towards the hub, down is from it
    g.strokeStyle = css('--line'); g.beginPath(); g.moveTo(L, y(v)); g.lineTo(W - R, y(v)); g.stroke();
    g.fillStyle = css('--muted'); g.textAlign = 'right'; g.fillText(rate(v), L - 8, y(v));
  }
  g.textAlign = 'center';
  for (let i = 0; i <= 4; i++) { const t = D.from + (D.to - D.from) * i / 4; g.fillText(clock(t), Math.min(W - R - 22, Math.max(L + 22, x(t))), H - 9); }
  [[1, '--s1', 1], [2, '--s2', -1]].forEach(([col, color, sign]) => {
    let seg = [];
    const flush = () => {
      if (!seg.length) return;
      g.beginPath(); seg.forEach((p, i) => i ? g.lineTo(x(p[0]), y(sign * p[col])) : g.moveTo(x(p[0]), y(sign * p[col])));
      g.strokeStyle = css(color); g.lineWidth = 2; g.lineJoin = g.lineCap = 'round'; g.stroke();
      g.lineTo(x(seg[seg.length - 1][0]), mid); g.lineTo(x(seg[0][0]), mid); g.closePath(); g.globalAlpha = 0.1; g.fillStyle = css(color); g.fill(); g.globalAlpha = 1; seg = [];
    };
    r.bps.forEach((p, i) => { if (i && p[0] - r.bps[i - 1][0] > D.step * 1.5) flush(); seg.push(p); }); flush();   // a gap means nobody was measuring
  });
  if (hover) {
    g.strokeStyle = css('--muted'); g.lineWidth = 1; g.beginPath(); g.moveTo(x(hover[0]), T); g.lineTo(x(hover[0]), H - B); g.stroke();
    [[1, '--s1', 1], [2, '--s2', -1]].forEach(([col, color, sign]) => { g.beginPath(); g.arc(x(hover[0]), y(sign * hover[col]), 4, 0, 7); g.fillStyle = css(color); g.fill(); g.lineWidth = 2; g.strokeStyle = css('--bg'); g.stroke(); });
  }
  cv.onpointermove = e => {
    if (!r.bps.length) return;
    const box = cv.getBoundingClientRect(), t = D.from + (e.clientX - box.left - L) / (W - L - R) * (D.to - D.from);
    const p = r.bps.reduce((a, b) => Math.abs(b[0] - t) < Math.abs(a[0] - t) ? b : a); draw(cv, r, p);
    const tip = $('#tip'); tip.textContent = '';
    const row = (color, value, label) => { const d = el('div'), key = el('i', null, 'k'); key.style.borderColor = css(color); key.style.marginLeft = 0; d.append(key, el('b', value), ' ' + label); return d; };
    tip.append(el('div', clock(p[0], true)), row('--s1', rate(p[1]), r.a + ' \\u2192 ' + r.b), row('--s2', rate(p[2]), r.b + ' \\u2192 ' + r.a));
    tip.style.display = 'block'; tip.style.left = Math.min(innerWidth - tip.offsetWidth - 8, e.clientX + 14) + 'px'; tip.style.top = e.clientY + 14 + 'px';
  };
  cv.onpointerleave = () => { $('#tip').style.display = 'none'; draw(cv, r); };
}
load(); setInterval(() => { if (range.span) load(); }, 60000); addEventListener('resize', () => charts.forEach(c => draw(...c)));
</script>"""


SIGN_SCRIPT = """<script>
// Ed25519 signing in the page: the browser offers no crypto API over plain http, and the key must not leave it.
const big = b => b.reduce((n, x, i) => n + (BigInt(x) << BigInt(8 * i)), 0n);
const bytes = (n, len) => Uint8Array.from({length: len}, (_, i) => Number((n >> BigInt(8 * i)) & 255n));
const cat = (...p) => Uint8Array.from(p.flatMap(x => [...x]));
const M = (1n << 64n) - 1n, rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M;
const root = (n, k) => { let x = 1n << BigInt(Math.ceil(n.toString(2).length / k)); for (;;) { const y = ((BigInt(k) - 1n) * x + n / x ** BigInt(k - 1)) / BigInt(k); if (y >= x) return x; x = y; } };
const primes = []; for (let n = 2; primes.length < 80; n++) if (primes.every(p => n % p)) primes.push(n);
const K = primes.map(p => root(BigInt(p) << 192n, 3) & M), H0 = primes.slice(0, 8).map(p => root(BigInt(p) << 128n, 2) & M);
function sha512(m) {
  const l = m.length, n = Math.ceil((l + 17) / 128) * 128, p = new Uint8Array(n); p.set(m); p[l] = 0x80;
  for (let i = 0; i < 8; i++) p[n - 1 - i] = Number((BigInt(l) * 8n >> BigInt(8 * i)) & 255n);
  let h = H0.slice();
  for (let o = 0; o < n; o += 128) {
    const w = []; for (let i = 0; i < 16; i++) { let v = 0n; for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(p[o + 8 * i + j]); w.push(v); }
    for (let i = 16; i < 80; i++) { const a = w[i - 15], b = w[i - 2];
      w.push((w[i - 16] + (rotr(a, 1n) ^ rotr(a, 8n) ^ (a >> 7n)) + w[i - 7] + (rotr(b, 19n) ^ rotr(b, 61n) ^ (b >> 6n))) & M); }
    let [a, b, c, d, e, f, g, y] = h;
    for (let i = 0; i < 80; i++) {
      const t1 = (y + (rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n)) + ((e & f) ^ (~e & M & g)) + K[i] + w[i]) & M;
      const t2 = ((rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n)) + ((a & b) ^ (a & c) ^ (b & c))) & M;
      y = g; g = f; f = e; e = (d + t1) & M; d = c; c = b; b = a; a = (t1 + t2) & M;
    }
    h = [a, b, c, d, e, f, g, y].map((v, i) => (v + h[i]) & M);
  }
  const out = new Uint8Array(64); h.forEach((v, i) => { for (let j = 0; j < 8; j++) out[8 * i + j] = Number((v >> BigInt(56 - 8 * j)) & 255n); }); return out;
}
const P = 2n ** 255n - 19n, L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;
const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
const inv = a => pow(a, P - 2n), D = mod(-121665n * inv(121666n)), By = mod(4n * inv(5n));
const Bx = (() => { const x2 = mod((By * By - 1n) * inv(D * By * By + 1n)); let x = pow(x2, (P + 3n) / 8n); if (mod(x * x - x2) !== 0n) x = mod(x * pow(2n, (P - 1n) / 4n)); return x & 1n ? P - x : x; })();
const add = ([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) => { const A = mod((Y1 - X1) * (Y2 - X2)), B = mod((Y1 + X1) * (Y2 + X2)), C = mod(2n * D * T1 * T2), Q = mod(2n * Z1 * Z2), E = B - A, F = Q - C, G = Q + C, H = B + A; return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)]; };
const mul = (k, p) => { let r = [0n, 1n, 1n, 0n]; while (k > 0n) { if (k & 1n) r = add(r, p); p = add(p, p); k >>= 1n; } return r; };
const enc = ([X, Y, Z]) => { const zi = inv(Z); return bytes(mod(Y * zi) | ((mod(X * zi) & 1n) << 255n), 32); };
const BASE = [Bx, By, 1n, mod(Bx * By)];
function sign(msg, seed) {
  const h = sha512(seed), a = (big(h.slice(0, 32)) & ((1n << 254n) - 8n)) | (1n << 254n), pub = enc(mul(a, BASE));
  const r = mod(big(sha512(cat(h.slice(32), msg))), L), R = enc(mul(r, BASE));
  return {pub, sig: cat(R, bytes(mod(r + mod(big(sha512(cat(R, pub, msg))), L) * a, L), 32))};
}
const b64 = b => btoa(String.fromCharCode(...b));
</script>"""


LOGIN_SCRIPT = """<script>
const S = __DATA__, form = document.getElementById('login'), key = document.getElementById('key');
const fail = t => { document.getElementById('why').textContent = t; return false; };
form.onsubmit = e => {
  e.preventDefault();
  let seed = [];
  try { seed = Uint8Array.from(atob(key.value.trim()), c => c.charCodeAt(0)); } catch (x) {}
  if (seed.length !== 32) return fail('that is not an admin key');
  if (Math.abs(Date.now() / 1000 - S.now) > 300) return fail('the clock of this node and yours differ by more than five minutes');
  const minutes = Math.max(1, Math.min(S.max, +form.minutes.value || 30)), nbf = S.now - 60, exp = S.now + minutes * 60;
  const made = sign(new TextEncoder().encode(['meshbone-session', S.mesh, S.admin_pub, S.pub, nbf, exp].join('\\n')), seed);
  if (b64(made.pub) !== S.admin_pub) return fail('this key does not belong to this mesh');
  form.nbf.value = nbf; form.exp.value = exp; form.sig.value = b64(made.sig); key.value = '';
  form.submit();   // only the token goes to the node; the key field has no name and was just emptied
};
</script>"""


def esc(v):
    return html.escape(str(v), quote=True)


def human(n):
    if n is None:
        return "-"
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" or n >= 100 else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def tags(labels):
    return "".join(f"<span class=tag>{esc(l)}</span>" for l in labels) or "-"


def page_head(mesh, title, here):
    tabs = [("/", "map"), ("/traffic", "traffic"), ("/metrics", "metrics"), ("/api", "API")]
    return (
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)} - mesh {esc(mesh['name'])}</title>{PAGE_STYLE}<nav><b>mesh {esc(mesh['name'])}</b>"
        + "".join(f"<b>{t}</b>" if t == here else f"<a href='{u}'>{t}</a>" for u, t in tabs)
        + "</nav>"
    )


def view_map(mesh, topo):
    """The whole mesh at a glance: the graph, the nodes, the links."""
    here = next(n for n in topo["nodes"] if n["me"])
    names = {n["id"]: n["name"] for n in topo["nodes"]}
    out = [
        page_head(mesh, "map", "map").replace("<title>", "<meta http-equiv=refresh content=20><title>"),
        f"<p>nodes <code>{esc(mesh['net'])}</code> &middot; cluster IPs <code>{esc(mesh['cluster_net'])}</code> &middot; "
        f"this page is <code>{admin_vip(mesh)}</code> on every hub, answered now by <b>{esc(here['name'])}</b></p>"
        "<canvas id=map></canvas><p class=key><span>large dot: hub</span><span>small dot: client</span>"
        "<span>thick line: hub-to-hub, or the hub a client sends through</span><span>thin line: standby link</span>"
        "<span>faint dashed red: no link</span><span>number: ping across that link</span>"
        "<span>dotted ring: admin node</span><span>bold outline: the node answering</span></p>",
        "<h2>nodes</h2><div class=scroll><table><tr><th>role<th>name<th>address<th>endpoint<th>subnets"
        "<th>sends through<th>seen by<th>labels<th>description",
    ]
    for n in topo["nodes"]:
        mine = [l for l in topo["links"] if l["a"] == n["id"] or (n["hub"] and l["b"] == n["id"])]
        via = next((names[l["b"]] for l in mine if l["primary"] and l["a"] == n["id"]), "")
        seen_by = ", ".join(sorted(names[l["b"] if l["a"] == n["id"] else l["a"]] for l in mine if l["up"])) or "nobody"
        role = (
            ("hub" if n["hub"] else "client")
            + (" · admin" if n["admin"] else "")
            + (" · simple" if n["simple"] else "")
        )
        out.append(
            f"<tr><td>{role}<td><b>{esc(n['name'])}</b><td class=m>{n['ip']}<td class=m>{esc(n['endpoint'] or 'behind NAT')}"
            f"<td class=m>{esc(' '.join(n['subnets'] + ['vip ' + v for v in n['vips']]) or '-')}"
            f"<td>{esc(via or ('-' if n['hub'] else 'not connected'))}<td>{esc(seen_by)}<td>{tags(n['labels'])}"
            f"<td>{esc(n['desc'] or '-')}"
        )
    out.append(
        "</table></div><h2>links</h2><div class=scroll><table><tr><th>from<th>to<th>state<th class=n>ping"
        "<th class=n>sent, last hour<th class=n>received, last hour<th>"
    )
    for l in topo["links"]:
        out.append(
            f"<tr><td>{esc(names[l['a']])}<td>{esc(names[l['b']])}<td>{'up' if l['up'] else 'down'}"
            f"<td class=n>{str(l['ms']) + ' ms' if l['ms'] is not None else '-'}"
            f"<td class=n>{human(l['to_hub_1h'])}<td class=n>{human(l['from_hub_1h'])}<td>{'in use' if l['primary'] else ''}"
        )
    admins = " &middot; ".join(
        f"<a href='http://{n['ip']}:{ADMIN_PORT}/admin'>{esc(n['name'])}</a>" for n in topo["nodes"] if n["admin"]
    )
    out.append(
        "</table></div><p>Sent and received are from the first node's side; <a href=/traffic>graphs over time</a>.</p>"
        f"<h2>manage</h2><p>{admins or 'no admin node is online'}</p>"
        "<p>Changes are signed on an admin node; hubs only show the mesh.</p>"
    )
    out.append(MAP_SCRIPT.replace("__DATA__", json.dumps(topo).replace("</", "<\\/")))
    return "".join(out).encode()


def view_traffic(mesh):
    return (
        page_head(mesh, "traffic", "traffic")
        + "<p>Bytes carried by each link, as counted by the hub at one end. Traffic between two clients shows up on "
        "both of their links to the hub that relayed it.</p><div class=bar id=bar></div><p id=note></p>"
        "<div class=scroll><table id=sum></table></div><div id=charts></div><div id=tip></div>" + TRAFFIC_SCRIPT
    ).encode()


def view_api(mesh):
    base = f"http://{admin_vip(mesh)}:{ADMIN_PORT}"
    paths = [
        (
            "/api/nodes",
            "every node: name, role, ip, endpoint, subnets, vips, labels, desc, admin. Filters: <code>?label=X</code> "
            "(repeatable, all must match), <code>?role=hub|client</code>, <code>?name=N</code>",
        ),
        ("/api/topology", "nodes plus every link with state, ping and whether it is in use (what the map draws)"),
        ("/api/policy", "the firewall policy: the default and the ordered rules"),
        (
            "/api/traffic",
            "per-link byte counts in buckets. <code>?from=UNIX&amp;to=UNIX</code> (default: last 6 h), "
            "<code>&amp;step=SECONDS</code> (default: about 240 points)",
        ),
        (
            "/metrics",
            f"the same in Prometheus text format; also reachable as <code>http://{metrics_vip(mesh)}:{ADMIN_PORT}/metrics</code>",
        ),
    ]
    return (
        page_head(mesh, "API", "API")
        + f"<p>Read-only, JSON, no login, reachable only from inside the mesh. Any hub answers on <code>{base}</code>.</p>"
        "<div class=scroll><table><tr><th>path<th>returns"
        + "".join(f"<tr><td class=m><a href='{p}'>{p}</a><td style='white-space:normal'>{d}" for p, d in paths)
        + "</table></div>"
    ).encode()


def view_login(mesh, sid, pub, now, note):
    """Ask for the admin key - and turn it, inside the browser, into a token for this session only."""
    facts = {
        "sid": sid,
        "pub": pub,
        "now": now,
        "mesh": mesh["name"],
        "admin_pub": mesh["admin_pub"],
        "max": SESSION_MAX // 60,
    }
    return (
        page_head(mesh, "manage", "")
        + "<h1>manage</h1><p>Paste the mesh's admin key. It stays in this browser: the page uses it once to sign a token "
        "that lets this node sign changes for a limited time, and only the token is sent.</p>"
        + (f"<pre>{esc(note)}</pre>" if note else "")
        + "<form id=login method=post action=/admin/login class=grid>"
        f'<input type=hidden name=sid value="{esc(sid)}"><input type=hidden name=nbf><input type=hidden name=exp>'
        "<input type=hidden name=sig><input id=key type=password class=w placeholder='admin key' autocomplete=off required> "
        "<label>valid for <input name=minutes value=30 style='width:4em'> minutes</label> "
        "<button>sign in</button></form><p id=why style='color:var(--bad)'></p>"
        "<p>The token only works on this node, from your address, until it expires. Changes made with it are signed by "
        "a key that exists only for this session.</p>"
        + SIGN_SCRIPT
        + LOGIN_SCRIPT.replace("__DATA__", json.dumps(facts).replace("</", "<\\/"))
    ).encode()


def view_metrics(topo, totals):
    """The mesh in Prometheus text format."""
    out, names = [], {n["id"]: n["name"] for n in topo["nodes"]}

    def quoted(v):
        return str(v).replace("\\", "\\\\").replace('"', '\\"')

    def family(name, kind, text, samples):
        out.extend([f"# HELP {name} {text}", f"# TYPE {name} {kind}"])
        for labels, value in samples:  # no backslashes inside f-strings: nodes may run Python older than 3.12
            out.append("%s{%s} %s" % (name, ",".join('%s="%s"' % (k, quoted(v)) for k, v in labels.items()), value))

    family(
        "meshbone_node_info",
        "gauge",
        "One per node in the mesh.",
        [
            (
                {
                    "node": n["name"],
                    "role": "hub" if n["hub"] else "client",
                    "ip": n["ip"],
                    "labels": ",".join(n["labels"]),
                },
                1,
            )
            for n in topo["nodes"]
        ],
    )
    pairs = [({"from": names[l["a"]], "to": names[l["b"]]}, l) for l in topo["links"]]
    family(
        "meshbone_link_up",
        "gauge",
        "1 if the hub at the far end currently sees the node.",
        [(k, int(l["up"])) for k, l in pairs],
    )
    family(
        "meshbone_link_in_use",
        "gauge",
        "1 if the client sends through this hub.",
        [(k, int(l["primary"])) for k, l in pairs],
    )
    family(
        "meshbone_link_ping_ms",
        "gauge",
        "Round-trip time across the link.",
        [(k, l["ms"]) for k, l in pairs if l["ms"] is not None],
    )
    known = [(names[r], names[p], rx, tx) for r, p, rx, tx in totals if r in names and p in names]
    family(
        "meshbone_link_received_bytes_total",
        "counter",
        "Bytes the hub received from the peer.",
        [({"hub": h, "peer": p}, rx) for h, p, rx, tx in known],
    )
    family(
        "meshbone_link_sent_bytes_total",
        "counter",
        "Bytes the hub sent to the peer.",
        [({"hub": h, "peer": p}, tx) for h, p, rx, tx in known],
    )
    return ("\n".join(out) + "\n").encode()


def view_admin(mesh, me, nodes, csrf, note, soft, until, held, origin, pol):
    """The management page: nodes, adding one, software versions, the password."""
    out = [
        page_head(mesh, "manage", ""),
        f"<h1>manage</h1><p>on <b>{esc(me)}</b> &middot; "
        + (
            f"signing with your token for another {max(0, until - int(time.time())) // 60 + 1} min &middot; "
            "<a href=/admin/logout>end the session</a>"
            if until
            else "this node holds the admin key &middot; <a href=/admin/login>use a token instead</a>"
        )
        + f" &middot; also reachable as <code>http://{admin_vip(mesh)}:{ADMIN_PORT}/admin</code> on every hub</p>",
    ]
    if note:
        out.append(f"<pre>{esc(note)}</pre>")
    hidden = f"<input type=hidden name=csrf value={csrf}>"
    out.append(
        "<h2>nodes</h2><p>A node with an endpoint is a hub: enter one and it becomes a hub once a client has reached it "
        "there; clear it and it is a client again.</p><div class=scroll><table>"
        "<tr><th>role<th>name<th>address<th>endpoint<th>subnets<th>labels<th>description<th>cost (ms)<th>"
    )
    for i, r in enumerate(nodes):
        approve = f" <button name=action value=approve>make hub at {esc(r['wants'])}</button>" if r["wants"] else ""
        simple = (
            f" &middot; <a href='/admin/simple?name={urllib.parse.quote(r['name'])}'>QR / config</a>"
            if r.get("simple") and held
            else ""
        )
        out.append(
            f"<tr><td>{r['role']}{simple}<td><b>{esc(r['name'])}</b><td class=m>{r['ip']}"
            f"<td><input form=f{i} name=endpoint value=\"{esc(r['endpoint'])}\" placeholder='host:port'>"
            f"<td><input form=f{i} name=subnets value=\"{esc(' '.join(r['subnets']))}\">"
            f"<td><input form=f{i} name=labels value=\"{esc(' '.join(r.get('labels', [])))}\">"
            f"<td><input form=f{i} class=w name=desc value=\"{esc(r.get('desc', ''))}\">"
            f"<td><input form=f{i} name=cost value={r['cost']}>"
            f"<td><form id=f{i} method=post>{hidden}<input type=hidden name=name value=\"{esc(r['name'])}\">"
            f"<button name=action value=set>save</button> <button name=action value=revoke>revoke</button>"
            f"{approve}</form>"
        )
    out.append(
        f"</table></div><h2>add a node</h2><form method=post class=grid>{hidden}"
        "<input name=name placeholder=name required> <input name=endpoint placeholder='host:port (hub only)'> "
        "<input name=ip placeholder='address (automatic)'> <input name=subnets placeholder=subnets> "
        "<input name=labels placeholder=labels> <input class=w name=desc placeholder=description> "
        "<input class=w name=remote placeholder='install over ssh: user:password@host' autocomplete=off> "
        "<input class=w name=identity placeholder='private key for that login (optional, used once)' autocomplete=off> "
        "<label><input type=checkbox name=simple value=1 style='width:auto'> simple client (phone, plain WireGuard)</label> "
        "<button name=action value=invite>add</button></form>"
        f"<p>With an ssh destination the node is installed and joined right away. The login starts from <b>{esc(me)}</b> "
        "and can prove itself in three ways: a password in the destination, a private key pasted next to it, or this "
        f"node's own key - add this line to <code>~/.ssh/authorized_keys</code> of the account on the target:</p>"
        f"<pre>{esc(origin or 'this node creates its key the first time it is needed')}</pre><p>Several hops are separated by "
        "<code>;</code>, each with or without a password, and each is reached through the one before it. "
        "Without one you get a config file to carry over (it holds the new node's private key).</p>"
    )
    rel, short = soft["release"], lambda sha: sha[:12] or "-"
    out.append(
        f"<h2>software</h2><p>this node runs <code>{short(soft['running'])}</code> &middot; published for the mesh: "
        + (
            f"<code>{short(rel['sha'])}</code> from {esc(rel.get('source', '?'))}, {esc(rel.get('time', ''))}"
            if rel
            else "nothing yet"
        )
        + "</p><div class=scroll><table><tr><th>node<th>runs<th>last update"
    )
    for n in soft["nodes"]:
        u = n["update"]
        last = (
            "-"
            if not u
            else f"{short(u.get('sha', ''))} "
            + ("installed" if u.get("ok") else "refused, kept the old version: " + str(u.get("why", "")))
        )
        mark = "" if not rel or not n["code"] else " (current)" if rel["sha"].startswith(n["code"]) else " (behind)"
        out.append(
            f"<tr><td><b>{esc(n['name'])}</b><td class=m>{esc(n['code'] or '?')}{mark}<td style='white-space:normal'>{esc(last)}"
        )
    source = rel.get("source", "") if rel else ""
    repo = re.match(r"https://raw\.githubusercontent\.com/([\w.-]+/[\w.-]+)/", source)
    out.append(
        f"</table></div><form method=post class=grid style='margin-top:10px'>{hidden}"
        f"<input class=w name=source placeholder='https://github.com/OWNER/REPO' value=\"{esc('https://github.com/' + repo[1] if repo else '')}\" required> "
        "<input name=ref placeholder='branch, tag or commit (main)'> "
        "<button name=action value=update>fetch, verify here, roll out</button></form>"
        + (
            f"<form method=post style='margin-top:6px'>{hidden}<button name=action value=rollback>roll the mesh back to "
            f"{short(soft['previous'])}</button></form>"
            if soft["previous"]
            else ""
        )
        + "<p>The new version is first installed on this node. Only if this node is still healthy afterwards is it signed and "
        "handed to the others; each of them tests it the same way and keeps its old version if anything goes wrong.</p>"
        "<details><summary>update log of this node</summary><pre>"
        + esc("\n".join(" ".join(f"{k}={v}" for k, v in e.items()) for e in soft["log"]) or "empty")
        + "</pre></details>"
    )
    out.append(
        "<h2>firewall</h2><p>Who may open connections to whom across the mesh. Rules are tried from the top and the first "
        f"match decides; without a match the default applies, which is <b>{pol['default']}</b>. Answers, ping and the mesh's "
        "own ports always pass.</p><div class=scroll><table><tr><th>#<th>action<th>from<th>to<th>ports<th>"
    )
    for i, r in enumerate(pol["rules"], 1):
        out.append(
            f"<tr><td>{i}<td>{esc(r['action'])}<td class=m>{esc(r['from'])}<td class=m>{esc(r['to'])}"
            f"<td class=m>{esc(r.get('ports') or 'all traffic')}<td><form method=post>{hidden}"
            f"<input type=hidden name=rule value={i}><button name=action value=policy_del>remove</button></form>"
        )
    out.append(
        f"</table></div><form method=post class=grid style='margin-top:10px'>{hidden}"
        "<select name=verdict><option>deny<option>allow</select> from <input name=src placeholder='group' required> "
        "to <input name=dst placeholder='group' required> <input name=ports placeholder='tcp/22,443 udp/53 (all)'> "
        f"<button name=action value=policy_add>add rule</button></form><form method=post class=grid style='margin-top:6px'>{hidden}"
        "otherwise <select name=default><option>allow<option>deny</select> <button name=action value=policy_default>set default"
        "</button></form><p>A group is a label (the nodes carrying it), <code>@name</code>, <code>nodes</code>, "
        "<code>hubs</code>, <code>clients</code>, <code>subnets</code> (every announced network), <code>LABEL+net</code> "
        "(the networks behind those nodes), <code>any</code>, or an address. Example: deny from <code>subnets</code> to "
        "<code>nodes</code> lets the mesh reach into the subnets but not the other way round.</p>"
    )
    if not held:
        return "".join(out).encode()
    out.append(
        f"<h2>password</h2><form method=post class=grid>{hidden}"
        "<input type=password name=new1 placeholder='new password' required minlength=8 autocomplete=new-password> "
        "<input type=password name=new2 placeholder='again' required autocomplete=new-password> "
        "<button name=action value=passwd>change</button></form>"
        "<p>Applies to this page on every admin node. Your browser will ask for it again.</p>"
    )
    return "".join(out).encode()


def view_simple(mesh, name, hub, hubs, text, code, stored):
    """One simple client: its QR code and config."""
    link = "/admin/simple?name=" + urllib.parse.quote(name)
    code = (
        code[code.index("<svg") :]
        if code and "<svg" in code
        else "<p>No QR code: qrencode is not installed on this node.</p>"
    )
    others = " &middot; ".join(
        f"<b>{esc(h)}</b>" if h == hub or not stored else f"<a href='{link}&hub={urllib.parse.quote(h)}'>{esc(h)}</a>"
        for h in hubs
    )
    download = "data:text/plain;base64," + base64.b64encode(text.encode()).decode()
    return (
        page_head(mesh, name, "")
        + f"<h1>{esc(name)}</h1><p>A plain WireGuard client. Scan this with the WireGuard app, "
        f'or <a download="{esc(name)}.conf" href="{download}">download {esc(name)}.conf</a>. <a href=/admin>back</a></p>'
        f"<p>connects through: {others}</p>"
        f"<div style='background:#fff;display:inline-block;padding:10px;border-radius:8px;margin:12px 0;width:min(320px,90vw)'>{code}</div>"
        + (
            ""
            if stored
            else "<p><b>Save it now.</b> This node does not keep the device's key, so this page cannot be shown again.</p>"
        )
        + "<p>Plain WireGuard uses one hub and cannot switch by itself: if that hub is down, export the config again through "
        "another one. The config lists the networks known now; export it again after adding subnets or hubs.</p>"
        f"<details><summary>show the config (contains the private key)</summary><pre>{esc(text)}</pre></details>"
    ).encode()


def view_status(mesh, nodes, notes, once, is_admin, version):
    """`meshbone status` as text."""
    lines = [
        f"mesh {mesh['name']} {mesh['net']}, cluster {mesh['cluster_net']} (map http://{admin_vip(mesh)}:{ADMIN_PORT}/ "
        f"on every hub){' (--once)' if once else ''}{', admin node' if is_admin else ''}, version {version[:12] or '?'}"
    ]
    for r in nodes:
        lines.append(
            f"{r['role']:<6} {r['name']:<16} {r['ip']:<15} {r['endpoint'] or '(nat)':<24} "
            f"{r['link']:<40} {' '.join(r['subnets'] + r['vips'])}"
            + (f"  cost {r['eff']}" if r["eff"] else "")
            + "".join(f" [{l}]" for l in r.get("labels", []))
            + (f"  # {r['desc']}" if r.get("desc") else "")
            + (f"  [asks to be a hub at {r['wants']}]" if r["wants"] else "")
        )
    return "\n".join(lines + ["warning: " + w for w in notes])


def view_policy(pol):
    """The policy as text, for the terminal."""
    lines = [f"default: {pol['default']} (for new connections no rule matches)"]
    for i, r in enumerate(pol["rules"], 1):
        lines.append(
            f"{i:>3}  {r['action']:<5} from {r['from']:<18} to {r['to']:<18} {r.get('ports') or 'all traffic'}"
        )
    return "\n".join(lines + ["always allowed: answers, ping, and the mesh's own ports between nodes"])


# ==============================================================================
# CONTROLLER - what happens when something asks: a command line, an HTTP request, another
# node's gossip, the timer. Controllers change the model, then pick a view.
# ==============================================================================


def handle(ip, line):
    """Answer one exchange -> (reply, changed).

    There is no application-level auth: WireGuard only lets a packet in if its
    source address belongs to the peer it came from, so inside the mesh the
    source address *is* the peer's identity.
    """
    try:
        node_id = int(IPv4Address(ip)) - int(mesh_net(local()["mesh"]).network_address)
    except ValueError:
        return None, False
    with locked():
        nodes = load()
        peer = next((pk for pk, n in live(nodes).items() if n["id"] == node_id), None)
        if not peer:
            return None, False
        try:
            msg = json.loads(line)
            changed = merge(msg, None if nodes[peer]["endpoint"] else peer)
        except ValueError:
            return None, False
        reply, me = state(), nodes[local()["pub"]]
        if not isinstance(msg, dict):
            msg = {}
        if type(msg.get("stats_since")) is int and me["endpoint"]:
            reply.update(stats_export(me["id"], msg["stats_since"]))  # for whoever keeps a copy of the traffic history
        if re.fullmatch(r"[0-9a-f]{64}", str(msg.get("want_code"))):
            reply["code"] = offer_code(
                msg["want_code"]
            )  # not secret, and the asker checks it against the signed release
        return json.dumps(reply).encode() + b"\n", changed


def gossip(flood=False):
    """Push-pull with every hub; a hub that has news (flood) also pushes it down to its clients."""
    loc = local()
    mypk, nodes = loc["pub"], load()
    hub = bool(nodes[mypk]["endpoint"])
    peers = [  # simple clients run no meshbone, nothing to tell them
        (pk, n)
        for pk, n in live(nodes).items()
        if pk != mypk and not n.get("simple") and (n["endpoint"] or (hub and flood))
    ]
    msg, want = state(), wanted_code()
    copies = keeps_stats(nodes[mypk])
    since = stats_cursors() if copies else {}
    if want:
        msg["want_code"] = want

    def one(peer):
        try:
            ask = {**msg, "stats_since": since.get(peer[1]["id"], 0)} if copies and peer[1]["endpoint"] else msg
            return peer[0], exchange(loc["mesh"], peer[1], ask)
        except (OSError, ValueError):
            return peer[0], None  # down or not linked yet; the next round will do

    with ThreadPoolExecutor(PARALLEL) as pool:
        results = list(pool.map(one, peers))
    with locked():
        changed = [merge(got, None if nodes[pk]["endpoint"] else pk) for pk, got in results]
        for pk, got in results:
            if copies and nodes[pk]["endpoint"] and isinstance(got, dict):
                stats_import(nodes[pk]["id"], got)
            if want and isinstance(got, dict) and got.get("code") and not os.path.exists(release_path(want)):
                store_code(want, got["code"])
        if any(changed):
            reconcile()
    if any(changed) and hub:
        gossip(flood=True)


def settle(changed):
    """After accepting news: apply it here and, on a hub, pass it on to everyone."""
    if changed:
        with locked():
            reconcile()
        gossip(flood=True)


def verify_links():
    """Wait for the first WireGuard handshakes: one proves the endpoint, the port forward, both
    keys and the preshared key in a single step."""
    loc, nodes = local(), load()
    mine = bool(nodes[loc["pub"]]["endpoint"])
    hubs = {pk: n for pk, n in live(nodes).items() if pk != loc["pub"] and n["endpoint"]}
    deadline = time.time() + VERIFY_WAIT
    while hubs and time.time() < deadline and not set(hubs) <= set(handshakes()):
        time.sleep(1)
    seen = handshakes()
    for pk, n in hubs.items():
        print(
            f"  link to hub {n['name']} ({n['endpoint']}): "
            + (
                "verified"
                if pk in seen
                else "NO HANDSHAKE yet - check its endpoint, UDP port forward and firewall"
                + (" (or this hub's own)" if mine else "")
            )
        )
    if hubs:
        with locked():
            reconcile()
        gossip()


def bootstrap(mesh, key, nodes, nets, a, admin_key=None, conf=None):
    if joined():
        sys.exit("this machine is already in a mesh; run `meshbone leave` first")
    install_packages()
    pub = run("wg", "pubkey", input=key + "\n").strip()
    if pub not in nodes:
        sys.exit("this config's key does not match any node in it")
    for l in map(IPv4Network, local_nets()):
        for reserved in (mesh_net(mesh), cluster_net(mesh)):
            if l.subnet_of(reserved):
                sys.exit(f"this machine is attached to {l}, which lies inside the mesh's own range {reserved}")
        for k, n in live(nodes).items():
            if k != pub and any(IPv4Network(s).subnet_of(l) for s in n["subnets"]):
                print(
                    f"warning: local network {l} overlaps a subnet of {n['name']}; "
                    f"this machine will keep using its local network for it"
                )
    set_mode(getattr(a, "once", False))
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    opts = {k: getattr(a, k) for k in ("listen_port", "mtu") if getattr(a, k, None)}
    if getattr(a, "nat", None):
        opts["nat"] = a.nat == "on"
    write(f"{DIR}/node.json", json.dumps({"mesh": mesh, "key": key, "pub": pub, "cost": {}, **opts}))
    if admin_key:
        write(f"{DIR}/admin.key", admin_key)
    save(nodes)
    save_nets(nets)
    write(f"{DIR}/conf.json", json.dumps(conf or {}))
    install_units()
    with locked():
        reconcile()
    me = nodes[pub]
    print(
        f"{me['name']}: {'hub' if me['endpoint'] else 'client'} in mesh {mesh['name']}, "
        f"address {router_ip(mesh, me['id'])}"
    )
    if me["endpoint"]:
        print(
            f"  listening on UDP {opts.get('listen_port') or me['endpoint'].rpartition(':')[2]}; "
            f"others dial {me['endpoint']}"
        )
    verify_links()


@contextlib.contextmanager
def editing():
    """Change the directory on an admin node. Yields (loc, nodes, nets); when the block ends
    normally the result is saved, applied here and pushed to the whole mesh."""
    with locked():
        loc, nodes, nets = admin()
        had_hub = any(n["endpoint"] for n in live(nodes).values())
        yield loc, nodes, nets
        if had_hub and not any(n["endpoint"] for n in live(nodes).values()):
            sys.exit("that would leave the mesh without a hub; make another node a hub first")
        save(nodes)
        reconcile()
    gossip(flood=True)


def confirm_hub(name):
    """A node only stays a hub if somebody outside can really dial it: wait until a client reports
    a ping through its endpoint, otherwise take the endpoint away so it is an ordinary client again."""
    loc, deadline = local(), time.time() + CONFIRM_WAIT
    while True:
        with locked():
            reconcile()
        gossip()
        alive, nets = live(load()), load_nets()
        pk, n = by_name(load(), name)
        hubs = [k for k, o in alive.items() if o["endpoint"]]
        online = {i for h in hubs for i in nets.get(h, {}).get("sees", [])}
        testers = [
            k
            for k, o in alive.items()
            if not o["endpoint"] and not o.get("simple") and (o["id"] in online or k == loc["pub"])
        ]
        if not testers or hubs == [pk]:
            print(f"note: no client is online to test {n['endpoint']} from outside; taking it on trust")
            return
        if any(str(n["id"]) in nets.get(k, {}).get("rtt", {}) for k in testers) or (
            loc["pub"] in testers and pk in read_json("state.json", {}).get("rtt", {})
        ):
            print(f"{name} is reachable at {n['endpoint']}: it is a hub now")
            return
        if time.time() > deadline:
            break
        time.sleep(3)
    with editing() as (loc, nodes, nets):
        pk, n = by_name(nodes, name)
        endpoint, n["endpoint"], n["seq"] = n["endpoint"], "", next_seq(n["seq"])
        sign(pk, n)
    sys.exit(
        f"no client could reach {name} at {endpoint} within {CONFIRM_WAIT}s (port forward? firewall? "
        f"listen port?), so it stays a client. --no-verify skips this test"
    )


def apply_release(sha):
    """Install a version on this node -> (ok, why not).

    The new version first has to pass its own dry run against this node's real
    state. Then it is installed, and if the node is worse off afterwards - the
    upgrade fails, or the node was in touch with the mesh before and is not any
    more - the version it ran before is put back. Either way the log says so.
    """
    path, node = release_path(sha), socket.gethostname()
    with open(f"{DIR}/update.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = code_sha()
        if code_sha(path) != sha:
            return False, "the file does not match the checksum of the release"
        ok, said = script(path, "check")
        if not ok:
            audit("rejected", node=node, sha=sha, why="dry run failed: " + said)
            write(
                f"{DIR}/update.json",
                json.dumps({"sha": sha, "ok": False, "why": "dry run failed: " + said[-200:], "was": old}),
            )
            return False, "dry run failed: " + said
        os.makedirs(f"{DIR}/releases", mode=0o700, exist_ok=True)
        if old and not os.path.exists(release_path(old)):
            shutil.copy(BIN, release_path(old))  # the way back, and what other nodes may ask us for
        was_fine = reachable()
        ok, said = script(path, "upgrade")
        if ok:
            time.sleep(UPDATE_SETTLE)
            ok, said = script(BIN, "sync")
        if ok and was_fine and not script(BIN, "health")[0]:
            ok, said = False, "the node lost touch with the mesh after the upgrade"
        if not ok:
            restored = bool(old) and script(release_path(old), "upgrade")[0]
            audit("rolled-back", node=node, sha=sha, back_to=old, restored=restored, why=said)
            write(f"{DIR}/update.json", json.dumps({"sha": sha, "ok": False, "why": said[-200:], "was": old}))
            return False, said
        audit("updated", node=node, sha=sha, was=old)
        write(f"{DIR}/update.json", json.dumps({"sha": sha, "ok": True, "why": "", "was": old}))
        return True, ""


def maybe_update():
    """Follow the published release, once per version: a version that failed here is not retried."""
    r = release()
    if not r or r["sha"] == code_sha() or read_json("update.json", {}).get("sha") == r["sha"]:
        return
    if os.path.exists(release_path(r["sha"])):  # otherwise gossip is still fetching it
        apply_release(r["sha"])
        with locked():
            reconcile()  # tell the mesh how it went
        gossip()


def set_password(new):
    if len(new) < 8:
        sys.exit("the password needs at least 8 characters")
    if not os.path.exists(f"{DIR}/admin.key"):
        sys.exit(
            "the password protects this page on nodes that hold the admin key; here you sign in with the key itself"
        )
    with locked():
        admin()
        salt = secrets.token_bytes(16)
        hashed = hashlib.scrypt(new.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        conf_put("admin_pw", password_box().encrypt(salt + hashed).decode())
    gossip(flood=True)


def cmd_install():
    install_packages()
    install_self(SBIN)
    print(f"installed {SBIN}; next: `meshbone create ...` or `meshbone join FILE`")


def cmd_create(a):
    install_packages()
    from cryptography.hazmat.primitives import serialization as ser

    key, psk = run("wg", "genkey").strip(), run("wg", "genpsk").strip()
    pub = run("wg", "pubkey", input=key + "\n").strip()
    password = secrets.token_urlsafe(16)
    signer = ed25519().Ed25519PrivateKey.generate()
    admin_key = base64.b64encode(
        signer.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    ).decode()
    admin_pub = base64.b64encode(signer.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
    try:
        mesh = {
            "name": a.mesh,
            "psk": psk,
            "net": str(IPv4Network(a.net)),
            "cluster_net": str(IPv4Network(a.cluster_net)),
            "admin": hashlib.sha256(password.encode()).hexdigest(),
            "admin_pub": admin_pub,
        }
    except ValueError as e:
        sys.exit(f"bad --net or --cluster-net: {e}")
    if not valid_mesh(mesh):
        sys.exit("bad --mesh, --net (a /20 to /23) or --cluster-net (must not overlap --net)")
    me = checked(
        mesh,
        {},
        {},
        pub,
        {
            "name": a.name,
            "id": id_pool(mesh, bool(a.endpoint))[0],
            "endpoint": a.endpoint,
            "subnets": a.subnet,
            "vips": [],
            "cost": 0,
            "seq": next_seq(),
            "desc": getattr(a, "desc", None) or "",
            "labels": getattr(a, "label", None) or [],
        },
    )
    me["sig"] = base64.b64encode(signer.sign(signable(pub, me))).decode()
    bootstrap(mesh, key, {pub: me}, {}, a, admin_key)
    print(
        f"mesh map: http://{admin_vip(mesh)}:{ADMIN_PORT}/ (any hub answers, from inside the mesh)\n"
        f"management: http://{router_ip(mesh, me['id'])}:{ADMIN_PORT}/admin, user admin, password {password}\n"
        f"(change it there or with `meshbone passwd`)\n"
        f"this machine holds {DIR}/admin.key, the key that controls the mesh"
    )


def cmd_invite(a):
    with editing() as (loc, nodes, nets):
        mesh = loc["mesh"]
        key = run("wg", "genkey").strip()
        pub = run("wg", "pubkey", input=key + "\n").strip()
        used = {n["id"] for n in nodes.values()}  # ids of revoked nodes are never reused
        if getattr(a, "ip", ""):
            try:
                node_id = int(IPv4Address(a.ip)) - int(mesh_net(mesh).network_address)
            except ValueError as e:
                sys.exit(f"bad --ip: {e}")
            if not 0 < node_id < mesh_net(mesh).num_addresses - 1 or node_id in used:
                sys.exit(f"{a.ip} is not a free address in {mesh['net']}")
        else:
            # random so that two admins inviting at the same moment rarely collide
            free = sorted(set(id_pool(mesh, bool(a.endpoint))) - used)
            if not free:
                sys.exit("the mesh range has no free address for this role")
            node_id = random.choice(free)
        simple = getattr(a, "simple", False)
        if simple and (a.endpoint or a.subnet or a.vip or a.admin):
            sys.exit("a simple client only gets an address: no endpoint, subnets, cluster IPs or admin key")
        nodes[pub] = sign(
            pub,
            checked(
                mesh,
                nodes,
                nets,
                pub,
                {
                    "name": a.name,
                    "id": node_id,
                    "endpoint": a.endpoint,
                    "subnets": a.subnet,
                    "vips": a.vip,
                    "cost": a.cost,
                    "seq": next_seq(),
                    "desc": getattr(a, "desc", "") or "",
                    "labels": getattr(a, "label", []) or [],
                    **({"simple": True} if simple else {}),
                },
            ),
        )
        if simple:
            ISSUED[a.name] = key
            if os.path.exists(f"{DIR}/admin.key"):  # kept encrypted with the admin nodes, to show the config again
                conf_put(f"simple_{node_id}", password_box().encrypt(key.encode()).decode())
    if simple:
        return
    out = a.out or f"{a.name}.mesh.json"
    cfg = {**state(), "mesh": mesh, "key": key}
    if a.admin:
        if not os.path.exists(f"{DIR}/admin.key"):
            sys.exit("--admin hands over the admin key file, and this machine does not hold it")
        cfg["admin_key"] = read("admin.key")
    write(out, json.dumps(cfg, indent=1))
    print(
        f"wrote {out} - it holds {a.name}'s private key: copy it over a secure channel, "
        f"run `meshbone join {os.path.basename(out)}` there, then delete it"
    )


def cmd_deploy(a):
    """Invite a node and install it over ssh."""
    hops = parse_chain(a.remote)
    chain, secret, tmp = [d for d, _ in hops], hops[-1][1], None
    cfg = f"{DIR}/{a.name}.deploy.json"
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_invite(argparse.Namespace(**{**vars(a), "out": cfg}))
    identity = getattr(a, "identity", None)
    if identity and "PRIVATE KEY" not in identity:  # the command line gives a file, the page the key itself
        with open(identity) as f:
            identity = f.read()
    with ssh_session(hops, identity) as base:
        try:
            keys_only = [] if any(p for _, p in hops) else ["-o", "BatchMode=yes"]
            jump = (
                len(chain) > 1
                and subprocess.run(
                    [*base, *keys_only, "-o", "ConnectTimeout=10", "-J", ",".join(chain[:-1]), chain[-1], "true"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                ).returncode
                == 0
            )
            if not jump and any(p for _, p in hops[1:]):
                raise OSError(
                    "a password for an inner hop only works if this machine can log in to it through the hops before it"
                )
            # scp cannot follow a chain of logins, a tar stream on stdin can
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w") as tar:
                tar.add(os.path.realpath(__file__), "meshbone.py")
                tar.add(cfg, "mesh.json")
            made = (
                subprocess.run(
                    remote_argv(base, chain, 'umask 077 && d=$(mktemp -d) && tar -xf - -C "$d" && echo "$d"', jump),
                    input=payload.getvalue(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                .stdout.decode()
                .split()
            )
            if not made or not re.fullmatch(r"/[\w./-]+", made[-1]):
                raise OSError(f"unexpected reply from {chain[-1]}: {made!r}")
            tmp = made[-1]
            join = (
                f"python3 {tmp}/meshbone.py join {tmp}/mesh.json"
                + (" --once" if a.once else "")
                + "".join(
                    f" --{k.replace('_', '-')} {shlex.quote(str(getattr(a, k)))}"
                    for k in ("listen_port", "mtu", "nat")
                    if getattr(a, k, None)
                )
            )
            sudo = "sudo -S -p ''" if secret else "sudo"  # with a password, sudo reads it from stdin
            tty = not secret and sys.stdin.isatty()
            subprocess.run(
                remote_argv(
                    base,
                    chain,
                    f'S=; [ "$(id -u)" = 0 ] || S="{sudo}"; $S {join}; rc=$?; rm -rf {tmp}; exit $rc',
                    jump,
                    tty=tty,
                ),
                check=True,
                **({} if tty else {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT}),
                **({"input": (secret + "\n").encode()} if secret else {}),
            )
        except (OSError, subprocess.CalledProcessError) as e:
            if tmp:  # the config holds the node's private key: do not leave it behind
                subprocess.run(
                    remote_argv(base, chain, f"rm -rf {tmp}", jump), stdin=subprocess.DEVNULL, capture_output=True
                )
            cmd_revoke(argparse.Namespace(name=a.name))
            said = (getattr(e, "stderr", None) or getattr(e, "stdout", None) or b"").decode("utf-8", "replace").strip()
            why = (
                said.splitlines()[-1]
                if said
                else str(e) if isinstance(e, OSError) else f"ssh ended with status {e.returncode}"
            )
            if "Permission denied" in why:
                why += (
                    ". The login offered "
                    + (
                        "the key you gave"
                        if identity
                        else "your own ssh identity" if base[0] == "sudo" else "this node's deploy key"
                    )
                    + "; make the target accept it, put a password in the destination, or hand over a key"
                )
            sys.exit(f"deploy to {chain[-1]} failed: {why}; {a.name} was revoked again")
        finally:
            os.remove(cfg)
    with locked():
        reconcile()
    print(f"{a.name} is installed and has joined")
    if a.endpoint and getattr(a, "verify", True):
        confirm_hub(a.name)


def cmd_join(a):
    with open(a.file) as f:
        cfg = json.load(f)
    if cfg.get("v") != VERSION or not valid_mesh(cfg.get("mesh")) or not re.fullmatch(KEY_RE, str(cfg.get("key"))):
        sys.exit(f"{a.file} is not a meshbone v{VERSION} config")
    nodes = {pk: n for pk, n in cfg["nodes"].items() if valid(cfg["mesh"], pk, n)}
    nets = {pk: r for pk, r in cfg.get("nets", {}).items() if valid_nets(pk, r)}
    conf = {k: r for k, r in cfg.get("conf", {}).items() if valid_conf(cfg["mesh"], k, r)}
    bootstrap(cfg["mesh"], cfg["key"], nodes, nets, a, cfg.get("admin_key"), conf)


def cmd_set(a):
    with editing() as (loc, nodes, nets):
        pk, n = by_name(nodes, a.name)
        had, was = list(n["subnets"]), n["endpoint"]
        if a.endpoint is not None:
            n["endpoint"] = a.endpoint
        if a.subnet or a.no_subnet:
            n["subnets"] = a.subnet
        if a.vip or a.no_vip:
            n["vips"] = a.vip
        if a.cost is not None:
            n["cost"] = a.cost
        if getattr(a, "desc", None) is not None:
            n["desc"] = a.desc
        if getattr(a, "label", None) or getattr(a, "no_label", False):
            n["labels"] = a.label
        n["seq"] = next_seq(n["seq"])
        sign(pk, checked(loc["mesh"], nodes, nets, pk, n, had))
    if n["endpoint"] and not was and getattr(a, "verify", True):
        confirm_hub(a.name)


def cmd_local(a):
    with locked():
        loc = local()
        for k in ("listen_port", "mtu"):
            if getattr(a, k) is not None:
                loc[k] = getattr(a, k)  # 0 puts it back to automatic
        if a.nat:
            loc["nat"] = a.nat == "on"
        write(f"{DIR}/node.json", json.dumps(loc))
        reconcile()
    print(
        f"listen port {loc.get('listen_port') or 'automatic'}, mtu {loc.get('mtu') or 1420}, "
        f"gateway NAT {'on' if loc.get('nat', True) else 'off'}"
    )


def cmd_promote(a):
    wants = norm_endpoint(a.endpoint)
    with locked():
        loc = local()
        write(f"{DIR}/node.json", json.dumps({**loc, "wants": wants}))
        reconcile()
    gossip()
    if wants:
        print(
            f"asked to become a hub at {wants}; on an admin node run `meshbone approve "
            f"{load()[loc['pub']]['name']}` (or use the admin page)"
        )


def cmd_approve(a):
    with editing() as (loc, nodes, nets):
        pk, n = by_name(nodes, a.name)
        wants, was = nets.get(pk, {}).get("wants", ""), n["endpoint"]
        if not wants or wants == n["endpoint"]:
            sys.exit(f"{a.name} has no pending request")
        n["endpoint"], n["seq"] = wants, next_seq(n["seq"])
        sign(pk, checked(loc["mesh"], nodes, nets, pk, n, n["subnets"]))
    if not was and getattr(a, "verify", True):
        confirm_hub(a.name)


def cmd_revoke(a):
    with editing() as (loc, nodes, nets):
        pk, n = by_name(nodes, a.name)
        if pk == loc["pub"]:
            sys.exit("revoke this node from another admin node, or run `meshbone leave` here")
        n["gone"], n["seq"] = True, next_seq(n["seq"])
        sign(pk, n)


def cmd_cost(a):
    with locked():
        loc = local()
        by_name(load(), a.name)
        loc["cost"] = {k: v for k, v in {**loc["cost"], a.name: a.value}.items() if v}
        write(f"{DIR}/node.json", json.dumps(loc))
        reconcile()


def cmd_policy(a):
    """Show or change the firewall policy: who may open connections to whom across the mesh."""
    pol = policy()
    if a.clear or a.default or a.add or a.delete is not None:
        with locked():
            loc, nodes, _ = admin()
            mesh, alive = loc["mesh"], live(nodes)
            if a.clear:
                pol = {"default": "allow", "rules": []}
            if a.default:
                pol["default"] = a.default
            if a.delete is not None:
                if not 1 <= a.delete <= len(pol["rules"]):
                    sys.exit(f"there is no rule {a.delete}")
                pol["rules"].pop(a.delete - 1)
            if a.add:
                src, dst, action = a.add
                if action not in ("allow", "deny"):
                    sys.exit("a rule ends in allow or deny")
                rule = {"from": src, "to": dst, "action": action, "ports": " ".join((a.ports or "").split())}
                members(src, mesh, alive), members(dst, mesh, alive), parse_ports(rule["ports"])
                pol["rules"].insert((a.at or len(pol["rules"]) + 1) - 1, rule)
            conf_put("policy", json.dumps(pol))
            reconcile()
        gossip(flood=True)
    print(view_policy(pol))


def cmd_simple(a):
    """Create a simple client, or export an existing one again (e.g. through another hub)."""
    if not any(n["name"] == a.name for n in live(load()).values()):
        cmd_invite(
            argparse.Namespace(
                name=a.name,
                endpoint="",
                subnet=[],
                vip=[],
                cost=0,
                admin=False,
                out=None,
                simple=True,
                desc=a.desc,
                label=a.label,
                ip=a.ip,
            )
        )
    text, hub, hubs = simple_config(a.name, a.hub, ISSUED.get(a.name))
    out = a.out or f"{a.name}.conf"
    write(out, text)
    print(
        f"wrote {out}: a standard WireGuard config for {a.name}, connecting through {hub}"
        + (f" (other hubs: {', '.join(h for h in hubs if h != hub)})" if len(hubs) > 1 else "")
        + ". It holds the device's private key - delete it once imported"
    )
    if a.qr:
        print(qr(text, "ansiutf8") or "(no QR code: qrencode is not installed)")


def cmd_sync():
    with locked():
        reconcile()
    gossip()
    maybe_update()


def cmd_serve():
    """One exchange on the connection systemd handed us (Accept=yes socket)."""
    sock = socket.fromfd(0, socket.AF_INET, socket.SOCK_STREAM)
    reply, changed = handle(sock.getpeername()[0], sock.makefile("rb").readline(8 << 20))
    if reply:
        sock.sendall(reply)
    sock.close()
    settle(changed)


def cmd_status():
    loc = local()
    notes = warnings() + [
        f"this machine already routes {p} some other way, so its own traffic there does not use the mesh "
        f"(traffic it relays for others does)"
        for p in read_json("state.json", {}).get("elsewhere", [])
    ]
    print(view_status(loc["mesh"], list(rows()), notes, ONCE, os.path.exists(f"{DIR}/admin.key"), code_sha()))


def cmd_leave():
    units = ["meshbone.timer", "meshbone.service", "meshbone-serve.socket", "meshbone-admin.socket"]
    run("systemctl", "disable", "--now", *units, check=False)
    firewall([])
    apply_table(None)
    run("ip", "rule", "del", "pref", str(MESH_TABLE), check=False)
    for ifn in (IFACE, "mbvip"):
        run("ip", "link", "del", ifn, check=False)
    for path in [f"{UNIT_DIR}/{name}" for name in UNITS]:
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)
    shutil.rmtree(DIR, ignore_errors=True)
    run("systemctl", "daemon-reload", check=False)
    print("left the mesh; run `meshbone revoke` for this node on an admin node so its key stops being accepted")


def cmd_upgrade():
    """Run from the new script: replaces the installed copy and units, keeps the mesh state."""
    install_units()
    with locked():
        reconcile()


def cmd_passwd():
    import getpass

    new = getpass.getpass("new management page password: ")
    if new != getpass.getpass("again: "):
        sys.exit("the two entries differ")
    set_password(new)
    print("password changed; the other admin nodes pick it up within seconds")


def cmd_check():
    """Dry run against this node's real state, changing nothing. A new version must pass this
    with the node's own Python before it is installed."""
    loc, nodes, nets = local(), load(), load_nets()
    mesh = loc["mesh"]
    if not valid_mesh(mesh) or loc["pub"] not in nodes:
        sys.exit("this version cannot read the node's own settings")
    unreadable = [n.get("name", pk) for pk, n in nodes.items() if not valid(mesh, pk, n)]
    if unreadable:
        sys.exit(f"this version rejects directory entries the node accepts today: {', '.join(unreadable)}")
    table, _ = plan(loc, nodes, nets, {}, {}) if loc["pub"] in live(nodes) else ({}, None)
    for pk in table:
        pair_psk(loc, pk)
    topo = topology()
    view_map(mesh, topo), view_traffic(mesh), view_api(mesh), view_metrics(topo, traffic_totals())
    view_status(mesh, list(rows()), warnings(), ONCE, False, code_sha())
    if os.path.exists(f"{DIR}/admin.key"):
        view_admin(mesh, nodes[loc["pub"]]["name"], list(rows()), "x", "", software(), None, True, "", policy())
    mesh_table(policy_ruleset(mesh, live(nodes), policy()), gateway_ruleset(mesh, nodes[loc["pub"]], True))
    view_policy(policy())
    view_login(mesh, "s", "p", 0, "")
    for text in UNITS.values():
        text.format(py="p", bin="b", port=1, net=mesh["net"], vip="v", aport=2)
    print("ok")


def cmd_health():
    sys.exit(0 if reachable() else "this node is not in touch with the mesh")


def cmd_update(a):
    """Fetch a version, prove it on this node first, then hand it to the whole mesh."""
    admin()
    if a.rollback:
        sha, source = read_json("update.json", {}).get("was", ""), "rollback"
        if not sha or not os.path.exists(release_path(sha)):
            sys.exit("there is no earlier version on this node to go back to")
    else:
        if a.file:
            with open(a.file, "rb") as f:
                data, source = f.read(), os.path.abspath(a.file)
        else:
            data, source = fetch_source(a.url or "", a.ref)
        try:
            compile(data, "meshbone.py", "exec")
        except (SyntaxError, ValueError) as e:
            sys.exit(f"{source} is not a program this node can run: {e}")
        sha = hashlib.sha256(data).hexdigest()
        store_code(sha, base64.b64encode(zlib.compress(data)).decode())
    audit("fetched", node=socket.gethostname(), sha=sha, source=source)
    if sha != code_sha():
        ok, why = apply_release(sha)
        if not ok:
            sys.exit(f"version {sha[:12]} was not accepted on this node, so it was not rolled out: {why}")
    with locked():
        conf_put("release", json.dumps({"sha": sha, "source": source, "time": time.strftime("%Y-%m-%d %H:%M")}))
        reconcile()
    gossip(flood=True)
    audit("published", node=socket.gethostname(), sha=sha, source=source)
    print(
        f"version {sha[:12]} runs on this node and is rolling out to the others; the management page shows how it goes"
    )


def web_passwd(a):
    if a.new1 != a.new2:
        sys.exit("the two entries differ")
    set_password(a.new1)
    print("password changed - log in again with the new one")


def web_set(a):
    vips = by_name(load(), a.name)[1]["vips"]  # the page has no field for these; leave them alone
    cmd_set(argparse.Namespace(**{**vars(a), "vip": vips, "no_vip": not vips}))


def web_invite(a):
    if a.simple and a.remote:
        sys.exit("a simple client is not installed over ssh: scan its QR code or import its config")
    cmd_deploy(a) if a.remote else cmd_invite(a)


def web_update(a):
    cmd_update(argparse.Namespace(url=a.source, ref=a.ref, file=None, rollback=a.action == "rollback"))


def web_policy(a):
    cmd_policy(
        argparse.Namespace(
            clear=False,
            default=a.default if a.action == "policy_default" else None,
            add=[a.src, a.dst, a.verdict] if a.action == "policy_add" else None,
            ports=a.ports,
            at=None,
            delete=int(a.rule) if a.action == "policy_del" else None,
        )
    )


def simple_response(mesh, query, key=None):
    name, hub = query.get("name", [""])[0], query.get("hub", [None])[0]
    try:
        text, hub, hubs = simple_config(name, hub, key)
    except SystemExit as e:
        return "404 Not Found", f"{e}\n".encode(), "text/plain; charset=utf-8", ""
    stored = os.path.exists(f"{DIR}/admin.key")
    return "200 OK", view_simple(mesh, name, hub, hubs, text, qr(text, "SVG"), stored), "text/html; charset=utf-8", ""


def respond(method, path, headers, body, peer="127.0.0.1"):
    """One HTTP request -> (status, body, content type, extra headers).

    Everything but /admin is read-only and open to the mesh: the map, traffic,
    the JSON API and /metrics. /admin works on every node. Where the admin key
    is stored it asks for the page password; anywhere else it asks for the key
    itself, which the browser turns into a short-lived token (see view_login).
    """
    global SESSION
    loc = local()
    mesh = loc["mesh"]
    route, _, qs = path.partition("?")
    route, query = route.rstrip("/") or "/", urllib.parse.parse_qs(qs)

    def page(content):
        return "200 OK", content, "text/html; charset=utf-8", ""

    def data(value):
        return "200 OK", json.dumps(value, indent=1).encode(), "application/json", ""

    public = {
        "/": lambda: page(view_map(mesh, topology())),
        "/traffic": lambda: page(view_traffic(mesh)),
        "/api": lambda: page(view_api(mesh)),
        "/api/nodes": lambda: data(api_nodes(query)),
        "/api/topology": lambda: data(topology()),
        "/api/policy": lambda: data(policy()),
        "/api/traffic": lambda: data(api_traffic(query)),
        "/metrics": lambda: (
            "200 OK",
            view_metrics(topology(), traffic_totals()),
            "text/plain; version=0.0.4; charset=utf-8",
            "",
        ),
    }
    if not route.startswith("/admin"):
        return public.get(route, public["/"])()

    form = (
        {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()} if method == "POST" else {}
    )
    sid = (re.search(r"(?:^|;\s*)mb=([\w-]{10,60})", headers.get("cookie", "")) or [None, None])[1]
    held, now = os.path.exists(f"{DIR}/admin.key"), int(time.time())
    if route == "/admin/logout":
        session_close(sid)
        return "303 See Other", b"", "text/plain", "Location: /admin\r\nSet-Cookie: mb=; Path=/admin; Max-Age=0\r\n"
    if route == "/admin/login" and method == "POST":
        try:
            nbf, exp = int(form.get("nbf", "")), int(form.get("exp", ""))
        except ValueError:
            nbf = exp = 0
        if session_grant(mesh, form.get("sid", ""), peer, nbf, exp, form.get("sig", "")):
            cookie = f"mb={form['sid']}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={exp - now}"
            return "303 See Other", b"", "text/plain", f"Location: /admin\r\nSet-Cookie: {cookie}\r\n"
        return page(view_login(mesh, *session_open(peer), now, "that token was not accepted; try again"))
    session = session_use(sid, peer)
    if route == "/admin/login" or not (session or held):
        return page(view_login(mesh, *session_open(peer), now, ""))
    if session:
        SESSION, secret, until = session[:2], sid, session[2]
    else:
        try:
            secret = base64.b64decode(headers.get("authorization", "").split()[1]).decode().partition(":")[2]
        except Exception:
            secret = ""
        if not secret or not check_password(secret):
            return (
                "401 Unauthorized",
                b"authentication required\n",
                "text/plain",
                'WWW-Authenticate: Basic realm="meshbone"\r\n',
            )
        until = None
    # a forged cross-site form cannot know this value
    csrf = hashlib.sha256(("csrf:" + secret).encode()).hexdigest()
    if route == "/admin/simple":
        return simple_response(mesh, query)
    note = ""
    if method == "POST":
        if not hmac.compare_digest(form.get("csrf", ""), csrf):
            return "403 Forbidden", b"bad form token\n", "text/plain", ""
        subnets, labels = listed(form.get("subnets", "")), listed(form.get("labels", ""))
        a = argparse.Namespace(
            action=form.get("action"),
            name=form.get("name", ""),
            endpoint=form.get("endpoint", ""),
            admin=False,
            verify=True,
            subnet=subnets,
            no_subnet=not subnets,
            vip=[],
            no_vip=False,
            label=labels,
            no_label=not labels,
            desc=form.get("desc", ""),
            ip=form.get("ip", ""),
            remote=form.get("remote", ""),
            identity=form.get("identity", ""),
            default=form.get("default", ""),
            src=form.get("src", ""),
            dst=form.get("dst", ""),
            verdict=form.get("verdict", ""),
            ports=form.get("ports", ""),
            rule=form.get("rule", "0"),
            once=False,
            listen_port=None,
            mtu=None,
            simple=form.get("simple") == "1",
            new1=form.get("new1", ""),
            new2=form.get("new2", ""),
            source=form.get("source", ""),
            ref=form.get("ref", ""),
            out=f"{DIR}/.invite-{os.getpid()}.json",
        )
        actions = {
            "set": web_set,
            "revoke": cmd_revoke,
            "approve": cmd_approve,
            "invite": web_invite,
            "passwd": web_passwd,
            "update": web_update,
            "rollback": web_update,
            "policy_add": web_policy,
            "policy_del": web_policy,
            "policy_default": web_policy,
        }
        try:
            a.cost = int(form.get("cost") or 0)
            if a.action not in actions:
                sys.exit("unknown action")
            with contextlib.redirect_stdout(io.StringIO()) as said:
                actions[a.action](a)
            if a.action == "invite" and a.simple:
                return simple_response(mesh, {"name": [a.name]}, ISSUED.get(a.name))
            if a.action == "invite" and not a.remote:
                with open(a.out, "rb") as f:
                    return (
                        "200 OK",
                        f.read(),
                        "application/json",
                        f'Content-Disposition: attachment; filename="{a.name}.mesh.json"\r\n',
                    )
            note = said.getvalue().strip() or "saved"
        except (SystemExit, ValueError) as e:
            note = f"error: {e}"
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.remove(a.out)
    me = load()[loc["pub"]]["name"]
    try:
        origin = deploy_key()[1] if os.geteuid() == 0 else ""
    except (OSError, subprocess.CalledProcessError):
        origin = ""
    return page(view_admin(mesh, me, list(rows()), csrf, note, software(), until, held, origin, policy()))


def cmd_admin():
    """One HTTP request on the connection systemd handed us."""
    sock = socket.fromfd(0, socket.AF_INET, socket.SOCK_STREAM)
    f = sock.makefile("rb")
    try:
        method, path = f.readline(4096).decode("ascii").split()[:2]
        headers = {}
        for _ in range(100):
            k, sep, v = f.readline(8192).decode("latin-1").partition(":")
            if not sep:
                break
            headers[k.strip().lower()] = v.strip()
        body = f.read(min(int(headers.get("content-length", 0)), 1 << 16))
        status, out, ctype, extra = respond(method, path, headers, body, sock.getpeername()[0])
    except (IndexError, ValueError):
        status, out, ctype, extra = "400 Bad Request", b"bad request\n", "text/plain", ""
    sock.sendall(
        f"HTTP/1.0 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(out)}\r\n"
        f"Cache-Control: no-store\r\n{extra}\r\n".encode() + out
    )
    sock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def node_options(s):
        s.add_argument("--subnet", action="append", default=[], help="network behind the node to announce")
        s.add_argument("--vip", action="append", default=[], help="cluster IP the node holds")
        s.add_argument("--cost", type=int, default=0, help="ms added when choosing this hub")
        s.add_argument("--desc", default="", help="free-text description")
        s.add_argument("--label", action="append", default=[], help="label, repeatable")
        s.add_argument("--ip", default="", help="mesh address to give the node (default: a free one)")
        s.add_argument(
            "--no-verify",
            dest="verify",
            action="store_false",
            help="keep a new hub's endpoint even if no client could reach it",
        )

    def local_options(s):
        s.add_argument("--listen-port", type=int, help="local UDP port, if it differs from the endpoint's")
        s.add_argument("--mtu", type=int, help="tunnel MTU (default 1420)")
        s.add_argument(
            "--nat", choices=("on", "off"), help="as a gateway, hide the mesh behind this node's address (default on)"
        )

    s = sub.add_parser("create")
    s.add_argument("--endpoint", default="", help="public HOST:PORT of this machine, if it is to be a hub")
    s.add_argument("--name", default=socket.gethostname().split(".")[0])
    s.add_argument("--subnet", action="append", default=[], help="network behind this node to announce")
    s.add_argument("--desc", default="")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("--mesh", default="mesh")
    s.add_argument("--net", default="10.253.254.0/23", help="node addresses: first /24 hubs, rest clients")
    s.add_argument("--cluster-net", default="10.253.253.0/24", help="cluster (anycast) IPs")
    local_options(s)
    s = sub.add_parser("invite")
    s.add_argument("name")
    s.add_argument("--endpoint", default="", help="public HOST:PORT; makes the new node a hub")
    node_options(s)
    s.add_argument("--admin", action="store_true", help="the new node also gets admin.key and can manage the mesh")
    s.add_argument("-o", "--out")
    s = sub.add_parser("deploy")
    s.add_argument("name")
    s.add_argument(
        "--remote",
        required=True,
        metavar="USER[:PASSWORD]@HOST[;...]",
        help="ssh destination, optionally behind jump hosts separated by ';'",
    )
    s.add_argument("--endpoint", default="")
    node_options(s)
    local_options(s)
    s.add_argument("--admin", action="store_true")
    s.add_argument("--identity", help="private key file to log in with, for this deploy only")
    s.add_argument("--once", action="store_true")
    s = sub.add_parser("join")
    s.add_argument("file")
    s.add_argument("--once", action="store_true")
    local_options(s)
    s = sub.add_parser("set")
    s.add_argument("name")
    s.add_argument("--endpoint")
    s.add_argument("--subnet", action="append", default=[])
    s.add_argument("--no-subnet", action="store_true")
    s.add_argument("--vip", action="append", default=[])
    s.add_argument("--no-vip", action="store_true")
    s.add_argument("--cost", type=int)
    s.add_argument("--desc")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("--no-label", action="store_true")
    s.add_argument("--no-verify", dest="verify", action="store_false")
    local_options(sub.add_parser("local"))
    s = sub.add_parser("promote")
    s.add_argument("--endpoint", required=True, help="stable public HOST:PORT of this node; '' withdraws")
    s = sub.add_parser("simple")
    s.add_argument("name")
    s.add_argument("--hub", help="hub to connect through (default: the one that sees the device, else the cheapest)")
    s.add_argument("--qr", action="store_true", help="also print a QR code for the WireGuard phone app")
    s.add_argument("-o", "--out")
    s.add_argument("--desc", default="")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("--ip", default="")
    s = sub.add_parser("approve")
    s.add_argument("name")
    s.add_argument("--no-verify", dest="verify", action="store_false")
    sub.add_parser("revoke").add_argument("name")
    s = sub.add_parser("policy")
    s.add_argument("--default", choices=("allow", "deny"), help="what happens to a new connection no rule matches")
    s.add_argument("--add", nargs=3, metavar=("FROM", "TO", "ACTION"), help="add a rule; ACTION is allow or deny")
    s.add_argument("--ports", help="limit the rule being added, e.g. 'tcp/22,443 udp/53'")
    s.add_argument("--at", type=int, help="position for the rule being added (default: last)")
    s.add_argument("--del", dest="delete", type=int, metavar="N", help="remove rule N")
    s.add_argument("--clear", action="store_true", help="remove every rule and allow everything again")
    s = sub.add_parser("cost")
    s.add_argument("name")
    s.add_argument("value", type=int)
    s = sub.add_parser("update")
    s.add_argument("url", nargs="?", help="https://github.com/OWNER/REPO, or a direct https link to meshbone.py")
    s.add_argument("--ref", help="branch, tag or commit (default main)")
    s.add_argument("--file", help="take the new version from a local file instead")
    s.add_argument("--rollback", action="store_true", help="publish the version this node ran before")
    plain = ("install", "sync", "serve", "admin", "status", "leave", "upgrade", "passwd", "check", "health")
    for c in plain:
        sub.add_parser(c)
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("meshbone must run as root")
    if a.cmd not in ("install", "create", "join") and not joined():
        sys.exit("this machine is not in a mesh yet (see `meshbone create` / `meshbone join`)")
    fn = globals()[f"cmd_{a.cmd}"]
    fn() if a.cmd in plain else fn(a)


if __name__ == "__main__":
    main()
