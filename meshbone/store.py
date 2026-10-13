"""MODEL: the mesh as data and rules - the signed directory, what nodes report about themselves, mesh-wide settings, sessions, releases. Reads and writes the node's files; never touches the network stack."""

import base64, contextlib, fcntl, hashlib, hmac, json, os, re, secrets, sys, time, zlib
from ipaddress import IPv4Address, IPv4Network

from . import model, settings


def read(name):
    with open(f"{settings.DIR}/{name}") as f:
        return f.read().strip()


def write(path, text, mode=0o600):
    """Write a file in one step. A device or pipe given as the path (/dev/null, /dev/stdout)
    is written through as it is - replacing it would leave a plain file where a device was."""
    if os.path.exists(path) and not os.path.isfile(path):
        with open(path, "w") as f:
            f.write(text)
        return
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
    with open(f"{settings.DIR}/lock", "w") as f:
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
    write(f"{settings.DIR}/nodes.json", json.dumps(nodes, indent=1, sort_keys=True))


def load_nets():
    """What each node reports about itself: {pubkey: {nets, wants, sees, rtt, primary, admin, seq}} -
    the local networks it sits on, the endpoint it asks to be a hub at, the ids of the nodes a
    hub currently reaches, its ping to each hub, the hub it sends through and whether it is an
    admin node. Each record is written by its own node and is not signed: it feeds the map and
    hub selection, never authority."""
    return json.loads(read("nets.json"))


def save_nets(nets):
    write(f"{settings.DIR}/nets.json", json.dumps(nets, indent=1, sort_keys=True))


def load_conf():
    """Mesh-wide settings, each signed with the admin key: {name: {value, seq, sig}}."""
    return read_json("conf.json", {})


def state():
    return {"v": settings.VERSION, "nodes": load(), "nets": load_nets(), "conf": load_conf()}


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


def same_name(a, b):
    """Node names are DNS names, so they are the same regardless of case."""
    return a.casefold() == b.casefold()


def named(nodes, name):
    """(pk, node) of the live node of this name, or (None, None)."""
    return next(((pk, n) for pk, n in live(nodes).items() if same_name(n["name"], name)), (None, None))


def by_name(nodes, name):
    pk, n = named(nodes, name)
    if not n:
        sys.exit(f"no node named {name}")
    return pk, n


def mesh_net(mesh):
    return IPv4Network(mesh["net"])


def cluster_net(mesh):
    return IPv4Network(mesh["cluster_net"])


def admin_vip(mesh):
    return cluster_net(mesh).network_address + 1


def metrics_vip(mesh):
    return cluster_net(mesh).network_address + 2


def dns_vip(mesh):
    return cluster_net(mesh).network_address + 3


def https_vip(mesh):
    return cluster_net(mesh).network_address + 4


def mesh_box():
    """Encryption every node of the mesh can open: keyed from the mesh secret. For what hubs
    must be able to read but should not travel in clear - the gateway's TLS key."""
    from cryptography.fernet import Fernet

    return Fernet(
        base64.urlsafe_b64encode(hashlib.sha256(b"meshbone mesh" + base64.b64decode(local()["mesh"]["psk"])).digest())
    )


def ca(mesh):
    """The mesh's own certificate authority -> (certificate PEM, private key PEM). Made once, on an
    admin node; the key is kept under the admin key, the certificate is for everyone to install."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    conf = load_conf()
    if "ca_cert" not in conf:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"meshbone {mesh['name']} CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256())
        )
        conf_put("ca_cert", cert.public_bytes(ser.Encoding.PEM).decode())
        conf_put(
            "ca_key",
            password_box()
            .encrypt(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
            .decode(),
        )
        conf = load_conf()
    key_pem = (
        password_box().decrypt(conf["ca_key"]["value"].encode()).decode()
        if os.path.exists(f"{settings.DIR}/admin.key")
        else ""
    )
    return conf["ca_cert"]["value"], key_pem


def https_routes(mesh):
    """The gateway's names and their backends: {host: url}. `map` is always there."""
    zone = dns_settings(mesh)["zone"]
    try:
        routes = json.loads(load_conf()["https_routes"]["value"])
        assert isinstance(routes, dict)
    except (KeyError, ValueError, AssertionError):
        routes = {}
    out = {f"map.{zone}": f"http://127.0.0.1:{settings.ADMIN_PORT}"}
    for host, url in routes.items():
        out[host if "." in host else f"{host}.{zone}"] = url
    return out


def https_material(mesh):
    """The gateway's certificate and key -> (cert PEM, key PEM), or ('', '') until an admin issued them."""
    conf = load_conf()
    try:
        return conf["https_cert"]["value"], mesh_box().decrypt(conf["https_key"]["value"].encode()).decode()
    except (KeyError, ValueError):
        return "", ""


def https_cert_names(mesh):
    """The names the gateway certificate was issued for, sorted - [] until there is one."""
    from cryptography import x509

    pem = https_material(mesh)[0]
    if not pem:
        return []
    san = x509.load_pem_x509_certificate(pem.encode()).extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return sorted(san.value.get_values_for_type(x509.DNSName))


def https_cert_info(mesh):
    """Who issued the gateway's certificate and until when, for people - '' until there is one."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    pem = https_material(mesh)[0]
    if not pem:
        return ""
    cert = x509.load_pem_x509_certificate(pem.encode())
    issuer = next((a.value for a in cert.issuer if a.oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME)), "?")
    until = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after  # < 42
    return f"{issuer}, until {until.date()}"


def issue_https_cert(mesh):
    """On an admin node: a certificate for every gateway name, signed by the mesh CA, two years."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    ca_cert_pem, ca_key_pem = ca(mesh)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = ser.load_pem_private_key(ca_key_pem.encode(), None)
    hosts = sorted(https_routes(mesh))
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts] + [x509.IPAddress(https_vip(mesh))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    put_https_material(
        cert.public_bytes(ser.Encoding.PEM).decode() + ca_cert_pem,
        key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode(),
    )
    return hosts


def put_https_material(chain_pem, key_pem):
    """Store the gateway's certificate chain and key for the mesh (under the lock); the key travels
    encrypted under a key derived from the mesh's psk, which every hub has."""
    conf_put("https_cert", chain_pem)
    conf_put("https_key", mesh_box().encrypt(key_pem.encode()).decode())


def https_covers(mesh):
    """The gateway names the certificate does not cover (a wildcard covers one label)."""
    names = https_cert_names(mesh)
    return sorted(h for h in https_routes(mesh) if h not in names and "*." + h.partition(".")[2] not in names and names)


def egress_settings():
    """The nodes that run an HTTP proxy: {name: {user, port, salt, hash, secret}}."""
    try:
        cfg = json.loads(load_conf()["egress"]["value"])
        return cfg if isinstance(cfg, dict) else {}
    except (KeyError, ValueError):
        return {}


def acme_settings():
    """The ACME account for the gateway's certificate, or None when the mesh CA signs it:
    {directory, email, token, account_key} - the last two encrypted under the admin key."""
    try:
        cfg = json.loads(load_conf()["acme"]["value"])
        return cfg if isinstance(cfg, dict) and cfg.get("directory") else None
    except (KeyError, ValueError):
        return None


def has_admin_key():
    return os.path.exists(f"{settings.DIR}/admin.key")


def router_ip(mesh, node_id):
    return mesh_net(mesh).network_address + node_id


def held_vips(mesh, node):
    """A node's cluster IPs; every hub that runs meshbone also holds the three service addresses
    (map, metrics, DNS)."""
    service = [str(admin_vip(mesh)), str(metrics_vip(mesh)), str(dns_vip(mesh)), str(https_vip(mesh))]
    return node["vips"] + (service if node["endpoint"] else [])


def transits(alive):
    """The routers that bring public addresses into the mesh: {pubkey: entry}, each with `transit`
    (the router's WireGuard endpoint), `via` (the hub it is linked to) and `public_nets`."""
    return {pk: n for pk, n in alive.items() if n.get("transit")}


def exit_node(alive):
    """The hub that carries the internet traffic of nodes with a public address: the one a transit
    router is linked to. None without a transit."""
    gateways = [n["via"] for n in transits(alive).values()]
    return next(
        (pk for pk, n in sorted(alive.items(), key=lambda kv: kv[1]["id"]) if n["endpoint"] and n["name"] in gateways),
        None,
    )


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
    if text and (not m or not 0 < int(m[2] or settings.DEFAULT_PORT) < 65536):
        sys.exit(f"bad endpoint {text!r}: use HOST or HOST:PORT")
    return f"{m[1]}:{m[2] or settings.DEFAULT_PORT}" if text else ""


def valid_mesh(mesh):
    try:
        assert re.fullmatch(settings.NAME_RE, mesh["name"]) and re.fullmatch(settings.KEY_RE, mesh["psk"])
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
    if settings.SESSION:
        return settings.SESSION
    load_key = ed25519().Ed25519PrivateKey.from_private_bytes
    if os.path.exists(f"{settings.DIR}/admin.key"):
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
    settings.SESSION = (key, None)
    return settings.SESSION


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
    assert 0 < by["exp"] - by["nbf"] <= settings.SESSION_MAX + 120 and by["nbf"] <= record["seq"] <= by["exp"]
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
        assert re.fullmatch(settings.KEY_RE, pk) and re.fullmatch(settings.NAME_RE, n["name"])
        assert type(n["seq"]) is int and type(n["id"]) is int and 1 <= n["id"] < 4096
        assert type(n["cost"]) is int and -10000 <= n["cost"] <= 10000
        assert re.fullmatch(settings.ENDPOINT_RE, n["endpoint"])
        assert canonical(n["subnets"])
        assert all(isinstance(v, str) and str(IPv4Address(v)) == v for v in n["vips"])
        assert isinstance(n.get("desc", ""), str) and len(n.get("desc", "")) <= 200 and n.get("desc", "").isprintable()
        assert type(n.get("simple", False)) is bool
        assert len(n.get("dns", [])) <= 8 and all(model.dns_name(d) == d for d in n.get("dns", []))
        assert not n.get("public") or str(IPv4Address(n["public"])) == n["public"]
        assert re.fullmatch(settings.ENDPOINT_RE, n.get("transit", "")) and re.fullmatch(
            settings.NAME_RE, n.get("via", "x")
        )
        assert canonical(n.get("public_nets", [])) and (not n.get("transit") or (n["via"] and n["public_nets"]))
        assert len(n.get("labels", [])) <= 16 and all(
            isinstance(l, str) and re.fullmatch(settings.LABEL_RE, l) for l in n.get("labels", [])
        )
        return True
    except Exception:
        return False


def valid_nets(pk, r):
    try:
        assert re.fullmatch(settings.KEY_RE, pk) and type(r["seq"]) is int and len(json.dumps(r)) < 16384
        assert len(r["nets"]) <= 64 and canonical(r["nets"])
        assert re.fullmatch(settings.ENDPOINT_RE, r.get("wants", ""))
        assert all(type(i) is int for i in r.get("sees", [])) and len(r.get("sees", [])) < 4096
        assert all(k.isdigit() and type(v) is int for k, v in r.get("rtt", {}).items()) and len(r.get("rtt", {})) < 256
        assert type(r.get("primary", 0)) in (int, type(None)) and type(r.get("admin", False)) is bool
        assert isinstance(r.get("code", ""), str) and isinstance(r.get("update") or {}, dict)
        h = r.get("health") or {"ok": True, "problems": []}
        assert (
            type(h["ok"]) is bool
            and len(h["problems"]) <= 20
            and all(isinstance(p, str) and len(p) <= 200 for p in h["problems"])
        )
        assert len(r.get("edges", [])) <= 40 and all(
            str(IPv4Address(e["ip"])) == e["ip"]
            and re.fullmatch(settings.NAME_RE, e["via"])
            and re.fullmatch(settings.NAME_RE, e["peer"])
            and type(e["bytes"]) is int
            for e in r.get("edges", [])
        )
        assert len(r.get("events", [])) <= 40 and all(
            type(e["t"]) is int
            and isinstance(e["k"], str)
            and len(e["k"]) <= 16
            and isinstance(e["m"], str)
            and len(e["m"]) <= 160
            for e in r.get("events", [])
        )
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
    if "dns" in n:
        n["dns"] = [model.dns_name(d) or sys.exit(f"{d!r} is not a host name") for d in listed(n["dns"])]
    n["endpoint"] = norm_endpoint(n["endpoint"])
    if n.get("public"):
        try:
            n["public"] = str(IPv4Address(n["public"]))
        except ValueError as e:
            sys.exit(f"bad public address: {e}")
        if any(IPv4Address(n["public"]) in net for net in (mesh_net(mesh), cluster_net(mesh))):
            sys.exit(f"{n['public']} is a mesh address, not a public one")
        delivered = [IPv4Network(p) for t in transits(live(nodes)).values() for p in t["public_nets"]]
        if not any(IPv4Address(n["public"]) in net for net in delivered):
            sys.exit(f"{n['public']} lies in no network an external gateway delivers (see `meshbone gateway`)")
    else:
        n.pop("public", None)
    if n.get("transit"):
        n["transit"] = norm_endpoint(n["transit"])
        n["public_nets"] = [str(IPv4Network(p)) for p in listed(n.get("public_nets", []))]
        gateway = named(nodes, n.get("via") or "")[1]
        if not gateway or not gateway["endpoint"]:
            sys.exit(f"{n.get('via')!r} is not a hub; an external gateway links to one hub")
        if n["endpoint"] or n["subnets"] or n["vips"]:
            sys.exit("an external gateway has a WireGuard endpoint and public networks, nothing else")
    if not wellformed(pk, n) or not n["id"] < mesh_net(mesh).num_addresses:
        sys.exit("bad name, endpoint, cost, description (200 printable characters) or label (letters, digits, _.:=/-)")
    others = {k: o for k, o in live(nodes).items() if k != pk}
    if any(same_name(o["name"], n["name"]) for o in others.values()):
        sys.exit(f"name {n['name']} is already taken")
    if n.get("public") and any(o.get("public") == n["public"] for o in others.values()):
        sys.exit(f"public address {n['public']} already belongs to another node")
    for v in map(IPv4Address, n["vips"]):
        if v not in cluster_net(mesh) or v in (admin_vip(mesh), metrics_vip(mesh), dns_vip(mesh)):
            sys.exit(
                f"{v} is not a free address in the cluster range {mesh['cluster_net']} "
                f"({admin_vip(mesh)}, {metrics_vip(mesh)} and {dns_vip(mesh)} belong to the hubs: map, metrics, DNS)"
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
    if not isinstance(msg, dict) or msg.get("v") != settings.VERSION:
        return False
    mesh, nodes, nets = local()["mesh"], load(), load_nets()
    theirs = msg.get("nets")
    if only:  # a client speaks for itself - and, as an admin node, for the routers it manages
        allowed = {only}
        theirs = {k: v for k, v in theirs.items() if k in allowed} if isinstance(theirs, dict) else {}
    conf = load_conf()
    a = lww(nodes, msg.get("nodes"), lambda pk, n: valid(mesh, pk, n))
    b = lww(nets, theirs, valid_nets)
    c = lww(conf, msg.get("conf"), lambda name, r: valid_conf(mesh, name, r))
    if a:
        save(nodes)
    if b:
        save_nets(nets)
    if c:
        write(f"{settings.DIR}/conf.json", json.dumps(conf, indent=1, sort_keys=True))
    return a or b or c


def conf_put(name, value):
    """Store one mesh-wide setting, signed (call it under the lock)."""
    conf = load_conf()
    conf[name] = seal(
        {"value": value, "seq": next_seq(conf.get(name, {}).get("seq", 0))}, lambda r: conf_signable(name, r)
    )
    write(f"{settings.DIR}/conf.json", json.dumps(conf, indent=1, sort_keys=True))


def session_file(sid):
    return f"{settings.SESSIONS}/{sid}.json" if re.fullmatch(r"[\w-]{10,60}", sid or "") else None


def session_open(peer):
    """Start a web session for the browser at address `peer` -> (session id, session public key).
    It can do nothing until the browser returns a token for that key."""
    from cryptography.hazmat.primitives import serialization as ser

    os.makedirs(settings.SESSIONS, mode=0o700, exist_ok=True)
    now = time.time()
    for name in os.listdir(settings.SESSIONS):  # forget sessions that have run out or were never completed
        try:
            with open(f"{settings.SESSIONS}/{name}") as f:
                s = json.load(f)
            over = now > s.get("exp", s["born"] + 600)
        except (OSError, ValueError, KeyError):
            over = True
        if over:
            with contextlib.suppress(OSError):
                os.remove(f"{settings.SESSIONS}/{name}")
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
        assert nbf <= now + 120 and now < exp and 0 < exp - nbf <= settings.SESSION_MAX + 120
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


def kept_key(node_id):
    """The private key of a node whose key the admin nodes keep (simple clients, external gateways)."""
    conf = load_conf()
    record = conf.get(f"node_{node_id}") or conf[f"simple_{node_id}"]
    return password_box().decrypt(record["value"].encode()).decode()


def policy():
    """The mesh's firewall policy -> {"default": "allow" | "deny", "rules": [{from, to, ports, action}]}.
    Without one, everything is allowed."""
    try:
        p = json.loads(load_conf()["policy"]["value"])
        assert p["default"] in ("allow", "deny") and isinstance(p["rules"], list)
        return p
    except (KeyError, ValueError, AssertionError, TypeError):
        return {"default": "allow", "rules": []}


def dns_settings(mesh):
    """The mesh's DNS: {zone, upstream}. The zone is where every node has a name; what is not
    in it is asked of the upstream resolvers, in order."""
    try:
        d = json.loads(load_conf()["dns"]["value"])
        assert model.dns_name(d["zone"]) and d["upstream"] and all(IPv4Address(u) for u in d["upstream"])
        return {"zone": d["zone"].lower(), "upstream": d["upstream"]}
    except (KeyError, ValueError, AssertionError, TypeError):
        return {"zone": f"{mesh['name'].lower()}.internal", "upstream": ["1.1.1.1", "8.8.8.8"]}


def code_sha(path=None):
    """The version of a copy of this program: the SHA-256 of the file ('' if it is not there)."""
    try:
        with open(path or settings.BIN, "rb") as f:
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
    return f"{settings.DIR}/releases/{sha}.pyz"


def audit(kind, **detail):
    """Append one line to this node's update log (and to its events)."""
    line = json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": kind, **detail})
    with open(f"{settings.DIR}/audit.log", "a") as f:
        f.write(line + "\n")
    settings.log(f"audit: {line}")
    event("update", f"{kind}: " + " ".join(f"{k}={str(v)[:40]}" for k, v in detail.items() if k != "node"))


def event(kind, text):
    """Note something that happened on this node: a line in events.log, kept bounded, and the
    newest lines travel with the node's report so every map can show them."""
    path, line = f"{settings.DIR}/events.log", json.dumps({"t": int(time.time()), "k": kind[:16], "m": text[:160]})
    try:
        with open(path, "a") as f:
            f.write(line + "\n")
        if os.path.getsize(path) > 600_000:  # keep the newest half
            with open(path) as f:
                lines = f.readlines()
            write(path, "".join(lines[len(lines) // 2 :]))
    except OSError:
        pass
    settings.log(f"{kind}: {text}")


def recent_events(count=30):
    try:
        with open(f"{settings.DIR}/events.log") as f:
            return [json.loads(l) for l in f.readlines()[-count:]]
    except (OSError, ValueError):
        return []


def audit_tail(count=25):
    try:
        with open(f"{settings.DIR}/audit.log") as f:
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
    path = release_path(sha) if os.path.exists(release_path(sha)) else settings.BIN if code_sha() == sha else None
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
    os.makedirs(f"{settings.DIR}/releases", mode=0o700, exist_ok=True)
    with open(os.open(release_path(sha) + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(data)
    os.replace(release_path(sha) + ".tmp", release_path(sha))
    return True
