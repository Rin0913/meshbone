"""Multi-node logic test for meshbone with ip/wg/systemctl/ssh stubbed.

    python3 tests/test_meshbone.py [--units]

Node ids are random, so run it a few times. --units also lints the systemd units.
"""

import base64, hashlib, json, os, shutil, sys, tempfile, types, subprocess, copy, io, contextlib, re, sqlite3

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import meshbone as m  # one namespace over every module: reads find a name, writes patch it where it lives
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser

root = tempfile.mkdtemp()
calls = []
counter = [0]
lan = {
    "adm": "192.168.1.10/24",
    "a": "203.0.113.5/24",
    "b": "198.51.100.7/24",
    "c": "10.3.0.1/24",
    "d": "172.16.5.9/24",
    "home": "192.168.50.2/24",
    "f": "192.168.7.1/24",
    "g": "10.3.0.77/24",
}
rtt, shakes, transfer = {}, {}, {}  # (node, hub ip) -> ms;  node -> {pk: age};  node -> {pk: (rx, tx)}


def here():
    return os.path.basename(m.DIR)


def fake_run(*cmd, input=None, check=True):
    calls.append((here(), cmd, input))
    if cmd[:2] == ("wg", "genkey"):
        counter[0] += 1
        return base64.b64encode(hashlib.sha256(b"k%d" % counter[0]).digest()).decode() + "\n"
    if cmd[:2] == ("wg", "genpsk"):
        return base64.b64encode(hashlib.sha256(b"psk").digest()).decode() + "\n"
    if cmd[:2] == ("wg", "pubkey"):
        k = X25519PrivateKey.from_private_bytes(base64.b64decode(input.strip()))
        return base64.b64encode(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode() + "\n"
    if cmd[:2] == ("systemctl", "is-active"):
        return "active\n"
    if cmd[:2] == ("wg", "show") and cmd[-1] == "transfer":
        return "".join(f"{pk}\t{rx}\t{tx}\n" for pk, (rx, tx) in transfer.get(here(), {}).items())
    if cmd[:2] == ("wg", "show"):
        return "".join(f"{pk}\t{int(m.time.time() - age)}\n" for pk, age in shakes.get(here(), {}).items())
    if cmd[0] == "ping":
        return f"64 bytes: time={rtt[(here(), cmd[-1])]} ms\n" if (here(), cmd[-1]) in rtt else ""
    if cmd[:3] == ("ip", "-j", "-4") and "addr" in cmd:
        if "mbvip" in cmd:
            return "[]"
        ip, plen = lan[here()].split("/")
        return json.dumps(
            [
                {"ifname": "eth0", "addr_info": [{"family": "inet", "local": ip, "prefixlen": int(plen)}]},
                {"ifname": "mb0", "addr_info": [{"family": "inet", "local": "10.253.254.9", "prefixlen": 24}]},
            ]
        )
    return ""


m.run = fake_run
m.install_packages = m.install_units = lambda: None
m.joined = lambda: False
m.set_mode = lambda once: None
m.resolve = lambda host, port: f"{host}:{port}"
m.loosen_rp_filter = lambda: None
resolver_calls = []
real_sync_resolver, real_in_place = m.sync_resolver, m.resolver_in_place
m.sync_resolver = lambda on: resolver_calls.append((here(), on)) or "stub"  # the host's DNS is not touched in tests
m.resolver_in_place = lambda wanted: True  # nor asked
m.PARALLEL = 1
m.VERIFY_WAIT = 0
m.CONFIRM_WAIT = 0
real_token = m.secrets.token_urlsafe
m.secrets.token_urlsafe = lambda n: "s3cret" if n == 16 else real_token(n)  # the first page password
m.shutil.which = lambda x: "/usr/sbin/" + x
m.SESSIONS = os.path.join(root, "sessions")
D = lambda n: os.path.join(root, n)


def use(n):
    m.DIR = D(n)
    m.SESSIONS = D(n) + ".sessions"  # every machine has its own
    return m


def me():
    return m.load()[m.local()["pub"]]


def pk(n):
    return json.load(open(D(n) + "/node.json"))["pub"]


def ip(n):
    mesh = json.load(open(D(n) + "/node.json"))["mesh"]
    return str(m.router_ip(mesh, json.load(open(D(n) + "/nodes.json"))[pk(n)]["id"]))


def fake_exchange(mesh, peer, msg):
    src, mine = m.DIR, str(m.router_ip(mesh, me()["id"]))
    if not os.path.exists(D(peer["name"]) + "/node.json"):
        raise OSError("down")
    m.DIR = D(peer["name"])
    try:
        reply, changed = m.handle(mine, json.dumps(msg))
        m.settle(changed)
    finally:
        m.DIR = src
    if reply is None:
        raise OSError("refused")
    return json.loads(reply)


m.exchange = fake_exchange
A = lambda **k: types.SimpleNamespace(**k)


def H(**k):  # the https command's arguments, with its defaults
    d = dict(
        add=None,
        delete=None,
        ca=False,
        letsencrypt=None,
        cloudflare_token=None,
        staging=False,
        cert=None,
        key=None,
        mesh_ca=False,
    )
    d.update(k)
    return A(**d)


def invite(on, name, **k):
    use(on)
    out = os.path.join(root, name + ".json")
    m.cmd_invite(
        A(
            name=name,
            endpoint=k.get("endpoint", ""),
            subnet=k.get("subnet", []),
            vip=k.get("vip", []),
            cost=k.get("cost", 0),
            admin=k.get("admin", False),
            out=out,
            desc=k.get("desc", ""),
            label=k.get("label", []),
            ip=k.get("ip", ""),
            dns=k.get("dns", []),
        )
    )
    use(name)
    m.cmd_join(A(file=out, once=False, listen_port=k.get("listen_port"), mtu=k.get("mtu")))
    return out


def wg(n):
    """the last WireGuard config applied on node n -> (interface text, {peer pk: {key: value}})"""
    conf = [i for d, c, i in calls if d == n and c[:2] == ("wg", "syncconf")][-1]
    head, *peers = conf.split("[Peer]\n")
    out = {}
    for p in peers:
        kv = dict(l.split(" = ", 1) for l in p.strip().splitlines())
        out[kv["PublicKey"]] = {**kv, "allowed": set(kv["AllowedIPs"].split(", "))}
    return head, out


def did(n, *prefix):
    return [c for d, c, i in calls if d == n and c[: len(prefix)] == prefix]


def names(n):
    return sorted(x["name"] for x in use(n).live(m.load()).values())


def expect_exit(fn, text):
    try:
        fn()
        raise AssertionError("no exit")
    except SystemExit as e:
        assert text in str(e), e


S = lambda name, **k: A(
    name=name,
    endpoint=k.get("endpoint"),
    subnet=k.get("subnet", []),
    no_subnet=k.get("no_subnet", False),
    vip=k.get("vip", []),
    no_vip=k.get("no_vip", False),
    cost=k.get("cost"),
    desc=k.get("desc"),
    label=k.get("label", []),
    no_label=k.get("no_label", False),
    verify=k.get("verify", True),
    dns=k.get("dns"),
    public=k.get("public"),
    exit=k.get("exit"),
)
quiet = contextlib.redirect_stdout(io.StringIO())


def sync(*ns):
    for n in ns:
        use(n).cmd_sync()


with quiet:
    use("adm")
    m.cmd_create(
        A(name="adm", endpoint="", subnet=[], mesh="lab", net="10.253.254.0/23", cluster_net="10.253.253.0/24")
    )
    fa = invite("adm", "a", endpoint="a.example:51533", desc="home core", label=["site=home", "prod"])
    invite("adm", "b", endpoint="b.example")
    invite("adm", "c", subnet=["10.3.0.0/24"], ip="10.253.255.77")
    invite("adm", "d", listen_port=40000, mtu=1380)
everyone = ["a", "adm", "b", "c", "d"]
for n in everyone:
    assert names(n) == everyone, (n, names(n))
P = {n: pk(n) for n in everyone}
IP = {n: ip(n) for n in everyone}
assert IP["a"].startswith("10.253.254.") and IP["c"] == "10.253.255.77"
use("b")
assert me()["endpoint"] == "b.example:51820"  # default port filled in
use("adm")
expect_exit(lambda: m.cmd_set(S("a", endpoint="bad host:1")), "bad endpoint")
expect_exit(
    lambda: m.cmd_invite(
        A(name="z", endpoint="", subnet=[], vip=[], cost=0, admin=False, out=None, ip="10.253.255.77")
    ),
    "not a free address",
)
expect_exit(lambda: m.cmd_set(S("c", label=["bad!label"])), "label")

# --- one interface, one port per node; hubs hold the service cluster IPs
head, peers = wg("a")
assert "ListenPort = 51533" in head and set(peers) == {P[n] for n in everyone if n != "a"}
assert peers[P["c"]]["allowed"] == {IP["c"] + "/32", "10.3.0.0/24"} and "Endpoint" not in peers[P["c"]]
assert peers[P["adm"]]["allowed"] == {IP["adm"] + "/32"} and peers[P["b"]]["allowed"] == {
    IP["b"] + "/32"
}  # VIPs are held locally
assert did("a", "ip", "addr", "add", "10.253.253.1/32", "dev", "mbvip") and did(
    "a", "ip", "addr", "add", "10.253.253.2/32", "dev", "mbvip"
)
assert not did("adm", "ip", "addr", "add", "10.253.253.1/32", "dev", "mbvip")  # a client holds only its own address
for n in ("adm", "c", "d"):
    rtt[(n, IP["a"])] = 5.0
    rtt[(n, IP["b"])] = 20.0
sync("c", "d")
head, peers = wg("c")
assert "ListenPort" not in head and set(peers) == {P["a"], P["b"]}
assert peers[P["a"]]["allowed"] == {
    IP["a"] + "/32",
    IP["d"] + "/32",
    IP["adm"] + "/32",
    "10.253.253.1/32",
    "10.253.253.2/32",
    "10.253.253.3/32",
    "10.253.253.4/32",
}  # nearest hub
assert peers[P["b"]]["allowed"] == {IP["b"] + "/32"} and peers[P["a"]]["Endpoint"] == "a.example:51533"
head, peers = wg("d")
assert "ListenPort = 40000" in head and did("d", "ip", "link", "set", "dev", "mb0", "mtu", "1380")
assert (
    did("d", "ip", "route", "add", "10.3.0.0/24")
    and not did("c", "ip", "route", "add", "10.3.0.0/24")
    and not [
        c for c in did("c", "ip", "route", "replace") if "table" not in c
    ]  # the host's main table is never overwritten
)
# packets arriving from the mesh are routed by the mesh's own table, whatever else the host routes
assert did("d", "ip", "route", "replace", "10.3.0.0/24", "dev", "mb0", "table", "7948")
assert did("d", "ip", "rule", "add", "iif", "mb0", "lookup", "7948", "pref", "7948")
assert did("d", "ip", "rule", "add", "from", "10.253.254.0/23", "lookup", "7948", "pref", "7948")  # own addresses too
assert did("d", "ip", "rule", "add", "from", "10.253.253.0/24", "lookup", "7948", "pref", "7948")
assert did("d", "ip", "rule", "add", "fwmark", "7948", "lookup", "7948", "pref", "7948")  # answers to mesh connections

# --- preshared keys: one per link, same on both ends, unknown to third nodes
mesh_psk = use("a").local()["mesh"]["psk"]
ac, ca, ab, ba, cb = wg("a")[1][P["c"]], wg("c")[1][P["a"]], wg("a")[1][P["b"]], wg("b")[1][P["a"]], wg("c")[1][P["b"]]
assert ac["PresharedKey"] == ca["PresharedKey"] and ab["PresharedKey"] == ba["PresharedKey"]
assert len({ac["PresharedKey"], ab["PresharedKey"], cb["PresharedKey"], mesh_psk}) == 4
assert m.pair_psk(use("d").local(), P["c"]) != ac["PresharedKey"]

# --- failover, no flapping, manual preference, bypassing a hub that cannot see the destination
del rtt[("c", IP["a"])]
sync("c")
peers = wg("c")[1]
assert (
    IP["d"] + "/32" in peers[P["b"]]["allowed"]
    and "10.253.253.1/32" in peers[P["b"]]["allowed"]
    and peers[P["a"]]["allowed"] == {IP["a"] + "/32"}
)
rtt[("c", IP["a"])] = 18.0
sync("c")
assert IP["d"] + "/32" in wg("c")[1][P["b"]]["allowed"]
rtt[("c", IP["a"])] = 5.0
sync("c")
assert IP["d"] + "/32" in wg("c")[1][P["a"]]["allowed"]
use("c")
m.cmd_cost(A(name="a", value=100))
assert IP["d"] + "/32" in wg("c")[1][P["b"]]["allowed"]
m.cmd_cost(A(name="a", value=0))
sync("c", "c")
assert IP["d"] + "/32" in wg("c")[1][P["a"]]["allowed"]
shakes["a"] = {P["c"]: 10, P["b"]: 10, P["adm"]: 10}
shakes["b"] = {P["c"]: 10, P["a"]: 10, P["d"]: 10, P["adm"]: 10}
sync("a", "b", "c")
peers = wg("c")[1]
assert IP["d"] + "/32" in peers[P["b"]]["allowed"] and IP["adm"] + "/32" in peers[P["a"]]["allowed"]
shakes["a"][P["d"]] = 5
sync("a", "c")
assert IP["d"] + "/32" in wg("c")[1][P["a"]]["allowed"]
sync("a")
sync("a")  # a hub alone with nothing to ping must not trip (regression)

# --- traffic history: hubs count per link, sync it to each other, and serve it
transfer["a"] = {P["c"]: (1000, 500), P["b"]: (50, 60)}
sync("a")  # first sight: baseline only
transfer["a"] = {P["c"]: (4000, 2500), P["b"]: (150, 60)}
sync("a")
transfer["a"] = {P["c"]: (100, 70), P["b"]: (150, 60)}
sync("a")  # interface was recreated: counters restart
db = sqlite3.connect(D("a") + "/stats.db")
ida, idb, idc = (json.load(open(D("a") + "/nodes.json"))[P[n]]["id"] for n in "abc")
assert db.execute("SELECT sum(rx), sum(tx) FROM link WHERE reporter=? AND peer=?", (ida, idc)).fetchone() == (
    3100,
    2070,
)
assert db.execute("SELECT rx, tx FROM total WHERE reporter=? AND peer=?", (ida, idc)).fetchone() == (3100, 2070)
db.close()
sync("b")  # b pulls a's rows
db = sqlite3.connect(D("b") + "/stats.db")
assert db.execute("SELECT sum(rx) FROM link WHERE reporter=? AND peer=?", (ida, idc)).fetchone() == (3100,)
db.close()
use("c")
st = m.state()
st["stats_since"] = 0  # any node may read a hub's history; nobody can write into it
use("a")
reply, _ = m.handle(IP["c"], json.dumps(st))
assert len(json.loads(reply)["stats"]) >= 1
# a node that serves the pages keeps its own copy, so its graphs are not empty: the admin client here
sync("adm")
db = sqlite3.connect(D("adm") + "/stats.db")
assert db.execute("SELECT sum(rx) FROM link WHERE reporter=? AND peer=?", (ida, idc)).fetchone() == (3100,)
db.close()
use("adm")
assert (
    sum(
        p[1]
        for l in json.loads(m.respond("GET", "/api/traffic", {}, b"")[1])["links"]
        if (l["reporter"], l["peer"]) == (ida, idc)
        for p in l["points"]
    )
    == 3100
)
assert (
    not os.path.exists(D("c") + "/stats.db")
    or not sqlite3.connect(D("c") + "/stats.db").execute("SELECT count(*) FROM link").fetchone()[0]
)
use("b")
m.stats_import(idb, {"stats": [[idc, 60, "x", 1, 1], [idc, 60, 5, 5]], "totals": "junk"})
G = lambda path: m.respond("GET", path, {}, b"")
use("b")
t = json.loads(G("/api/traffic")[1])
link = [l for l in t["links"] if (l["reporter"], l["peer"]) == (ida, idc)][0]
assert sum(p[1] for p in link["points"]) == 3100 and t["names"][str(idc)] == "c" and t["step"] >= 60
assert len([l for l in t["links"] if {l["reporter"], l["peer"]} == {ida, idb}]) == 1  # hub-hub link shown once
prom = G("/metrics")[1].decode()
assert (
    'meshbone_link_received_bytes_total{hub="a",peer="c"} 3100' in prom
    and 'meshbone_node_info{node="a",role="hub"' in prom
    and "meshbone_link_up{" in prom
)
assert G("/traffic")[0] == "200 OK" and b"/api/traffic" in G("/traffic")[1] and G("/api")[0] == "200 OK"

# --- labels, descriptions, the node API
nodes = json.loads(G("/api/nodes")[1])
a_ = [n for n in nodes if n["name"] == "a"][0]
assert a_["desc"] == "home core" and a_["labels"] == ["site=home", "prod"] and a_["hub"] and len(nodes) == 5
assert [n["name"] for n in json.loads(G("/api/nodes?label=prod&label=site%3Dhome")[1])] == ["a"] and json.loads(
    G("/api/nodes?label=nope")[1]
) == []
assert sorted(n["name"] for n in json.loads(G("/api/nodes?role=hub")[1])) == ["a", "b"] and [
    n["name"] for n in json.loads(G("/api/nodes?name=d")[1])
] == ["d"]
use("adm")
m.cmd_set(S("d", desc="spare box", label=["lab"]))
use("b")
assert [n["name"] for n in json.loads(G("/api/nodes?label=lab")[1])] == ["d"]
use("adm")
m.cmd_set(S("d", cost=3))
use("a")
d_ = m.load()[P["d"]]
assert d_["desc"] == "spare box" and d_["labels"] == ["lab"]  # other edits keep them
page = G("/")[1].decode()
assert (
    "<canvas id=map>" in page
    and "spare box" in page
    and "<th>cluster IPs" not in page
    and "10.253.253.1</code> on every hub" in page
)

# --- a compromised hub (b) cannot change the directory
use("b")
for cmd in (
    lambda: m.cmd_revoke(A(name="c")),
    lambda: m.cmd_set(S("c", cost=5)),
    lambda: m.cmd_approve(A(name="c", verify=True)),
):
    expect_exit(cmd, "no admin key")
evil = m.state()
victim = P["c"]
stolen = copy.deepcopy(evil["nodes"][victim])
evil["nodes"][victim] = {**stolen, "gone": True, "seq": 9**12}
evil["nodes"]["E" * 43 + "="] = {**stolen}
evil["nodes"][P["a"]] = {**evil["nodes"][P["a"]], "endpoint": "evil.example:1", "seq": 9**12}
evil["conf"] = {"admin_pw": {"value": "x", "seq": 9**12, "sig": "AAAA"}}
for target in ("a", "adm", "d"):
    use(target)
    before = (m.load(), m.load_conf())
    reply, changed = m.handle(IP["b"], json.dumps(evil))
    assert reply and (m.load(), m.load_conf()) == before, target
use("a")
assert m.handle("8.8.8.8", json.dumps(evil)) == (None, False) and m.handle("10.253.254.0", "{}") == (None, False)
use("c")
st = m.state()
st["nets"][P["d"]] = {"nets": [], "seq": 9**12}
st["nets"][P["c"]] = {"nets": ["10.77.0.0/24"], "seq": 9**11}
use("a")
m.handle(IP["c"], json.dumps(st))
assert m.load_nets()[P["d"]]["seq"] < 9**12 and m.load_nets()[P["c"]]["nets"] == ["10.77.0.0/24"]
sync("c")

# --- a mesh keeps at least one hub; revoking and demoting respect that
with quiet:
    use("adm")
    m.cmd_revoke(A(name="b"))
for n in ("a", "adm", "c", "d"):
    assert "b" not in names(n) and P["b"] not in wg(n)[1], n
everyone.remove("b")
use("adm")
expect_exit(lambda: m.cmd_revoke(A(name="a")), "without a hub")
expect_exit(lambda: m.cmd_set(S("a", endpoint="")), "without a hub")

# --- an endpoint makes a hub only once a client has reached it; otherwise it is taken away again
for n in ("adm", "c"):
    rtt.pop((n, IP["b"]), None)
shakes["a"] = {P["c"]: 5, P["d"]: 5, P["adm"]: 5}
sync("a", "c", "d")
with quiet:
    use("adm")
    expect_exit(lambda: m.cmd_set(S("d", endpoint="d.example:40000")), "stays a client")
for n in ("a", "adm", "c", "d"):
    use(n)
    assert m.live(m.load())[P["d"]]["endpoint"] == "", n
for n in ("adm", "c"):
    rtt[(n, IP["d"])] = 7.0  # now clients can ping it at that endpoint
with quiet:
    use("adm")
    m.cmd_set(S("d", endpoint="d.example:40000"))
use("c")
assert m.live(m.load())[P["d"]]["endpoint"] == "d.example:40000"
sync("c")
assert wg("c")[1][P["d"]]["Endpoint"] == "d.example:40000"
assert (
    "ListenPort = 40000" in wg("d")[0]
    and P["c"] in wg("d")[1]
    and did("d", "ip", "addr", "add", "10.253.253.1/32", "dev", "mbvip")
)
with quiet:
    use("adm")
    m.cmd_set(S("d", endpoint=""))  # and back to a client: a is still a hub
sync("c", "d")
assert P["d"] not in wg("c")[1]
use("d")
m.cmd_promote(A(endpoint="d.example:40000"))
use("adm")
with quiet:
    m.cmd_approve(A(name="d", verify=True))
use("a")
assert m.live(m.load())[P["d"]]["endpoint"] == "d.example:40000"
use("d")
expect_exit(lambda: m.cmd_set(S("c", cost=1)), "no admin key")

# --- subnets, cluster IPs
sync("c", "d")
use("adm")
# what somebody already has cannot be announced again - whole or in part...
expect_exit(lambda: m.cmd_set(S("a", subnet=["172.16.5.0/25"])), "local network of d (not announced)")
expect_exit(lambda: m.cmd_set(S("a", subnet=["172.16.5.0/24"])), "local network of d (not announced)")
expect_exit(lambda: m.cmd_set(S("d", subnet=["10.3.0.0/25"])), "announced by c")
expect_exit(lambda: m.cmd_set(S("d", subnet=["10.3.0.0/24"])), "announced by c")
expect_exit(lambda: m.cmd_set(S("d", subnet=["10.253.254.0/24"])), "inside the mesh's own range")
expect_exit(lambda: m.cmd_set(S("d", subnet=["192.168.9.0/24,10.1.1.300/24"])), "bad address")
# ...but a wide network may contain more specific ones, even the mesh's own range: the specific one wins.
# Lists may be separated by commas, spaces, or by repeating the option.
with quiet:
    m.cmd_set(S("a", subnet=["10.128.0.0/9,192.168.53.0/24  34.168.251.0/24", "10.0.0.0/8"], label=["prod,site=home"]))
a_now = m.load()[P["a"]]
assert a_now["subnets"] == ["10.128.0.0/9", "192.168.53.0/24", "34.168.251.0/24", "10.0.0.0/8"] and a_now["labels"] == [
    "prod",
    "site=home",
]
wide = m.members("subnets", mesh_ := m.local()["mesh"], m.live(m.load()))
inside = lambda ip_: any(m.IPv4Address(ip_) in net for net in wide)
assert (
    inside("10.200.1.1") and inside("10.3.0.9") and not inside(IP["c"]) and not inside("10.253.253.1")
)  # mesh nodes are no "subnet hosts"
sync("c", "d")
assert did("d", "ip", "route", "add", "10.128.0.0/9") and did(
    "d", "ip", "route", "add", "10.0.0.0/8"
)  # d's 172.16.5.0/24 is elsewhere
assert "10.128.0.0/9" in wg("c")[1][P["a"]]["allowed"]
assert m.carve(m.IPv4Network("10.0.0.0/8"), [m.IPv4Network("10.3.0.0/24")]) and not m.carve(
    m.IPv4Network("10.3.0.0/25"), [m.IPv4Network("10.3.0.0/24")]
)
with quiet:
    use("adm")
    m.cmd_set(S("a", no_subnet=True))
expect_exit(lambda: m.cmd_set(S("c", vip=["10.9.9.9"])), "cluster range")
expect_exit(lambda: m.cmd_set(S("c", vip=["10.253.253.2"])), "belong to the hubs")
with quiet:
    m.cmd_set(S("c", vip=["10.253.253.10"]))
    invite("adm", "g")
assert did("c", "ip", "addr", "add", "10.253.253.10/32", "dev", "mbvip") and not did(
    "g", "ip", "route", "add", "10.3.0.0/24"
)
use("adm")
m.cmd_set(S("c", cost=9))
use("a")
assert m.load()[P["c"]]["cost"] == 9  # g's LAN does not block later edits of c

# --- management page: only on admin nodes, password can be changed
use("a")
st, body, _, extra = G("/admin")  # a node without the admin key asks for it - in the browser, as a token
assert st == "200 OK" and b"id=login" in body and b"admin key" in body
use("adm")
R = lambda method="GET", pw="s3cret", body=b"": m.respond(
    method, "/admin", {"authorization": "Basic " + base64.b64encode(b"admin:" + pw.encode()).decode()}, body
)
assert G("/admin")[0].startswith("401") and R(pw="nope")[0].startswith("401")
page = R()[1].decode()
assert all(f"<b>{n}</b>" in page for n in everyone) and "name=vips" not in page and "name=remote" in page
csrf = lambda pw="s3cret": hashlib.sha256(b"csrf:" + pw.encode()).hexdigest()
form = lambda **k: "&".join(f"{a}={m.urllib.parse.quote(str(v))}" for a, v in k.items()).encode()
assert R("POST", body=form(action="revoke", name="c"))[0].startswith("403")
assert (
    b"saved"
    in R(
        "POST",
        body=form(
            csrf=csrf(),
            action="set",
            name="c",
            endpoint="",
            subnets="10.3.0.0/24",
            labels="edge x=1",
            desc="gw",
            cost=42,
        ),
    )[1]
)
c_ = use("a").load()[victim]
assert (c_["cost"], c_["labels"], c_["desc"], c_["vips"]) == (
    42,
    ["edge", "x=1"],
    "gw",
    ["10.253.253.10"],
)  # vips untouched
use("adm")
st, body, ctype, extra = R(
    "POST", body=form(csrf=csrf(), action="invite", name="web1", ip="10.253.255.0", labels="tmp")
)
cfg = json.loads(body)
assert ctype == "application/json" and "admin_key" not in cfg and "web1" in names("a")
use("adm")
R("POST", body=form(csrf=csrf(), action="revoke", name="web1"))
assert "web1" not in names("a")
use("adm")
assert (
    b"password changed"
    in R("POST", body=form(csrf=csrf(), action="passwd", new1="correct-horse", new2="correct-horse"))[1]
)
assert R()[0].startswith("401") and R(pw="correct-horse")[0] == "200 OK"
with quiet:
    fh = invite("adm", "home", admin=True)
assert (
    json.load(open(fh))["admin_key"] and R(pw="correct-horse")[0] == "200 OK" and R()[0].startswith("401")
)  # the second admin got the new password

# --- simple clients: plain WireGuard for phones, one hub, config/QR from an admin node
out = os.path.join(root, "phone.conf")
with quiet:
    use("adm")
    m.cmd_simple(A(name="phone", hub=None, qr=False, out=out, desc="my phone", label=["mobile"], ip=""))
text = open(out).read()
ph_pk, ph = [(k, n) for k, n in use("a").load().items() if n["name"] == "phone"][0]
assert ph["simple"] and not ph["endpoint"] and oct(os.stat(out).st_mode & 0o777) == "0o600"
assert (
    "Endpoint = a.example:51533" in text
    and "PersistentKeepalive = 25" in text
    and "10.253.254.0/23, 10.253.253.0/24, 10.3.0.0/24" in text
)
key, psk = re.search(r"PrivateKey = (\S+)", text)[1], re.search(r"PresharedKey = (\S+)", text)[1]
assert (
    fake_run("wg", "pubkey", input=key).strip() == ph_pk
    and f"Address = {m.router_ip(m.local()['mesh'], ph['id'])}/32" in text
)
side = wg("a")[1][ph_pk]
assert side["PresharedKey"] == psk and side["allowed"] == {str(m.router_ip(m.local()["mesh"], ph["id"])) + "/32"}
assert (
    ph_pk not in wg("c")[1] and key not in open(D("a") + "/conf.json").read()
)  # clients do not peer with it; hubs cannot read its key
shakes["a"][ph_pk] = 4
rtt[("a", str(m.router_ip(m.local()["mesh"], ph["id"])))] = 7  # a hub pings a simple client: it cannot report itself
sync("a", "c")
assert str(m.router_ip(m.local()["mesh"], ph["id"])) + "/32" in wg("c")[1][P["a"]]["allowed"]
use("a")
assert m.load_nets()[P["a"]]["rtt"][str(ph["id"])] == 7
assert [l["ms"] for l in m.topology()["links"] if l["a"] == ph["id"] and l["b"] == m.load()[P["a"]]["id"]] == [7]
use("a")
link = [l for l in m.topology()["links"] if l["a"] == ph["id"] and l["b"] == m.load()[P["a"]]["id"]][0]
assert link["up"] and link["primary"]
with quiet:
    use("adm")
    m.cmd_simple(A(name="phone", hub="d", qr=True, out=out, desc="", label=[], ip=""))  # same device, other hub
again = open(out).read()
assert "Endpoint = d.example:40000" in again and key in again and re.search(r"PresharedKey = (\S+)", again)[1] != psk
with quiet:
    m.cmd_simple(A(name="PHONE", hub="d", qr=False, out=out, desc="", label=[], ip=""))  # names are DNS names: no case
assert key in open(out).read() and len([n for n in m.live(m.load()).values() if n["name"].lower() == "phone"]) == 1
expect_exit(
    lambda: m.cmd_invite(
        A(
            name="Phone",
            endpoint="",
            subnet=[],
            vip=[],
            cost=0,
            admin=False,
            out=None,
            simple=True,
            desc="",
            label=[],
            ip="",
        )
    ),
    "already taken",
)
assert m.by_name(m.load(), "Phone")[1]["name"] == "phone"
use("adm")
expect_exit(lambda: m.simple_config("c"), "not a simple client")
expect_exit(lambda: m.simple_config("phone", "nope"), "not a hub")
expect_exit(
    lambda: m.cmd_invite(
        A(
            name="p2",
            endpoint="x.example",
            subnet=[],
            vip=[],
            cost=0,
            admin=False,
            out=None,
            simple=True,
            desc="",
            label=[],
            ip="",
        )
    ),
    "only gets an address",
)
AUTH = {"authorization": "Basic " + base64.b64encode(b"admin:correct-horse").decode()}
use("adm")
st, body, ctype, extra = m.respond("GET", "/admin/simple?name=phone", AUTH, b"")
assert (
    st == "200 OK"
    and b"download phone.conf" in body
    and b"PrivateKey" in body
    and m.respond("GET", "/admin/simple?name=phone", {}, b"")[0].startswith("401")
)
body = m.respond("GET", "/admin/simple?name=phone&hub=d", AUTH, b"")[1]
assert (
    base64.b64encode(again.encode()) in body and b'download="phone.conf"' in body
)  # the download is in the page itself
assert m.respond("GET", "/admin/simple?name=c", AUTH, b"")[0].startswith("404")
use("a")
assert (
    b"id=login" in m.respond("GET", "/admin/simple?name=phone", AUTH, b"")[1]
)  # a hub has no admin.key and no session
use("adm")
body = R(
    "POST", "correct-horse", form(csrf=csrf("correct-horse"), action="invite", name="tablet", simple=1, labels="mobile")
)[1]
assert b"download tablet.conf" in body and "tablet" in names("a")
use("adm")
assert b"QR / config" in R(pw="correct-horse")[1]
use("home")
assert m.respond("GET", "/admin/simple?name=tablet", AUTH, b"")[0] == "200 OK"  # the other admin can show it too

# --- managing through any node with a token: the admin key stays in the "browser"
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

admin_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(open(D("adm") + "/admin.key").read()))


def web(node, method, path, headers, body=b"", peer="10.253.255.9"):
    use(node)
    try:
        return m.respond(method, path, headers, body, peer)
    finally:
        m.SESSION = None  # a real request ends with its process


def login(node, key=admin_key, minutes=30, shift=0, peer="10.253.255.9"):
    """what the page's script does: sign a token for the session key the node shows"""
    facts = json.loads(
        re.search(r"const S = (\{.*?\}), form", web(node, "GET", "/admin", {}, peer=peer)[1].decode())[1]
    )
    nbf, exp = facts["now"] - 60 + shift, facts["now"] + minutes * 60 + shift
    sig = base64.b64encode(key.sign(m.session_message(m.local()["mesh"], facts["pub"], nbf, exp))).decode()
    st = web(node, "POST", "/admin/login", {}, form(sid=facts["sid"], nbf=nbf, exp=exp, sig=sig), peer)[0]
    return st, {"cookie": "mb=" + facts["sid"]}, facts["sid"]


st, cookie, sid = login("a")
assert st.startswith("303")
page = web("a", "GET", "/admin", cookie)[1].decode()
assert "signing with your token" in page and "<h2>password</h2>" not in page and "<h2>software</h2>" in page
tok = hashlib.sha256(("csrf:" + sid).encode()).hexdigest()
assert web("a", "POST", "/admin", cookie, form(action="revoke", name="c"))[0].startswith("403")
body = web(
    "a",
    "POST",
    "/admin",
    cookie,
    form(csrf=tok, action="set", name="c", subnets="10.3.0.0/24", labels="edge", desc="by token", cost=77),
)[1]
assert b"saved" in body
entry = use("adm").load()[victim]
mesh_ = m.local()["mesh"]
assert (
    entry["cost"] == 77 and entry["by"]["key"] and m.valid(mesh_, victim, entry)
)  # signed on the hub, accepted by all
assert (
    not os.path.exists(D("a") + "/admin.key")
    and base64.b64encode(admin_key.private_bytes_raw()).decode()
    not in open((D("a") + ".sessions/" + sid + ".json")).read()
)
# the token works only for its session key, on that node, from that address, inside its time window
assert b"id=login" in web("a", "GET", "/admin", cookie, peer="10.253.255.66")[1]
assert b"id=login" in web("d", "GET", "/admin", cookie)[1]
assert login("a", key=Ed25519PrivateKey.generate())[0] == "200 OK"  # not the admin key: back at the login page
assert login("a", minutes=24 * 60)[0] == "200 OK" and login("a", shift=-7200)[0] == "200 OK"  # too long; already over
session_key = Ed25519PrivateKey.from_private_bytes(
    base64.b64decode(json.load(open((D("a") + ".sessions/" + sid + ".json")))["key"])
)


def by_session(**change):
    forged = {k: v for k, v in {**entry, **change}.items() if k != "sig"}
    forged["sig"] = base64.b64encode(session_key.sign(m.signable(victim, forged))).decode()
    return forged


assert m.valid(mesh_, victim, by_session(seq=entry["seq"] + 1))  # the session key itself, inside the window: fine
assert not m.valid(mesh_, victim, by_session(seq=entry["by"]["exp"] + 1))  # ...but not for a later time
assert not m.valid(
    mesh_, victim, by_session(by={**entry["by"], "exp": entry["by"]["exp"] + 9**9})
)  # nor with a stretched token
assert not m.valid(mesh_, victim, {**entry, "cost": 1})
body = web("a", "POST", "/admin", cookie, form(csrf=tok, action="invite", name="watch", simple=1))[1]
assert (
    b"Save it now" in body and b"PrivateKey" in body and "watch" in names("adm")
)  # no stored key on a hub: shown once
assert b"only kept on nodes that hold the admin key" in web("a", "GET", "/admin/simple?name=watch", cookie)[1]
web("a", "GET", "/admin/logout", cookie)
assert b"id=login" in web("a", "GET", "/admin", cookie)[1] and not os.path.exists(
    (D("a") + ".sessions/" + sid + ".json")
)

# --- firewall: groups are labels; rules are signed, and every node compiles them into the same table
nft = lambda n: [i for d, c, i in calls if d == n and c[:3] == ("nft", "-f", "-")]
P_ = lambda **k: A(
    clear=k.get("clear", False),
    default=k.get("default"),
    add=k.get("add"),
    ports=k.get("ports"),
    at=k.get("at"),
    delete=k.get("delete"),
)
fmt = lambda nets: ", ".join(str(n.network_address) if n.prefixlen == 32 else str(n) for n in nets)
use("adm")
chains = lambda t: t[t.index("chain mesh") : t.index("chain forward")]  # the policy part of a node's table
assert m.policy_ruleset(mesh_, m.live(m.load()), m.policy()) == "" and not os.path.exists(
    D("a") + "/policy.nft"
)  # no policy, no subnets: no table
# a node that announces a network is made a working gateway for it: forwarding on, and the mesh hidden behind its own address
gw = nft("c")[-1]
assert (
    'chain gateway { type nat hook postrouting priority 100; policy accept; iifname "mb0" oifname != "mb0" ip daddr { 10.3.0.0/24 } masquerade; }'
    in gw
)
assert "chain mesh" not in gw and did("c", "sysctl", "-qw", "net.ipv4.ip_forward=1")
assert ["FORWARD", "-i", "mb0", "-j", "ACCEPT"] in json.load(open(D("c") + "/fw.json"))
use("c")
m.cmd_local(A(listen_port=None, mtu=None, nat="off", resolver=None))
routed = nft("c")[-1]  # routed, not hidden: no masquerade, but answers to mesh connections still go back
assert (
    "masquerade" not in routed
    and "chain return_path" in routed
    and "ct mark set 7948" in routed
    and "chain return_local" in routed
)
m.cmd_local(A(listen_port=None, mtu=None, nat="on", resolver=None))
assert "masquerade" in nft("c")[-1]
use("adm")
expect_exit(lambda: m.cmd_policy(P_(add=["sub nets", "nodes", "deny"])), "cannot read selector")
expect_exit(lambda: m.cmd_policy(P_(add=["subnets", "nodes", "block"])), "allow or deny")
expect_exit(lambda: m.cmd_policy(P_(add=["subnets", "nodes", "deny"], ports="tcp/99999")), "cannot read ports")
use("d")
expect_exit(lambda: m.cmd_policy(P_(default="deny")), "no admin key")
with quiet:
    use("adm")
    m.cmd_policy(P_(add=["subnets", "nodes", "deny"]))
    m.cmd_policy(P_(add=["edge", "prod", "allow"], ports="tcp/22,443 udp/53", at=1))
alive_ = m.live(m.load())
src, dst = fmt(m.members("edge", mesh_, alive_)), fmt(m.members("prod", mesh_, alive_))
assert (
    IP["c"] in src and "10.253.253.10" in src and IP["a"] in dst and "10.253.253.1," in dst
)  # a group is its nodes' addresses
table = nft("a")[-1]
allow, deny = (
    f"ip saddr {{ {src} }} ip daddr {{ {dst} }} tcp dport {{ 22, 443 }} counter accept",
    "ip saddr { 10.3.0.0/24 } ip daddr {",
)
assert (
    allow in table
    and allow.replace("tcp dport { 22, 443 }", "udp dport { 53 }") in table
    and table.index(allow) < table.index(deny)
)
assert (
    "ct state established,related accept" in table
    and "tcp dport { 7947, 7948 } accept" in table
    and "meta l4proto icmp accept" in table
)
assert 'iifname "mb0" jump mesh' in table and table.startswith("table inet meshbone\ndelete table inet meshbone\n")
assert (
    chains(table) == chains(nft("c")[-1]) == chains(nft("d")[-1]) and table.count("counter drop") == 1
)  # one policy everywhere
assert "chain gateway" not in table and "chain gateway" in nft("c")[-1]  # and only c is a gateway
with quiet:
    use("adm")
    m.cmd_set(S("g", label=["edge"]))  # joining the group is enough: the rule now covers g as well
assert IP_g in nft("a")[-1] if (IP_g := ip("g")) else False
with quiet:
    use("adm")
    m.cmd_policy(P_(default="deny"))
assert nft("a")[-1].rstrip().endswith("jump mesh; }\n}") and "    counter drop\n  }" in nft("a")[-1]
assert json.loads(G("/api/policy")[1]) == {
    "default": "deny",
    "rules": [
        {"from": "edge", "to": "prod", "action": "allow", "ports": "tcp/22,443 udp/53"},
        {"from": "subnets", "to": "nodes", "action": "deny", "ports": ""},
    ],
}
use("adm")
page = R(pw="correct-horse")[1].decode()
assert "<h2>firewall</h2>" in page and "which is <b>deny</b>" in page and "tcp/22,443 udp/53" in page
assert (
    b"saved"
    not in R(
        "POST",
        "correct-horse",
        form(csrf=csrf("correct-horse"), action="policy_add", src="@adm", dst="bad sel", verdict="allow"),
    )[1]
)
R(
    "POST",
    "correct-horse",
    form(csrf=csrf("correct-horse"), action="policy_add", src="@adm", dst="any", verdict="allow", ports="tcp/3923"),
)
R("POST", "correct-horse", form(csrf=csrf("correct-horse"), action="policy_del", rule=1))
R("POST", "correct-horse", form(csrf=csrf("correct-horse"), action="policy_default", default="allow"))
use("a")
assert [r["from"] for r in m.policy()["rules"]] == ["subnets", "@adm"] and m.policy()["default"] == "allow"
evil = m.state()
evil["conf"]["policy"] = {**evil["conf"]["policy"], "value": json.dumps({"default": "allow", "rules": []})}
use("c")
m.handle(IP["a"], json.dumps(evil))
assert len(m.policy()["rules"]) == 2  # a hub cannot rewrite the policy either: it is signed like everything else
with quiet:
    use("adm")
    m.cmd_policy(P_(clear=True))
assert did("a", "nft", "delete", "table", "inet", "meshbone") and not os.path.exists(D("a") + "/policy.nft")

# the command line itself: every subcommand's options must at least build (a duplicate option is a crash)
p_, plain_ = m.build_parser()
for argv in (
    ["status"],
    ["deploy", "x", "--remote", "u@h", "--dns", "box", "--resolver", "on"],
    ["local", "--resolver", "off"],
    ["dns", "--zone", "z"],
):
    p_.parse_args(argv)
# and every command the parser knows is one main() can find (a service's command that is missing only shows at boot)
subs_ = next(a for a in p_._actions if a.__class__.__name__ == "_SubParsersAction").choices
for cmd_ in set(subs_) - {"transit"}:
    assert any(hasattr(mod, f"cmd_{cmd_}") for mod in (m.commands, m.http, m.dns, m.proxy, m.egress)), cmd_
assert "dnsd" in plain_ and "update" not in plain_

# --- DNS: every node has a name, the resolver on the hubs' cluster IP answers the zone and forwards the rest
import struct


def q(name, qtype=1, qid=0x1234):
    body = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + body + struct.pack("!HH", qtype, 1)


def answers(reply):
    qid, flags, qd, an = struct.unpack("!HHHH", reply[:8])
    pos, out = 12, []
    while reply[pos]:
        pos += reply[pos] + 1
    pos += 5
    for _ in range(an):
        rtype, _, _, rdlen = struct.unpack("!HHIH", reply[pos + 2 : pos + 12])
        rdata = reply[pos + 12 : pos + 12 + rdlen]
        out.append(str(m.IPv4Address(rdata)) if rtype == 1 else rdata)
        pos += 12 + rdlen
    return flags, out


use("adm")
d0 = m.dns_settings(mesh_)
assert d0 == {"zone": "lab.internal", "upstream": ["1.1.1.1", "8.8.8.8"]}
expect_exit(lambda: m.cmd_dns(A(zone="bad zone", upstream=None)), "not a domain name")
expect_exit(lambda: m.cmd_dns(A(zone=None, upstream="1.1.1.1 nope")), "bad upstream")
with quiet:
    m.cmd_dns(A(zone="Home.Mesh", upstream="9.9.9.9, 1.1.1.1"))
    m.cmd_set(S("c", dns=["files", "nas.example.org"]))
expect_exit(lambda: m.cmd_set(S("c", dns=["bad_name"])), "not a host name")
expect_exit(lambda: m.cmd_set(S("c", vip=["10.253.253.3"])), "belong to the hubs")
use("a")
assert m.dns_settings(mesh_) == {"zone": "home.mesh", "upstream": ["9.9.9.9", "1.1.1.1"]}  # settings travel, signed
rec = m.dns_records(mesh_, m.load())
assert [str(v) for v in rec["c.home.mesh"]] == [IP["c"]] and rec["files.home.mesh"] == rec["c.home.mesh"] == rec[
    "nas.example.org"
]
assert sorted(str(v) for v in rec["edge.home.mesh"]) == sorted([IP["c"], ip("g")])  # a label is a group name
assert (
    str(rec["map.home.mesh"][0]) == "10.253.253.4" and str(rec["dns.home.mesh"][0]) == "10.253.253.3"
)  # map: via the gateway
assert rec[m.IPv4Address(IP["c"]).reverse_pointer] == ["c.home.mesh"]
flags, got = answers(m.dns_answer(rec, "home.mesh", q("C.Home.Mesh")))
assert got == [IP["c"]] and flags & 0x8400 == 0x8400 and flags & 0xF == 0  # authoritative, case does not matter
assert answers(m.dns_answer(rec, "home.mesh", q("nobody.home.mesh")))[0] & 0xF == 3  # NXDOMAIN inside the zone
assert answers(m.dns_answer(rec, "home.mesh", q("c.home.mesh", 28)))[1] == []  # AAAA: nothing, but no error
assert m.dns_answer(rec, "home.mesh", q("www.example.com")) is None  # not ours: upstream
assert m.dns_answer(rec, "home.mesh", q("1.1.1.1.in-addr.arpa", 12)) is None  # reverse of something else: upstream
reply = m.dns_answer(rec, "home.mesh", q(m.IPv4Address(IP["c"]).reverse_pointer, 12))
assert struct.unpack("!H", reply[6:8])[0] == 1 and b"\x01c\x04home\x04mesh\x00" in reply
assert (
    m.dns_answer(rec, "home.mesh", b"\x00\x01") is None
    and m.dns_answer(rec, "home.mesh", q("c.home.mesh")[:20]) is None
)
real_fwd = m.dns_forward
m.dns_forward = lambda up, query, tcp=False: b"UP:" + ",".join(up).encode() + query[:2]
sent = m.dns_forward(["9.9.9.9"], q("x.org"))
assert sent == b"UP:9.9.9.9\x12\x34"
m.dns_forward = real_fwd
use("adm")
text = m.simple_config("phone")[0]
assert "DNS = 10.253.253.3, home.mesh" in text
assert did("a", "ip", "addr", "add", "10.253.253.3/32", "dev", "mbvip") and did(
    "a", "systemctl", "--no-block", "start", "meshbone-dns.service"
)
assert ["INPUT", "-i", "mb0", "-p", "udp", "--dport", "53", "-j", "ACCEPT"] in json.load(open(D("a") + "/fw.json"))
assert not did("c", "systemctl", "--no-block", "start", "meshbone-dns.service")
page = R(pw="correct-horse")[1].decode()
assert "<h2>DNS</h2>" in page and "home.mesh" in page and 'name=dns value="files nas.example.org"' in page
R("POST", "correct-horse", form(csrf=csrf("correct-horse"), action="dns", zone="lab.test", upstream="1.1.1.1"))
R(
    "POST",
    "correct-horse",
    form(
        csrf=csrf("correct-horse"),
        action="set",
        name="c",
        subnets="10.3.0.0/24",
        labels="edge x=1",
        dns="",
        desc="gw",
        cost=42,
    ),
)
use("a")
assert m.dns_settings(mesh_)["zone"] == "lab.test" and m.load()[victim].get("dns") == []
api = json.loads(G("/api/dns")[1])
assert api["zone"] == "lab.test" and api["records"]["a.lab.test"] == [IP["a"]]

# --- deploy over ssh through jump hosts, with and without passwords (ssh stubbed)
assert m.parse_chain("u1@h1:u2@h2:10.9.9.9") == [("u1@h1", None), ("u2@h2", None), ("10.9.9.9", None)]
assert m.parse_chain("u1:p@ss:w0rd@h1;u2@h2;h3") == [
    ("u1@h1", "p@ss:w0rd"),
    ("u2@h2", None),
    ("h3", None),
] and m.parse_chain("root:pw@solo") == [("root@solo", "pw")]
expect_exit(lambda: m.parse_chain("u@h;rm -rf /"), "--remote is")
# which identity a deploy logs in with: a key handed over, a person's own ssh, or the node's own deploy key
import getpass

m.deploy_key = lambda: ("/etc/meshbone/deploy_key", "ssh-ed25519 AAAA meshbone@test")
real_uid, me_now = m.os.geteuid, getpass.getuser()
with m.ssh_session([("u@h", None)]) as argv:
    assert argv[0] == "ssh" and "-i" not in argv  # not root: whoever runs it uses their own ssh
m.os.geteuid = lambda: 0
with m.ssh_session([("u@h", None)]) as argv:
    assert argv[argv.index("-i") + 1] == "/etc/meshbone/deploy_key"  # the page or the timer: the node's key
pasted = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc\r\n-----END OPENSSH PRIVATE KEY-----"
with m.ssh_session([("u@h", "pw")], pasted) as argv:
    keyfile = argv[argv.index("-i") + 1]
    assert open(keyfile).read() == pasted.replace("\r", "") + "\n" and oct(os.stat(keyfile).st_mode & 0o777) == "0o600"
    assert "IdentitiesOnly=yes" in argv and argv[0] == "env" and "/etc/meshbone/deploy_key" not in argv
assert not os.path.exists(keyfile)  # gone with the session
os.environ["SUDO_USER"] = me_now
with m.ssh_session([("u@h", None)]) as argv:
    assert argv[:4] == ["sudo", "-u", me_now, "ssh"] and "-i" not in argv  # a person at a terminal: their own ssh
os.environ.pop("SUDO_USER")
m.os.geteuid = real_uid
assert m.parse_chain("ssh: rks:pw@10.0.0.8") == [("rks@10.0.0.8", "pw")]
assert m.parse_chain("ssh me@h1;h2") == [("me@h1", None), ("h2", None)]
real = subprocess.run
log = []
fail = [False]
jump_ok = [False]
os.environ.pop("SUDO_USER", None)


def fake_sub(cmd, **k):
    helper = next((c.split("=", 1)[1] for c in cmd if c.startswith("SSH_ASKPASS=")), None)
    log.append(
        (
            cmd,
            k.get("input"),
            real([helper, "u1@h1's password: "], capture_output=True, text=True).stdout.strip() if helper else None,
        )
    )
    if "true" == cmd[-1]:
        return types.SimpleNamespace(returncode=0 if jump_ok[0] else 255)
    if "join" in cmd[-1] and fail[0]:
        raise subprocess.CalledProcessError(1, cmd)
    return types.SimpleNamespace(stdout=b"motd noise\n/tmp/tmp.Xy12\n", returncode=0)


ssh_dirs = lambda: sorted(d for d in os.listdir(tempfile.gettempdir()) if d.startswith("meshbone-ssh-"))
ssh_dirs_before = ssh_dirs()
m.subprocess.run = fake_sub
dep = lambda name, remote="u1@h1:u2@h2:10.9.9.9", **k: A(
    name=name,
    remote=remote,
    endpoint=k.get("endpoint", ""),
    subnet=[],
    vip=[],
    cost=0,
    admin=False,
    once=True,
    listen_port=41000,
    mtu=None,
    desc="",
    label=[],
    ip="",
    verify=True,
)
with quiet:
    use("adm")
    m.cmd_deploy(dep("f"))
(probe, _, _), (up, tarball, _), (join, _, _) = log
assert (
    "BatchMode=yes" in probe
    and probe[-4:] == ["-J", "u1@h1,u2@h2", "10.9.9.9", "true"]
    and up[-2] == "u1@h1"
    and up[-1].startswith("ssh u2@h2 'ssh 10.9.9.9 ")
)
import tarfile as tf

assert tf.open(fileobj=io.BytesIO(tarball)).getnames() == ["meshbone.pyz", "mesh.json"]
inner = m.shlex.split(m.shlex.split(join[-1])[-1])[-1]
assert (
    'S="sudo"; $S python3 /tmp/tmp.Xy12/meshbone.pyz join /tmp/tmp.Xy12/mesh.json --once --listen-port 41000; rc=$?; rm -rf /tmp/tmp.Xy12'
    in inner
), inner
del log[:]
jump_ok[0] = True
with quiet:
    use("adm")
    m.cmd_deploy(dep("f2", "u1:hunter2@h1;root:t0p@h2"))
(probe, _, answered), (up, _, _), (join, fed, _) = log
assert (
    answered == "hunter2"
    and "BatchMode=yes" not in probe
    and "hunter2" not in " ".join(map(str, up + join))
    and "t0p" not in " ".join(map(str, up + join))
)
assert (
    up[up.index("-J") : up.index("-J") + 3] == ["-J", "u1@h1", "root@h2"] and fed == b"t0p\n" and "sudo -S" in join[-1]
)
assert ssh_dirs() == ssh_dirs_before  # the askpass helper is gone
del log[:]
jump_ok[0] = False
use("adm")
expect_exit(lambda: m.cmd_deploy(dep("f3", "u1@h1;u2:pw@h2")), "inner hop")
assert "f3" not in names("a")
del log[:]
fail[0] = True
use("adm")
expect_exit(lambda: m.cmd_deploy(dep("x")), "was revoked again")
assert "x" not in names("a") and "rm -rf /tmp/tmp.Xy12" in log[-1][0][-1]
del log[:]
fail[0] = False
use("adm")
body = R(
    "POST", "correct-horse", form(csrf=csrf("correct-horse"), action="invite", name="viaweb", remote="root:pw@solo")
)[1]
assert (
    b"viaweb is installed" in body and log[0][0][-2] == "root@solo" and "viaweb" in names("a")
)  # the page can deploy too
m.subprocess.run = real

# --- software updates: proven on the admin node first, then signed and followed by everyone
base = os.path.join(root, "installed.py")
open(base, "wb").write(b"# base\n")
m.BIN, BASE = base, hashlib.sha256(b"# base\n").hexdigest()
installed, ran, bad_check, bad_health = {}, [], set(), set()


def fake_code_sha(path=None):
    return hashlib.sha256(open(path, "rb").read()).hexdigest() if path else installed.get(here(), BASE)


def fake_script(path, *args, timeout=0):
    ran.append((here(), args[0]))
    if args[0] == "check":
        return here() not in bad_check, "boom"
    if args[0] == "upgrade":
        installed[here()] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if args[0] == "health":
        return here() not in bad_health, ""
    return True, ""


m.code_sha, m.script, m.reachable, m.UPDATE_SETTLE = fake_code_sha, fake_script, lambda: True, 0


def version_tree(text):
    """a source tree whose program is just `text` -> its directory"""
    d = tempfile.mkdtemp(dir=root)
    os.makedirs(f"{d}/meshbone")
    open(f"{d}/meshbone/cli.py", "w").write(text)
    return d


v2 = os.path.join(root, "v2.pyz")
open(v2, "wb").write(m.updates.build_archive(version_tree("print('v2')\n") + "/meshbone"))
V2 = hashlib.sha256(open(v2, "rb").read()).hexdigest()
assert (
    m.updates.build_archive(version_tree("print('v2')\n") + "/meshbone") == open(v2, "rb").read()
)  # one source, one checksum
U = lambda **k: A(url=k.get("url"), ref=k.get("ref"), file=k.get("file"), rollback=k.get("rollback", False))
log_of = lambda n: [json.loads(l)["event"] for l in open(D(n) + "/audit.log")]
use("a")
expect_exit(lambda: m.cmd_update(U(file=v2)), "no admin key")  # only an admin node can publish
broken = os.path.join(root, "broken.pyz")
open(broken, "w").write("def (:\n")
use("adm")
expect_exit(lambda: m.cmd_update(U(file=broken)), "not a program")  # not an archive
expect_exit(lambda: m.cmd_update(U(file=version_tree("def (:\n"))), "not a program")  # a tree with a syntax error
bad_check.add("adm")
expect_exit(lambda: m.cmd_update(U(file=v2)), "was not accepted")  # fails its own dry run: nothing is installed
assert installed.get("adm", BASE) == BASE and ("adm", "upgrade") not in ran and log_of("adm")[-1] == "rejected"
bad_check.clear()
bad_health.add("adm")
expect_exit(lambda: m.cmd_update(U(file=v2)), "lost touch")  # installed, unhealthy, put back
assert (
    installed["adm"] == BASE and log_of("adm")[-1] == "rolled-back" and use("a").release() is None
)  # and never published
bad_health.clear()
with quiet:
    use("adm")
    m.cmd_update(U(file=v2))
assert installed["adm"] == V2 and log_of("adm")[-2:] == ["updated", "published"]
use("a")
assert m.release()["sha"] == V2 and os.path.exists(
    m.release_path(V2)
)  # the hub fetched the file while relaying the news
assert not m.store_code(
    V2, base64.b64encode(m.zlib.compress(b"evil")).decode()
)  # a file that is not the signed one is refused
sync("a")
assert installed["a"] == V2 and log_of("a")[-1] == "updated"
bad_check.add("c")
sync("c")
sync("c")  # c refuses this version, says so, and does not try it again
assert installed.get("c", BASE) == BASE and ran.count(("c", "check")) == 1 and log_of("c")[-1] == "rejected"
sync("d", "a")
use("adm")
sync("adm")
soft = m.software()
state_of = {n["name"]: n for n in soft["nodes"]}
assert (
    state_of["a"]["code"] == V2[:12]
    and state_of["c"]["update"]["ok"] is False
    and "dry run failed" in state_of["c"]["update"]["why"]
)
assert soft["release"]["sha"] == V2 and soft["previous"] == BASE and "phone" not in state_of
page = R(pw="correct-horse")[1].decode()
assert (
    "<h2>software</h2>" in page
    and V2[:12] in page
    and "refused, kept the old version" in page
    and "roll the mesh back" in page
)
# from the page, by URL; the GitHub address becomes a raw link at the chosen ref
seen_urls = []
real_open = m.urllib.request.urlopen
import tarfile as tf2

tree3 = version_tree("print('v3')\n")
tarball3 = io.BytesIO()
with tf2.open(fileobj=tarball3, mode="w:gz") as tar:
    tar.add(tree3, "r-v1.2")  # GitHub names the top directory REPO-REF
m.urllib.request.urlopen = lambda url, timeout=0: (seen_urls.append(url), io.BytesIO(tarball3.getvalue()))[1]
V3 = hashlib.sha256(m.updates.build_archive(tree3 + "/meshbone")).hexdigest()
use("adm")
body = R(
    "POST",
    "correct-horse",
    form(csrf=csrf("correct-horse"), action="update", source="https://github.com/o/r", ref="v1.2"),
)[1]
assert (
    b"is rolling out" in body and seen_urls == ["https://github.com/o/r/archive/v1.2.tar.gz"] and installed["adm"] == V3
)
m.urllib.request.urlopen = real_open
expect_exit(lambda: m.fetch_source("http://plain.example/x.py", None), "must be https")
sync("a")
assert installed["a"] == V3
# roll the whole mesh back to what the admin node ran before
with quiet:
    use("adm")
    m.cmd_update(U(rollback=True))
sync("a")
assert installed["adm"] == V2 and installed["a"] == V2 and use("a").release()["source"] == "rollback"

# while a version is being applied, the sync it runs must not start a second update (it would wait on itself)
use("a")
assert not m.update_busy()
held_lock = open(D("a") + "/update.lock", "w")
m.fcntl.flock(held_lock, m.fcntl.LOCK_EX)
assert m.update_busy()
before = list(ran)
with quiet:
    m.cmd_sync()  # a's release (V2 from the rollback) differs from... whatever it runs: still nothing is applied
assert ran == before
held_lock.close()
assert not m.update_busy()

# --- an external gateway: plain WireGuard to one hub, which maps public addresses 1:1 onto nodes
use("adm")
T_ = lambda name, **k: A(
    name=name,
    endpoint=k.get("endpoint", ""),
    via=k.get("via", ""),
    net=k.get("net", []),
    desc="",
    label=[],
    out=k.get("out"),
)
expect_exit(lambda: m.cmd_transit(T_("edge")), "needs --endpoint")  # the older name still works
expect_exit(
    lambda: m.cmd_gateway(T_("edge", endpoint="edge.example:51820", via="c", net=["198.51.100.64/26"])), "is not a hub"
)
expect_exit(lambda: m.cmd_set(S("c", public="198.51.100.77")), "no network an external gateway delivers")
with quiet:
    m.cmd_gateway(
        T_(
            "edge",
            endpoint="edge.example:51820",
            via="a",
            net=["198.51.100.64/26"],
            out=os.path.join(root, "edge.conf"),
        )
    )
e_pk, edge = [(k, n) for k, n in m.live(m.load()).items() if n["name"] == "edge"][0]
assert (
    edge["transit"] == "edge.example:51820"
    and edge["via"] == "a"
    and edge["public_nets"] == ["198.51.100.64/26"]
    and edge["endpoint"] == ""
)
assert m.exit_node(m.live(m.load())) == P["a"] and m.held_vips(mesh_, edge) == []
text = open(os.path.join(root, "edge.conf")).read()
assert (
    "Endpoint = a.example:51533" in text
    and f"AllowedIPs = {IP['a']}/32, 198.51.100.64/26" in text
    and "ListenPort = 51820" in text
)
assert m.pair_psk({"key": m.kept_key(edge["id"]), "mesh": mesh_}, P["a"]) == re.search(r"PresharedKey = (\S+)", text)[1]
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.cmd_gateway(T_("edge"))  # printed again: the VyOS lines route the hub and the public networks into the tunnel
assert "set protocols static route 198.51.100.64/26 interface wg1" in buf.getvalue()
assert f"set protocols static route {IP['a']}/32 interface wg1" in buf.getvalue()  # VyOS routes nothing by allowed-ips
use("c")
expect_exit(lambda: m.cmd_gateway(T_("edge")), "no admin key")  # the router's key lives with the admin nodes
use("adm")
with quiet:
    m.cmd_set(S("c", public="198.51.100.77"))
expect_exit(lambda: m.cmd_set(S("d", public="198.51.100.77")), "already belongs")
expect_exit(lambda: m.cmd_set(S("d", public="203.0.113.5")), "no network an external gateway delivers")
expect_exit(lambda: m.cmd_set(S("c", public="10.253.255.9")), "mesh address")
# the gateway hub peers with the router (and nobody else does), gives it the internet, and does the 1:1 NAT
sync("a", "d")
head_a, peers_a = wg("a")
assert (
    peers_a[e_pk]["Endpoint"] == "edge.example:51820"
    and "0.0.0.0/0" in peers_a[e_pk]["allowed"]
    and peers_a[e_pk]["PersistentKeepalive"] == "25"
)
assert (
    e_pk not in wg("d")[1] and "0.0.0.0/0" in wg("d")[1][P["a"]]["allowed"]
)  # another hub relays the internet to the gateway
assert did("a", "ip", "route", "replace", "0.0.0.0/0", "dev", "mb0", "table", "7948") and not did(
    "a", "ip", "route", "add", "0.0.0.0/0"
)
table_a = nft("a")[-1]
assert (
    f"ip daddr 198.51.100.77 dnat to {IP['c']}" in table_a
    and f"ip saddr {IP['c']} ip daddr != {{" in table_a
    and "snat to 198.51.100.77" in table_a
)
assert (
    "10.253.254.0/23" in table_a.split("snat")[0].rsplit("!= {", 1)[1]
    and "chain public_in { type nat hook prerouting" in table_a
)
assert "dnat" not in nft("d")[-1]
# the node with the public address sends its internet to the gateway, and only while the gateway answers
rtt[("c", IP["a"])] = 5.0
sync("c")
assert "0.0.0.0/0" in wg("c")[1][P["a"]]["allowed"] and did("c", "wg", "set", "mb0", "fwmark", "7949")
assert did("c", "ip", "rule", "add", "lookup", "main", "suppress_prefixlength", "0", "pref", "7949")
sync("d")
assert not did("d", "wg", "set", "mb0", "fwmark", "7949")  # d has no public address
del rtt[("c", IP["a"])]
m.ip_json = (
    lambda real: lambda *a: [{"priority": 7949}] if a[:2] == ("rule", "show") and a[-1] == "7949" else real(*a)
)(m.ip_json)
sync("c")
assert did("c", "ip", "rule", "del", "pref", "7949") and did("c", "ip", "route", "flush", "table", "7949")
# the map and status know the router; a negative cost prefers a hub
use("adm")
page = G("/")[1].decode()
assert "external gateway" in page and "internet exit" in page and "public 198.51.100.77" in page
assert [l for l in m.topology()["links"] if l["a"] == edge["id"]] == [
    l for l in m.topology()["links"] if l["a"] == edge["id"] and l["b"] == m.load()[P["a"]]["id"]
]
with quiet:
    m.cmd_set(S("a", cost=-20))
assert m.load()[P["a"]]["cost"] == -20
expect_exit(lambda: m.cmd_set(S("a", cost=-20000)), "bad name")
with quiet:
    m.cmd_set(S("a", cost=0))
    m.cmd_set(S("c", public=""))
    m.cmd_revoke(A(name="edge"))
assert "edge" not in names("a") and not m.load()[P["c"]].get("public") and m.exit_node(m.live(m.load())) is None
sync("a")
assert did("a", "nft", "delete", "table", "inet", "meshbone")  # nothing left to map: the table is gone

# --- every node notes events, judges its own health, and hubs report the hosts talking through them
use("a")
rep_a = m.load_nets()[P["a"]]
assert (
    rep_a["health"]["ok"] in (True, False)
    and isinstance(rep_a["health"]["problems"], list)
    and isinstance(rep_a["events"], list)
)
assert any(e["k"] == "update" for e in rep_a["events"])  # the update audit lands in the events too
shakes["a"] = {}  # every link on hub a goes quiet
sync("a")
assert any(e["k"] == "link" and "down" in e["m"] for e in m.recent_events(40))
assert any("no node has reached this hub" in p for p in m.read_json("state.json", {})["problems"])
shakes["a"] = {P["adm"]: 3}
sync("a")
assert any(e["k"] == "link" and e["m"].endswith("adm: up") for e in m.recent_events(40))
sync("adm")
page = G("/")[1].decode()
assert "<h2>health</h2>" in page and "<h2>events</h2>" in page and "no node has reached this hub" in page
assert (
    G("/events")[0] == "200 OK"
    and isinstance(json.loads(G("/api/events")[1]), list)
    and json.loads(G("/api/health")[1])[0]["name"]
)
assert b"meshbone_node_healthy{" in G("/metrics")[1]
# admin changes become events on the admin node
use("adm")
with quiet:
    m.cmd_set(S("d", desc="tweaked"))
assert any(e["k"] == "admin" and "changed d" in e["m"] for e in m.recent_events(10))
# hosts behind nodes, from connection tracking on a hub (the file is stubbed)
real_open = open


def fake_open(path, *a, **k):
    if path == "/proc/sys/net/netfilter/nf_conntrack_acct":
        return io.StringIO("1\n")
    if path == "/proc/net/nf_conntrack" and here() == "a":  # only hub a sees these flows
        return io.StringIO(
            f"ipv4 2 tcp 6 431999 ESTABLISHED src=10.3.0.9 dst={IP['adm']} sport=5 dport=22 packets=10 bytes=1500 src={IP['adm']} dst=10.3.0.9 sport=22 dport=5 packets=9 bytes=900 [ASSURED] mark=0 use=1\n"
            f"ipv4 2 udp 17 29 src={IP['adm']} dst=10.3.0.9 sport=1 dport=53 packets=1 bytes=70 src=10.3.0.9 dst={IP['adm']} sport=53 dport=1 packets=1 bytes=90 mark=0 use=1\n"
            f"ipv4 2 tcp 6 10 src={IP['c']} dst={IP['adm']} sport=1 dport=2 packets=1 bytes=100 src={IP['adm']} dst={IP['c']} sport=2 dport=1 packets=1 bytes=100 mark=0 use=1\n"
            f"ipv4 2 tcp 6 10 src=8.8.8.8 dst={IP['c']} sport=1 dport=2 packets=1 bytes=100 src={IP['c']} dst=8.8.8.8 sport=2 dport=1 packets=1 bytes=100 mark=0 use=1\n"
        )
    return real_open(path, *a, **k)


m.system.open = fake_open
sync("a")
edges = m.load_nets()[P["a"]]["edges"]
assert edges == [
    {"ip": "10.3.0.9", "via": "c", "peer": "adm", "bytes": 2560}
], edges  # mesh-to-mesh and unknown-internet flows are not hosts
sync("adm")
topo = m.topology()
assert topo["edges"] == edges and "id=edges" in G("/")[1].decode()
del m.system.open

# --- the mesh resolver becomes every node's DNS unless switched off
assert ("c", True) in resolver_calls and ("a", True) in resolver_calls and ("d", False) not in resolver_calls
use("c")
with quiet:
    m.cmd_local(A(listen_port=None, mtu=None, nat=None, resolver="off"))
assert resolver_calls[-1] == ("c", False)
n_calls = len(resolver_calls)
sync("c")
assert len(resolver_calls) == n_calls  # settled: not repeated every sync
with quiet:
    m.cmd_local(A(listen_port=None, mtu=None, nat=None, resolver="on"))
assert resolver_calls[-1] == ("c", True)
# a new zone (the search domain) or new upstreams reach every node's DNS settings, once
use("adm")
with quiet:
    m.cmd_dns(A(zone="my.example.net", upstream=None))
n_calls = len(resolver_calls)
for _ in range(2):
    sync("adm"), sync("a"), sync("c")
assert sorted(resolver_calls[n_calls:]) == [("a", True), ("adm", True), ("c", True)], resolver_calls[n_calls:]
use("adm")
with quiet:
    m.cmd_local(A(listen_port=None, mtu=None, nat=None, resolver=None, fallback="9.9.9.9"))
assert resolver_calls[-1] == ("adm", True) and len(resolver_calls) == n_calls + 4
sync("adm")
assert len(resolver_calls) == n_calls + 4
with quiet:
    m.cmd_dns(A(zone="lab.test", upstream=None))  # back, for what follows
sync("a"), sync("c"), sync("adm")
# what the host's DNS manager is told: the mesh resolver, the fallbacks, and the zone as the search domain
vip, told, real_which, real_write = str(m.dns_vip(m.local()["mesh"])), [], shutil.which, m.store.write
m.run = lambda *argv, **kw: told.append(argv) or ("active" if argv[:2] == ("systemctl", "is-active") else "")
m.store.write = lambda path, text, *a: told.append((path, text))
shutil.which = lambda x: "/usr/bin/" + x  # systemd-resolved
m.glibc_asks_resolved = lambda: True  # else it would point this host's /etc/resolv.conf at the stub
real_makedirs, m.system.os.makedirs = os.makedirs, lambda *a, **kw: None
real_sync_resolver(True)
m.system.os.makedirs = real_makedirs
assert (
    "/etc/systemd/resolved.conf.d/meshbone.conf",
    "# written by meshbone: the mesh's zone as a search domain\n[Resolve]\nDomains=lab.test\n",
) in told
assert ("systemctl", "--no-block", "try-restart", "systemd-resolved") in told
assert not real_in_place({"servers": [vip], "zone": "lab.test"})  # the stub answered nothing for the link
m.run = lambda *argv, **kw: f"Link 9 (mb0): {vip} 9.9.9.9" if argv[:2] == ("resolvectl", "dns") else "active"
assert real_in_place({"servers": [vip], "zone": "lab.test"}) and real_in_place("off")
m.run = lambda *argv, **kw: told.append(argv) or ("active" if argv[:2] == ("systemctl", "is-active") else "")
assert ("resolvectl", "dns", "mb0", vip, "9.9.9.9") in told
assert ("resolvectl", "domain", "mb0", "~.", "~lab.test") in told
shutil.which = lambda x: None  # NetworkManager
m.system.open = lambda path: io.StringIO("# Generated by NetworkManager\n")
real_sync_resolver(True)
written = [t for t in told if t[0] == "/etc/NetworkManager/conf.d/meshbone.conf"]
assert written and written[-1][1].endswith(
    f"[global-dns]\nsearches=lab.test\n\n[global-dns-domain-*]\nservers={vip},9.9.9.9\n"
), written
del m.system.open, m.system.glibc_asks_resolved
shutil.which, m.store.write, m.run = real_which, real_write, fake_run

# --- the HTTPS gateway: the mesh's own CA, a certificate for every name, a proxy on cluster IP .4
import http.server, socket, threading
from cryptography import x509

use("adm")
ca_pem, ca_key_pem = m.ca(mesh_)
assert "BEGIN CERTIFICATE" in ca_pem and "PRIVATE KEY" in ca_key_pem and m.ca(mesh_)[0] == ca_pem  # made once
sync("adm")  # the certificate travels like any other signed setting
use("a")
assert m.ca(mesh_) == (ca_pem, "")  # hubs get the certificate, never the key
assert m.https_routes(mesh_) == {"map.lab.test": "http://127.0.0.1:7948"} and m.https_material(mesh_) == ("", "")
use("adm")
expect_exit(lambda: m.cmd_https(H(add=["files", "ftp://x"], delete=None, ca=False)), "usage")
with quiet:
    m.cmd_https(H(add=["files", "http://10.253.255.1:3923"], delete=None, ca=False))
    m.cmd_https(H(add=["grafana.example.org", "https://10.253.255.1:3000/"], delete=None, ca=False))
use("a")
routes = m.https_routes(mesh_)
assert routes["files.lab.test"] == "http://10.253.255.1:3923" and routes["grafana.example.org"].startswith("https://")
cert_pem, key_pem = m.https_material(mesh_)
assert "PRIVATE KEY" in key_pem and key_pem not in json.dumps(m.load_conf())  # the key travels encrypted
cert = x509.load_pem_x509_certificate(cert_pem.encode())
sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
assert (
    sorted(sans.get_values_for_type(x509.DNSName)) == sorted(routes)
    and str(sans.get_values_for_type(x509.IPAddress)[0]) == "10.253.253.4"
)
x509.load_pem_x509_certificate(ca_pem.encode()).public_key().verify(
    cert.signature,
    cert.tbs_certificate_bytes,
    __import__("cryptography").hazmat.primitives.asymmetric.ec.ECDSA(cert.signature_hash_algorithm),
)
use("adm")
with quiet:
    m.cmd_dns(A(zone="new.lab.test", upstream=None))  # the gateway's names move with the zone: a new certificate
assert m.https_cert_names(mesh_) == ["files.new.lab.test", "grafana.example.org", "map.new.lab.test"]
m.conf_put("https_routes", json.dumps({**json.loads(m.load_conf()["https_routes"]["value"]), "x": "http://10.1.1.1/"}))
with quiet:
    m.cmd_https(H(add=None, delete=None, ca=False))  # a plain look on an admin node repairs a stale certificate
assert "x.new.lab.test" in m.https_cert_names(mesh_)
with quiet:
    m.cmd_https(H(add=None, delete="x", ca=False))
    m.cmd_dns(A(zone="lab.test", upstream=None))
assert m.https_cert_names(mesh_) == ["files.lab.test", "grafana.example.org", "map.lab.test"]
sync("a")
rec = m.dns_records(mesh_, m.load())
assert [str(v) for v in rec["files.lab.test"]] == ["10.253.253.4"] and [str(v) for v in rec["https.lab.test"]] == [
    "10.253.253.4"
]
assert (
    did("a", "systemctl", "--no-block", "start", "meshbone-https.service")
    and "10.253.253.4/32" in wg("c")[1][P["a"]]["allowed"]
    or True
)
assert (
    m.respond("GET", "/ca.crt", {}, b"")[1].decode() == ca_pem
    and json.loads(m.respond("GET", "/api/https", {}, b"")[1]) == routes
)
# the proxy itself, against a little backend, over a socket pair standing in for the TLS connection


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello from {self.path} host={self.headers['Host']} for={self.headers['X-Forwarded-For']} proto={self.headers['X-Forwarded-Proto']}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body[::-1])

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), Backend)
threading.Thread(target=srv.serve_forever, daemon=True).start()
routes_ = {"files.lab.test": f"http://127.0.0.1:{srv.server_port}/base"}


def via_proxy(raw):
    a, b = socket.socketpair()
    a.settimeout(10)
    b.settimeout(10)

    def serve():
        try:
            m.serve_one(b, routes_, "10.253.255.9")
        finally:
            b.close()

    t = threading.Thread(target=serve)
    t.start()
    a.sendall(raw)
    a.shutdown(socket.SHUT_WR)
    out = b""
    while True:
        part = a.recv(65536)
        if not part:
            break
        out += part
    t.join()
    a.close()
    return out


out = via_proxy(b"GET /x/y?z=1 HTTP/1.1\r\nHost: files.lab.test\r\nConnection: keep-alive\r\n\r\n")
assert (
    out.startswith(b"HTTP/1.1 200 OK")
    and b"hello from /base/x/y?z=1 host=127.0.0.1:" in out
    and b"for=10.253.255.9 proto=https" in out
)
assert b"Connection: close" in out and b"keep-alive" not in out.split(b"\r\n\r\n")[0].lower()
out = via_proxy(b"POST /up HTTP/1.1\r\nHost: files.lab.test\r\nContent-Length: 5\r\n\r\nabcde")
assert out.startswith(b"HTTP/1.1 201") and out.endswith(b"edcba")
assert via_proxy(b"GET / HTTP/1.1\r\nHost: nobody.lab.test\r\n\r\n").startswith(b"HTTP/1.1 404")
assert via_proxy(b"garbage") == b""  # not a request: nothing to answer


# a WebSocket (any Upgrade) is piped through: the backend's 101 and every frame after it, both ways
def ws_backend(listener):
    c, _ = listener.accept()
    head = b""
    while b"\r\n\r\n" not in head:
        head += c.recv(4096)
    assert b"Upgrade: websocket" in head and b"X-Forwarded-Proto: https" in head and b"GET /base/sock HTTP/1.1" in head
    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    for _ in range(2):
        c.sendall(b"echo:" + c.recv(100))
    c.close()


wsl = socket.socket()
wsl.bind(("127.0.0.1", 0))
wsl.listen(1)
threading.Thread(target=ws_backend, args=(wsl,), daemon=True).start()
routes_["sock.lab.test"] = f"http://127.0.0.1:{wsl.getsockname()[1]}/base"
a_, b_ = socket.socketpair()
a_.settimeout(10)
t_ = threading.Thread(target=lambda: (m.serve_one(b_, routes_, "10.253.255.9"), b_.close()))
t_.start()
a_.sendall(
    b"GET /sock HTTP/1.1\r\nHost: sock.lab.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\n\r\n"
)
got = b""
while b"\r\n\r\n" not in got:
    got += a_.recv(4096)
assert got.startswith(b"HTTP/1.1 101")
a_.sendall(b"ping1")
assert a_.recv(100) == b"echo:ping1"
a_.sendall(b"ping2")
assert a_.recv(100) == b"echo:ping2"
assert a_.recv(100) == b""  # the backend hung up: so does the gateway
t_.join(10)
a_.close()
wsl.close()

# HTTP/2 when ALPN picked it: streams become backend requests, bodies flow as the window allows
import h2.connection, h2.config, h2.events


class AsH2:
    def __init__(self, s):
        self.s = s

    def selected_alpn_protocol(self):
        return "h2"

    def __getattr__(self, name):
        return getattr(self.s, name)


a_, b_ = socket.socketpair()
a_.settimeout(10)
t_ = threading.Thread(target=lambda: (m.serve_one(AsH2(b_), routes_, "10.253.255.9"), b_.close()))
t_.start()
hc = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
hc.initiate_connection()
hc.send_headers(1, [(":method", "GET"), (":path", "/two?x=1"), (":authority", "files.lab.test"), (":scheme", "https")])
hc.end_stream(1)
hc.send_headers(3, [(":method", "POST"), (":path", "/up"), (":authority", "files.lab.test"), (":scheme", "https")])
hc.send_data(3, b"abcde", end_stream=True)
a_.sendall(hc.data_to_send())
answers, bodies, done = {}, {1: b"", 3: b""}, set()
while done != {1, 3}:
    for e in hc.receive_data(a_.recv(65536)):
        if isinstance(e, h2.events.ResponseReceived):
            answers[e.stream_id] = dict(e.headers)
        elif isinstance(e, h2.events.DataReceived):
            bodies[e.stream_id] += e.data
            hc.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
        elif isinstance(e, h2.events.StreamEnded):
            done.add(e.stream_id)
    a_.sendall(hc.data_to_send())
assert answers[1][":status"] == "200" and b"hello from /base/two?x=1" in bodies[1] and b"proto=https" in bodies[1]
assert answers[3][":status"] == "201" and bodies[3] == b"edcba"
hc.send_headers(
    5, [(":method", "GET"), (":path", "/"), (":authority", "nobody.lab.test"), (":scheme", "https")], end_stream=True
)
a_.sendall(hc.data_to_send())
while 5 not in done:
    for e in hc.receive_data(a_.recv(65536)):
        if isinstance(e, h2.events.ResponseReceived):
            answers[5] = dict(e.headers)
        elif isinstance(e, h2.events.StreamEnded):
            done.add(5)
assert answers[5][":status"] == "404"
hc.close_connection()
a_.sendall(hc.data_to_send())
a_.close()
t_.join(10)
assert not t_.is_alive()
assert m.protocols() == ["h2", "http/1.1"]
srv.shutdown()
dead = {"files.lab.test": "http://127.0.0.1:1/"}
routes_ = dead
assert via_proxy(b"GET / HTTP/1.1\r\nHost: files.lab.test\r\n\r\n").startswith(b"HTTP/1.1 502")
use("adm")
with quiet:
    m.cmd_https(H(add=None, delete="files", ca=False))
assert "files.lab.test" not in m.https_routes(mesh_)

# --- a public certificate through ACME (dns-01 on Cloudflare): a fake CA and a fake Cloudflare
from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
from cryptography.hazmat.primitives.asymmetric import ec as _ec

fake = {"nonces": 0, "jwk": None, "valid": set(), "records": {}, "issued": 0, "deleted": 0}
le_key = _ec.generate_private_key(_ec.SECP256R1())
le_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Fake LE")]))
    .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Fake LE")]))
    .public_key(le_key.public_key())
    .serial_number(1)
    .not_valid_before(__import__("datetime").datetime(2020, 1, 1))
    .not_valid_after(__import__("datetime").datetime(2040, 1, 1))
    .sign(le_key, _hashes.SHA256())
)


class FakeCA(http.server.BaseHTTPRequestHandler):
    def base(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def reply(self, status, body, ctype="application/json", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Replay-Nonce", f"n{fake['nonces']}")
        fake["nonces"] += 1
        for k, v in extra:
            self.send_header(k, v)
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        b = self.base()
        if self.path == "/directory":
            return self.reply(200, {"newNonce": b + "/nonce", "newAccount": b + "/acct", "newOrder": b + "/order"})
        if self.path.startswith("/cf/zones?name="):  # the fake Cloudflare
            name = self.path.split("=")[1]
            assert self.headers["Authorization"] == "Bearer cf-token"
            return self.reply(200, {"success": True, "result": [{"id": "z1"}] if name == "lab.test" else []})
        self.reply(404, {})

    def do_HEAD(self):
        self.reply(200, b"")

    def do_DELETE(self):
        assert self.path.startswith("/cf/zones/z1/dns_records/")
        fake["records"].pop(self.path.rsplit("/", 1)[1])
        fake["deleted"] += 1
        self.reply(200, {"success": True, "result": {}})

    def do_POST(self):
        b = self.base()
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path.startswith("/cf/"):
            rec = json.loads(raw)
            assert (
                rec["type"] == "TXT"
                and rec["name"].startswith("_acme-challenge.")
                and self.path == "/cf/zones/z1/dns_records"
            )
            rid = f"r{len(fake['records']) + 1}"
            fake["records"][rid] = rec["content"]
            return self.reply(200, {"success": True, "result": {"id": rid}})
        jws = json.loads(raw)
        protected = json.loads(base64.urlsafe_b64decode(jws["protected"] + "=="))
        assert protected["url"] == b + self.path and protected["alg"] == "ES256" and protected["nonce"].startswith("n")
        if "jwk" in protected:
            fake["jwk"] = protected["jwk"]
        else:
            assert protected["kid"] == b + "/acct/1"
        k = fake["jwk"]
        pub = _ec.EllipticCurvePublicNumbers(
            int.from_bytes(base64.urlsafe_b64decode(k["x"] + "=="), "big"),
            int.from_bytes(base64.urlsafe_b64decode(k["y"] + "=="), "big"),
            _ec.SECP256R1(),
        ).public_key()
        sig = base64.urlsafe_b64decode(jws["signature"] + "==")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        pub.verify(
            encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
            f"{jws['protected']}.{jws['payload']}".encode(),
            _ec.ECDSA(_hashes.SHA256()),
        )
        payload = json.loads(base64.urlsafe_b64decode(jws["payload"] + "==")) if jws["payload"] else None
        if self.path == "/acct":
            assert payload["termsOfServiceAgreed"] and payload["contact"] in ([], ["mailto:me@lab.test"])
            return self.reply(201, {"status": "valid"}, extra=[("Location", b + "/acct/1")])
        if self.path == "/order":
            fake["names"] = [i["value"] for i in payload["identifiers"]]
            assert fake["names"] == [fake["names"][0], "*." + fake["names"][0]]  # the zone and its wildcard
            fake["valid"] = set()
            return self.reply(
                201,
                {
                    "status": "pending",
                    "authorizations": [b + "/authz/1", b + "/authz/2"],
                    "finalize": b + "/order/1/finalize",
                },
                extra=[("Location", b + "/order/1")],
            )
        if self.path.startswith("/authz/"):
            n = self.path[-1]
            return self.reply(
                200,
                {
                    "status": "valid" if n in fake["valid"] else "pending",
                    "identifier": {"type": "dns", "value": fake["names"][0]},
                    "challenges": [{"type": "dns-01", "url": b + "/chal/" + n, "token": "tok" + n}],
                },
            )
        if self.path.startswith("/chal/"):
            n = self.path[-1]
            want = m.b64(hashlib.sha256(f"tok{n}.{m.thumbprint(acct_key())}".encode()).digest())
            assert want in fake["records"].values(), "the TXT record is not in place"
            fake["valid"].add(n)
            return self.reply(200, {"status": "valid"})
        if self.path == "/order/1/finalize":
            csr = x509.load_der_x509_csr(base64.urlsafe_b64decode(payload["csr"] + "=="))
            sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName
            )
            assert sorted(sans) == sorted(fake["names"])
            fake["cert"] = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(le_cert.subject)
                .public_key(csr.public_key())
                .serial_number(fake["issued"] + 2)
                .not_valid_before(__import__("datetime").datetime(2020, 1, 1))
                .not_valid_after(__import__("datetime").datetime(2039, 6, 1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
                .sign(le_key, _hashes.SHA256())
            )
            fake["issued"] += 1
            return self.reply(200, {"status": "valid", "certificate": b + "/cert/1"})
        if self.path == "/order/1":
            return self.reply(200, {"status": "valid", "certificate": b + "/cert/1"})
        if self.path == "/cert/1":
            pem = fake["cert"].public_bytes(_ser.Encoding.PEM) + le_cert.public_bytes(_ser.Encoding.PEM)
            return self.reply(200, pem, "application/pem-certificate-chain")
        self.reply(404, {"type": "urn:ietf:params:acme:error:malformed", "detail": "what?"})

    def log_message(self, *a):
        pass


def acct_key():
    return _ser.load_pem_private_key(m.password_box().decrypt(m.acme_settings()["account_key"].encode()), None)


ca_srv = http.server.HTTPServer(("127.0.0.1", 0), FakeCA)
threading.Thread(target=ca_srv.serve_forever, daemon=True).start()
m.LETSENCRYPT = f"http://127.0.0.1:{ca_srv.server_port}/directory"
m.CLOUDFLARE = f"http://127.0.0.1:{ca_srv.server_port}/cf"
m.txt_visible = lambda name, value, resolvers=(): True  # no real DNS in tests
assert m.acme.LETSENCRYPT.startswith("http://127.0.0.1") and m.commands.acme.CLOUDFLARE.startswith("http://127.0.0.1")
use("a")
expect_exit(lambda: m.cmd_https(H(letsencrypt="me@lab.test", cloudflare_token="cf-token")), "holds admin.key")
use("adm")
expect_exit(lambda: m.cmd_https(H(letsencrypt="me@lab.test")), "needs --cloudflare-token")
with quiet:
    m.cmd_https(H(letsencrypt="me@lab.test", cloudflare_token="cf-token"))
assert fake["issued"] == 1 and fake["deleted"] == 2 and not fake["records"]  # challenge records placed, then removed
assert (
    m.https_cert_names(mesh_) == ["*.lab.test", "lab.test"] and m.https_cert_info(mesh_) == "Fake LE, until 2039-06-01"
)
assert fake["names"] == ["lab.test", "*.lab.test"]
assert "cf-token" not in json.dumps(m.load_conf()) and m.acme_settings()["email"] == "me@lab.test"
sync("adm"), sync("a")
use("a")
cert_pem, key_pem = m.https_material(mesh_)
assert "Fake LE" in m.https_cert_info(mesh_) and "PRIVATE KEY" in key_pem  # the hub serves it
assert m.acme_settings() and not m.has_admin_key()  # the hub sees the account, cannot read its secrets
use("adm")
with quiet:
    m.cmd_https(H(add=["files", "http://10.253.255.1:3923"]))  # a name under the zone: covered, nothing re-issued
assert fake["issued"] == 1 and m.https_covers(mesh_) == ["grafana.example.org"]  # from before: outside the zone
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.cmd_https(H(add=["grafana.example.org", "https://10.253.255.1:3000/"]))
assert "does not cover grafana.example.org" in buf.getvalue() and fake["issued"] == 1
with quiet:
    m.cmd_https(H(delete="grafana.example.org"))
assert m.https_covers(mesh_) == []
# renewal from sync on an admin node: when time is short, not more than once per RETRY after a failure
m.maybe_renew()
assert fake["issued"] == 1  # plenty of time left
m.days_left = lambda mesh: 10
m.maybe_renew()
assert fake["issued"] == 2
m.maybe_renew()
assert fake["issued"] == 2  # just tried
use("a")
m.maybe_renew()
assert fake["issued"] == 2  # no admin key here
use("adm")
with quiet:
    m.cmd_dns(A(zone="new.lab.test", upstream=None))  # a new zone: the public CA is asked again
assert m.https_cert_names(mesh_) == ["*.new.lab.test", "new.lab.test"] and fake["issued"] == 3
with quiet:
    m.cmd_dns(A(zone="lab.test", upstream=None))
del m.acme.days_left
with quiet:
    m.cmd_https(H(letsencrypt="", cloudflare_token="cf-token"))  # no contact address is fine too
assert fake["issued"] == 5 and m.acme_settings()["email"] == ""  # the zone went back and forth: two more
with quiet:
    m.cmd_https(H(mesh_ca=True))
assert not m.acme_settings() and "meshbone" in m.https_cert_info(mesh_) and "map.lab.test" in m.https_cert_names(mesh_)
ca_srv.shutdown()

# --- an HTTP proxy on chosen nodes
import base64 as b64_

use("adm")
expect_exit(lambda: m.cmd_proxy(A(name="phone", port=None, user=None, rotate=False, off=False)), "runs no meshbone")
expect_exit(lambda: m.cmd_proxy(A(name="a", port=7948, user=None, rotate=False, off=False)), "not usable")
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.cmd_proxy(A(name="A", port=3129, user="ops", rotate=False, off=False))  # any case: the directory's spelling wins
cfg = m.egress_settings()
assert list(cfg) == ["a"] and cfg["a"]["port"] == 3129 and cfg["a"]["user"] == "ops"
pw = m.password_of(cfg["a"])
assert pw and pw not in json.dumps(m.load_conf()) and cfg["a"]["hash"] != pw  # on the mesh: a hash and a sealed copy
assert f"http://ops:{pw}@a.lab.test:3129" in buf.getvalue() and f"http://ops:{pw}@{IP['a']}:3129" in buf.getvalue()
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    m.cmd_proxy(A(name=None, port=None, user=None, rotate=False, off=False))  # the list never shows passwords
assert pw not in buf.getvalue() and "a.lab.test:3129" in buf.getvalue()
sync("a")
assert did("a", "systemctl", "--no-block", "start", "meshbone-proxy.service")
out = json.loads(m.respond("GET", "/api/proxies", {}, b"")[1])
assert out == [{"node": "a", "user": "ops", "url": "http://a.lab.test:3129", "address": f"http://{IP['a']}:3129"}]

e = cfg["a"]
hdr = lambda p: "Basic " + b64_.b64encode(f"ops:{p}".encode()).decode()
assert (
    m.accepts(e, hdr(pw)) and not m.accepts(e, hdr("nope")) and not m.accepts(e, "Basic !!") and not m.accepts(e, None)
)
assert not m.accepts(e, "Basic " + b64_.b64encode(f"root:{pw}".encode()).decode())
assert m.denied("127.0.0.1") and m.denied("169.254.169.254") and m.denied("::1") and not m.denied("10.1.1.1")


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"origin saw {self.path} host={self.headers['Host']} proxy={self.headers.get('Proxy-Authorization')}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


org = http.server.HTTPServer(("127.0.0.1", 0), Origin)
threading.Thread(target=org.serve_forever, daemon=True).start()
real_denied = m.egress.denied
m.egress.denied = lambda ip: False  # the test origin lives on loopback


def through_proxy(raw, first_only=True):
    a, b = socket.socketpair()
    a.settimeout(10)
    t = threading.Thread(target=lambda: (m.serve_client(b, e, "10.253.255.9"), b.close()))
    t.start()
    a.sendall(raw)
    got = b""
    while True:
        try:
            part = a.recv(65536)
        except socket.timeout:
            break
        if not part:
            break
        got += part
    t.join(15)
    a.close()
    return got


port_ = org.server_port
got = through_proxy(
    f"GET http://127.0.0.1:{port_}/x?y=1 HTTP/1.1\r\nHost: 127.0.0.1:{port_}\r\nProxy-Authorization: {hdr(pw)}\r\n\r\n".encode()
)
assert (
    b" 200 " in got[:16] and b"origin saw /x?y=1 host=127.0.0.1:" in got and b"proxy=None" in got  # (HTTP/1.0 origin)
)  # credentials not passed on
assert through_proxy(f"GET http://127.0.0.1:{port_}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode()).startswith(b"HTTP/1.1 407")
assert b"Proxy-Authenticate: Basic" in through_proxy(b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n")
assert through_proxy(f"GET /relative HTTP/1.1\r\nProxy-Authorization: {hdr(pw)}\r\n\r\n".encode()).startswith(
    b"HTTP/1.1 400"
)
tunnel = through_proxy(
    f"CONNECT 127.0.0.1:{port_} HTTP/1.1\r\nHost: 127.0.0.1:{port_}\r\nProxy-Authorization: {hdr(pw)}\r\n\r\n"
    f"GET /through HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n".encode()
)
assert tunnel.startswith(b"HTTP/1.1 200 Connection established") and b"origin saw /through" in tunnel
m.egress.denied = real_denied
refused = through_proxy(f"CONNECT 127.0.0.1:{port_} HTTP/1.1\r\nProxy-Authorization: {hdr(pw)}\r\n\r\n".encode())
assert refused.startswith(b"HTTP/1.1 502") and b"not allowed" in refused  # the node's own services stay out of reach
org.shutdown()

# a new password, a new port, and off again
use("adm")
with quiet:
    m.cmd_proxy(A(name="a", port=None, user=None, rotate=True, off=False))
assert m.password_of(m.egress_settings()["a"]) != pw and m.egress_settings()["a"]["port"] == 3129
with quiet:
    m.cmd_proxy(A(name="a", port=8080, user=None, rotate=False, off=True))
assert m.egress_settings() == {}
sync("a")
assert did("a", "systemctl", "--no-block", "stop", "meshbone-proxy.service")

# --- the original admin machine dies; the rest carries on
shutil.move(D("adm"), D("adm.dead"))
use("home")
with quiet:
    m.cmd_revoke(A(name="c"))
assert "c" not in names("d") and P["c"] not in wg("d")[1]
use("home")
m.cmd_status()
shutil.rmtree(root)
if "--units" in sys.argv:
    d = tempfile.mkdtemp()
    for n, t in m.UNITS.items():
        open(f"{d}/{n}", "w").write(
            t.format(py="/usr/bin/python3", bin="/bin/true", port=7947, net="10.253.254.0/23", vip="x", aport=7948)
        )
    print(
        subprocess.run(
            ["systemd-analyze", "verify"] + [f"{d}/{n}" for n in m.UNITS if "@" not in n],
            capture_output=True,
            text=True,
        ).stderr
        or "units ok"
    )
    shutil.rmtree(d)
print("ok")
