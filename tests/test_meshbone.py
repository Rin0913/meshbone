"""Multi-node logic test for meshbone with ip/wg/systemctl/ssh stubbed.

    python3 tests/test_meshbone.py [--units]

Node ids are random, so run it a few times. --units also lints the systemd units.
"""

import base64, hashlib, json, os, shutil, sys, tempfile, types, importlib.util, subprocess, copy, io, contextlib, re, sqlite3

sys.dont_write_bytecode = True
SOURCE = os.environ.get("MESHBONE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "meshbone.py"))
spec = importlib.util.spec_from_file_location("meshbone", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
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
m.PARALLEL = 1
m.VERIFY_WAIT = 0
m.CONFIRM_WAIT = 0
m.secrets.token_urlsafe = lambda n: "s3cret"
m.shutil.which = lambda x: "/usr/sbin/" + x
D = lambda n: os.path.join(root, n)


def use(n):
    m.DIR = D(n)
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
expect_exit(lambda: m.cmd_set(S("c", label=["bad label"])), "label")

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
}  # nearest hub
assert peers[P["b"]]["allowed"] == {IP["b"] + "/32"} and peers[P["a"]]["Endpoint"] == "a.example:51533"
head, peers = wg("d")
assert "ListenPort = 40000" in head and did("d", "ip", "link", "set", "dev", "mb0", "mtu", "1380")
assert (
    did("d", "ip", "route", "add", "10.3.0.0/24")
    and not did("c", "ip", "route", "add", "10.3.0.0/24")
    and not did("c", "ip", "route", "replace")
)

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
st["stats_since"] = 0  # a client asking gets no history, and cannot inject any
use("a")
reply, _ = m.handle(IP["c"], json.dumps(st))
assert "stats" not in json.loads(reply)
use("b")
m.stats_import(idb, {"stats": [[idc, 60, "x", 1, 1], [idc, 60, 5, 5]], "totals": "junk"})
G = lambda path: m.admin_response("GET", path, {}, b"")
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
    expect_exit(cmd, "admin.key")
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
expect_exit(lambda: m.cmd_set(S("c", cost=1)), "admin.key")

# --- subnets, cluster IPs
sync("c", "d")
use("adm")
expect_exit(lambda: m.cmd_set(S("a", subnet=["172.16.0.0/16"])), "local network of d (not announced)")
expect_exit(lambda: m.cmd_set(S("d", subnet=["10.3.0.0/25"])), "announced by c")
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
assert G("/admin")[0].startswith("404")
use("adm")
R = lambda method="GET", pw="s3cret", body=b"": m.admin_response(
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
sync("a", "c")
assert str(m.router_ip(m.local()["mesh"], ph["id"])) + "/32" in wg("c")[1][P["a"]]["allowed"]
use("a")
link = [l for l in m.topology()["links"] if l["a"] == ph["id"] and l["b"] == m.load()[P["a"]]["id"]][0]
assert link["up"] and link["primary"]
with quiet:
    use("adm")
    m.cmd_simple(A(name="phone", hub="d", qr=True, out=out, desc="", label=[], ip=""))  # same device, other hub
again = open(out).read()
assert "Endpoint = d.example:40000" in again and key in again and re.search(r"PresharedKey = (\S+)", again)[1] != psk
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
st, body, ctype, extra = m.admin_response("GET", "/admin/simple?name=phone", AUTH, b"")
assert (
    st == "200 OK"
    and b"download phone.conf" in body
    and b"PrivateKey" in body
    and m.admin_response("GET", "/admin/simple?name=phone", {}, b"")[0].startswith("401")
)
st, body, ctype, extra = m.admin_response("GET", "/admin/simple?name=phone&hub=d&download=1", AUTH, b"")
assert body.decode() == again and "phone.conf" in extra
assert m.admin_response("GET", "/admin/simple?name=c", AUTH, b"")[0].startswith("404")
use("a")
assert m.admin_response("GET", "/admin/simple?name=phone", AUTH, b"")[0].startswith("404")  # a hub has no admin.key
use("adm")
body = R(
    "POST", "correct-horse", form(csrf=csrf("correct-horse"), action="invite", name="tablet", simple=1, labels="mobile")
)[1]
assert b"download tablet.conf" in body and "tablet" in names("a")
use("adm")
assert b"QR / config" in R(pw="correct-horse")[1]
use("home")
assert m.admin_response("GET", "/admin/simple?name=tablet", AUTH, b"")[0] == "200 OK"  # the other admin can show it too

# --- deploy over ssh through jump hosts, with and without passwords (ssh stubbed)
assert m.parse_chain("u1@h1:u2@h2:10.9.9.9") == [("u1@h1", None), ("u2@h2", None), ("10.9.9.9", None)]
assert m.parse_chain("u1:p@ss:w0rd@h1;u2@h2;h3") == [
    ("u1@h1", "p@ss:w0rd"),
    ("u2@h2", None),
    ("h3", None),
] and m.parse_chain("root:pw@solo") == [("root@solo", "pw")]
expect_exit(lambda: m.parse_chain("u@h;rm -rf /"), "--remote is")
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

assert tf.open(fileobj=io.BytesIO(tarball)).getnames() == ["meshbone.py", "mesh.json"]
inner = m.shlex.split(m.shlex.split(join[-1])[-1])[-1]
assert (
    'S="sudo"; $S python3 /tmp/tmp.Xy12/meshbone.py join /tmp/tmp.Xy12/mesh.json --once --listen-port 41000; rc=$?; rm -rf /tmp/tmp.Xy12'
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
assert not [d for d in os.listdir(tempfile.gettempdir()) if d.startswith("meshbone-ssh-")]  # the askpass helper is gone
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
