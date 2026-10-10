"""Render the map and traffic pages with a made-up mesh (3 hubs, 7 clients) to check the drawing.
python3 preview.py OUTDIR   ->  OUTDIR/map.html, OUTDIR/traffic.html"""

import importlib.util, json, math, os, random, sys, tempfile, base64, hashlib, time

sys.dont_write_bytecode = True
SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "meshbone.py")
spec = importlib.util.spec_from_file_location("meshbone", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.DIR = tempfile.mkdtemp()
m.run = lambda *a, **k: ""
key = lambda s: base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
mesh = {
    "name": "home",
    "psk": key("p"),
    "net": "10.253.254.0/23",
    "cluster_net": "10.253.253.0/24",
    "admin": "0" * 64,
    "admin_pub": key("a"),
}
spec_nodes = [
    (
        "home-hub",
        226,
        "home.example.net:51533",
        ["10.20.30.0/24", "192.168.40.0/24"],
        [],
        ["site=home"],
        "home gateway",
    ),
    ("tokyo-vps", 12, "203.0.113.9:51820", [], [], ["site=tokyo"], ""),
    ("office-gw", 77, "office.example:40000", ["10.20.0.0/16"], [], ["site=office"], "office gateway"),
    ("desktop", 257, "", [], [], ["desktop"], "main workstation"),
    ("macbook", 300, "", [], [], [], ""),
    ("iphone", 301, "", [], [], [], ""),
    ("nas", 340, "", ["192.168.50.0/24"], ["10.253.253.10"], ["storage"], ""),
    ("lab-box", 388, "", [], ["10.253.253.10"], [], ""),
    ("roger-laptop", 402, "", [], [], [], ""),
    ("old-pi", 455, "", [], [], [], ""),
]
nodes = {
    key(n): {"name": n, "id": i, "endpoint": e, "subnets": s, "vips": v, "cost": 0, "seq": 1, "labels": l, "desc": d}
    for n, i, e, s, v, l, d in spec_nodes
}
K = {n[0]: key(n[0]) for n in spec_nodes}
nets = {
    K["home-hub"]: {"sees": [12, 77, 257, 300, 301, 340, 388], "rtt": {"12": 34, "77": 6}},
    K["tokyo-vps"]: {"sees": [226, 257, 300, 340, 388, 402], "rtt": {"226": 34, "77": 41}},
    K["office-gw"]: {"sees": [226, 12, 257, 402], "rtt": {"226": 6, "12": 41}},
    K["desktop"]: {"rtt": {"226": 3, "12": 36, "77": 9}, "primary": 226, "admin": True},
    K["macbook"]: {"rtt": {"226": 12, "12": 48}, "primary": 226},
    K["iphone"]: {"rtt": {"226": 25}, "primary": 226},
    K["nas"]: {"rtt": {"226": 2, "12": 35}, "primary": 226},
    K["lab-box"]: {"rtt": {"226": 40, "12": 8}, "primary": 12},
    K["roger-laptop"]: {"rtt": {"12": 19, "77": 4}, "primary": 77},
    K["old-pi"]: {},
}
for r in nets.values():
    r.update({"nets": [], "seq": 1})
json.dump({"mesh": mesh, "key": key("k"), "pub": K["home-hub"], "cost": {}}, open(m.DIR + "/node.json", "w"))
json.dump(nodes, open(m.DIR + "/nodes.json", "w"))
json.dump(nets, open(m.DIR + "/nets.json", "w"))
random.seed(7)
now = int(time.time()) // 60 * 60
db = m.stats_db()
for reporter, peer, scale, ms in [
    (226, 257, 4e6, 3),
    (226, 340, 9e6, 2),
    (226, 300, 6e5, 12),
    (12, 388, 2e6, 8),
    (226, 12, 1.5e6, 34),
    (77, 402, 3e5, 4),
]:
    for i in range(360):
        ts = now - (360 - i) * 60
        if peer == 300 and 120 < i < 200:
            continue  # the macbook was asleep
        wave = 0.35 + 0.65 * max(0, math.sin(i / 57 + peer)) ** 2
        db.execute(
            "INSERT INTO link VALUES (?,?,?,?,?,?)",
            (
                reporter,
                peer,
                ts,
                int(scale * wave * random.uniform(0.5, 1.2) * 7.5),
                int(scale * 0.3 * wave * random.uniform(0.4, 1.3) * 7.5),
                ms + random.randint(-1, 2),
            ),
        )
db.commit()
db.close()
out = sys.argv[1]
G = lambda path: m.admin_response("GET", path, {}, b"")[1]
open(out + "/map.html", "wb").write(G("/").replace(b"<meta http-equiv=refresh content=20>", b""))
data = G(f"/api/traffic?from={now - 21600}&to={now}")
open(out + "/traffic.html", "wb").write(
    G("/traffic").replace(b"<script>", b"<script>window.fetch = async () => ({json: async () => (" + data + b")});", 1)
)
