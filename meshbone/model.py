"""MODEL: computations over the directory - the routing table, firewall and router configurations, DNS records, traffic history, views' data."""

import base64, hmac, os, re, socket, sqlite3, struct, sys, time
from ipaddress import IPv4Address, IPv4Network, collapse_addresses

from . import settings, store, system


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

    The exit node, if there is one, gets everything else (0.0.0.0/0): on hubs, so
    they relay for it and accept the internet's addresses from it; on a node with
    a public address, whose internet goes out through it.
    """
    mesh, mypk, alive = loc["mesh"], loc["pub"], store.live(nodes)
    me = alive[mypk]
    hub = bool(me["endpoint"])
    gateway = store.exit_node(alive) == mypk
    peers = {pk: n for pk, n in alive.items() if pk != mypk and not n.get("transit") and (hub or n["endpoint"])}
    if gateway:  # only the gateway hub is linked to the transit routers
        peers.update({pk: n for pk, n in store.transits(alive).items() if n["via"] == me["name"]})
    table = {pk: [] for pk in peers}
    if not peers:
        return table, None
    owners = {}
    for pk, n in alive.items():
        for p in store.prefixes(mesh, n):
            owners.setdefault(p, []).append(pk)
    via_exit = store.exit_node(alive)
    if gateway:  # the internet, inbound and outbound, is behind the transit routers
        for pk in store.transits(alive):
            if pk in table:
                table[pk].append(IPv4Network("0.0.0.0/0"))
    elif via_exit in peers and (hub or me.get("public")):
        table[via_exit].append(IPv4Network("0.0.0.0/0"))
    if hub:
        for p, own in owners.items():
            own = [pk for pk in own if pk in table]  # a transit router is only the gateway's peer
            if mypk in owners[p] or not own:
                continue
            table[min(own, key=lambda pk: (seen.get(pk, float("inf")), pk))].append(
                p
            )  # several holders: the one heard from last
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


def transit_config(name):
    """The WireGuard side of a transit router -> (config text, its entry, the hub it is linked to).
    The hub's addresses and the public networks are what the router may send through the tunnel."""
    loc, nodes, nets = store.admin()
    mesh, alive = loc["mesh"], store.live(nodes)
    pk, n = store.by_name(nodes, name)
    if not n.get("transit"):
        sys.exit(f"{name} is not a transit router")
    gpk, gateway = store.named(alive, n["via"])
    if not gateway:
        sys.exit(f"the hub {n['via']} that {name} links to is gone; revoke the router and add it again")
    key = store.kept_key(n["id"])
    text = (
        f"# mesh {mesh['name']}: transit router {name}, linked to hub {gateway['name']}\n[Interface]\nPrivateKey = {key}\n"
        f"Address = {store.router_ip(mesh, n['id'])}/32\nListenPort = {n['transit'].rpartition(':')[2]}\n\n[Peer]\nPublicKey = {gpk}\n"
        f"PresharedKey = {pair_psk({'key': key, 'mesh': mesh}, gpk)}\nEndpoint = {gateway['endpoint']}\n"
        f"AllowedIPs = {', '.join([str(store.router_ip(mesh, gateway['id'])) + '/32'] + n['public_nets'])}\nPersistentKeepalive = 25\n"
    )
    return text, n, {**gateway, "pk": gpk}


def simple_config(name, hub=None, key=None):
    """A standard WireGuard config for a simple client -> (text, hub used, all hub names).

    Plain WireGuard cannot choose between hubs, so the device sends everything through
    one of them; pick another and import again if that hub is ever down. The config
    lists the networks known right now - it does not follow later changes by itself.
    The device's key is `key` if it was just created here, else the copy the admin
    nodes keep.
    """
    loc, nodes, nets = store.admin()
    mesh, alive = loc["mesh"], store.live(nodes)
    pk, n = store.by_name(nodes, name)
    if not n.get("simple"):
        sys.exit(f"{name} is not a simple client")
    try:
        key = key or store.kept_key(n["id"])
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
        f"Address = {store.router_ip(mesh, n['id'])}/32\nDNS = {store.dns_vip(mesh)}, {store.dns_settings(mesh)['zone']}\n\n[Peer]\nPublicKey = {hub_pk}\n"
        f"PresharedKey = {pair_psk({'key': key, 'mesh': mesh}, hub_pk)}\nEndpoint = {h['endpoint']}\n"
        f"AllowedIPs = {', '.join(reach)}\nPersistentKeepalive = 25\n"
    )
    return text, hub, list(hubs)


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
        chosen = [n for n in alive.values() if store.same_name(n["name"], name[1:])]
    elif re.fullmatch(settings.LABEL_RE, name):
        chosen = [n for n in alive.values() if name in n.get("labels", [])]
    else:
        sys.exit(f"cannot read selector {selector!r}")
    nets = []
    for n in chosen:
        if part:
            for s in n["subnets"]:  # a wide announced network still does not make mesh nodes "subnet hosts"
                nets += store.carve(IPv4Network(s), [store.mesh_net(mesh), store.cluster_net(mesh)])
        else:
            nets += [IPv4Network(f"{ip}/32") for ip in [store.router_ip(mesh, n["id"])] + store.held_vips(mesh, n)]
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
        f"{match('saddr', members('nodes', mesh, alive))}tcp dport {{ {settings.GOSSIP_PORT}, {settings.ADMIN_PORT} }} accept",
        f"ip daddr {store.dns_vip(mesh)} meta l4proto {{ tcp, udp }} th dport 53 accept",
        f"ip daddr {store.https_vip(mesh)} tcp dport {settings.HTTPS_PORT} accept",
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
        f'  chain input {{ type filter hook input priority 0; policy accept; iifname "{settings.IFACE}" jump mesh; }}\n'
        f'  chain forward {{ type filter hook forward priority 0; policy accept; iifname "{settings.IFACE}" jump mesh; '
        f'iifname != "{settings.IFACE}" oifname "{settings.IFACE}" jump mesh; }}\n'
    )


def gateway_ruleset(mesh, me, nat, public=(), inside=()):
    """What makes a node a working gateway for the networks it announces -> nftables text, or ''.

    `public`, on the hub a transit router is linked to, maps public addresses 1:1 onto nodes:
    [(public address, node's mesh address)]. Inbound, a packet for the public address is handed
    to the node; outbound, what the node sends to the internet (not to `inside`: the mesh and
    its subnets) leaves as the public address.

    The hosts in such a network know nothing about the mesh: they would send their answers to
    their own default router, and the connection would never complete. So whatever comes out of
    the mesh for an announced network leaves the gateway with the gateway's own address there
    (masquerade); answers then come back to it and it hands them on. `meshbone local --nat off`
    is for networks whose router already has a route back to the mesh.
    """
    nets = [
        str(piece)
        for s in me["subnets"]
        for piece in store.carve(IPv4Network(s), [store.mesh_net(mesh), store.cluster_net(mesh)])
    ]
    out = ""
    if nets and nat:
        out += (
            f'  chain gateway {{ type nat hook postrouting priority 100; policy accept; iifname "{settings.IFACE}" '
            f'oifname != "{settings.IFACE}" ip daddr {{ {", ".join(nets)} }} masquerade; }}\n'
        )
    if public:
        keep = ", ".join(str(n) for n in inside)
        out += (
            "  chain public_in { type nat hook prerouting priority -100; policy accept;\n"
            + "".join(f"    ip daddr {pub} dnat to {ip}\n" for pub, ip in public)
            + "  }\n  chain public_out { type nat hook postrouting priority 100; policy accept;\n"
            + "".join(f"    ip saddr {ip} ip daddr != {{ {keep} }} snat to {pub}\n" for pub, ip in public)
            + "  }\n"
        )
    return out


def mesh_table(*chains):
    """Our own nftables table holding these chains -> text that replaces it in one step, or None if empty."""
    body = "".join(chains)
    return f"table inet meshbone\ndelete table inet meshbone\ntable inet meshbone {{\n{body}}}\n" if body else None


def dns_name(text):
    """A host name: labels of letters, digits and hyphens, dots between -> lower case, or None."""
    text = (text or "").strip(".").lower()
    ok = (
        text
        and len(text) <= 253
        and all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", l) for l in text.split("."))
    )
    return text if ok else None


def dns_records(mesh, nodes):
    """What the resolver answers for the mesh's zone -> {name: [IPv4Address]} plus reverse names.

    Every node is `<node>.<zone>` and may add names of its own (`--dns`): a bare name goes under
    the zone, a dotted one is taken as written. A label that is a valid host name resolves to all
    nodes carrying it. `map`, `metrics` and `dns` are the hubs' service addresses.
    """
    zone, alive = store.dns_settings(mesh)["zone"], store.live(nodes)
    out = {}

    def add(name, ip):
        out.setdefault(name, [])
        if ip not in out[name]:
            out[name].append(ip)

    for n in sorted(alive.values(), key=lambda n: n["id"]):
        ip = store.router_ip(mesh, n["id"])
        add(f"{n['name'].lower()}.{zone}", ip)
        add(f"{ip.reverse_pointer}", n["name"].lower() + "." + zone)
        for extra in n.get("dns", []):
            add(extra if "." in extra else f"{extra}.{zone}", ip)
    for n in alive.values():  # groups after names, so a node's own name is never shadowed
        for label in n.get("labels", []):
            name = dns_name(label)
            if name and "." not in name and f"{name}.{zone}" not in out:
                out[f"{name}.{zone}"] = []
            if name and "." not in name and store.router_ip(mesh, n["id"]) not in out[f"{name}.{zone}"]:
                out[f"{name}.{zone}"].append(store.router_ip(mesh, n["id"]))
    gateway = store.https_routes(mesh)  # names the gateway serves go to it, `map` included
    for host in gateway:
        add(host, store.https_vip(mesh))
    for name, ip in (
        ("map", store.admin_vip(mesh)),
        ("metrics", store.metrics_vip(mesh)),
        ("dns", store.dns_vip(mesh)),
        ("https", store.https_vip(mesh)),
    ):
        if f"{name}.{zone}" not in gateway:
            add(f"{name}.{zone}", ip)
    return out


def dns_answer(records, zone, query):
    """Reply to one DNS message from what we know -> bytes, or None when it is not ours to answer
    (then it goes upstream). Pure: a question in, an answer out."""
    try:
        qid, flags, qd = struct.unpack("!HHH", query[:6])
        if qd != 1 or flags & 0x8000:
            return None
        labels, pos = [], 12
        while True:
            n = query[pos]
            pos += 1
            if n == 0:
                break
            if n & 0xC0 or pos + n > len(query):
                return None
            labels.append(query[pos : pos + n].decode("ascii").lower())
            pos += n
        qtype, qclass = struct.unpack("!HH", query[pos : pos + 4])
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    name = ".".join(labels)
    ours = name == zone or name.endswith("." + zone) or name.endswith(".in-addr.arpa")
    if not ours:
        return None
    question = query[12 : pos + 4]
    rrs = []
    if qclass == 1 and name in records:
        for value in records[name]:
            if qtype in (1, 255) and isinstance(value, IPv4Address):
                rrs.append(struct.pack("!HHIH", 1, 1, 60, 4) + value.packed)
            elif qtype in (12, 255) and isinstance(value, str):
                rdata = b"".join(bytes([len(l)]) + l.encode() for l in value.split(".")) + b"\x00"
                rrs.append(struct.pack("!HHIH", 12, 1, 60, len(rdata)) + rdata)
    if name not in records and name.endswith(".in-addr.arpa"):
        return None  # a reverse name that is not one of ours: let the upstream try
    rcode = 0 if name in records else 3  # NXDOMAIN for a name in our zone that nobody has
    head = struct.pack("!HHHHHH", qid, 0x8400 | (flags & 0x0100) | 0x0080 | rcode, 1, len(rrs), 0, 0)
    return head + question + b"".join(b"\xc0\x0c" + rr for rr in rrs)


def dns_forward(upstream, query, tcp=False):
    """Ask the upstream resolvers in turn -> their raw reply, or a SERVFAIL."""
    for server in upstream:
        try:
            if tcp:
                with socket.create_connection((server, 53), timeout=3) as s:
                    s.sendall(struct.pack("!H", len(query)) + query)
                    size = struct.unpack("!H", s.recv(2))[0]
                    reply = b""
                    while len(reply) < size:
                        part = s.recv(size - len(reply))
                        if not part:
                            break
                        reply += part
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(3)
                    s.sendto(query, (server, 53))
                    reply = s.recv(4096)
            if reply[:2] == query[:2]:
                return reply
        except OSError:
            continue
    return query[:2] + struct.pack("!H", 0x8182) + query[4:6] + b"\x00\x00\x00\x00" + query[12:]  # SERVFAIL


def stats_db():
    """Traffic and latency history. Every row belongs to the hub that measured it (reporter):
    what it received from and sent to one peer in one time bucket, and the ping across that link."""
    db = sqlite3.connect(f"{settings.DIR}/stats.db", timeout=10)
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
    cut = bucket - settings.KEEP_FINE
    db.execute(
        "INSERT INTO link SELECT reporter, peer, ts / 600 * 600, sum(rx), sum(tx), CAST(avg(ms) AS INT) FROM link "
        "WHERE ts < ? AND ts % 600 != 0 GROUP BY 1, 2, 3 ON CONFLICT(reporter, peer, ts) DO UPDATE SET "
        "rx = rx + excluded.rx, tx = tx + excluded.tx",
        (cut,),
    )
    db.execute("DELETE FROM link WHERE ts < ? AND ts % 600 != 0", (cut,))
    db.execute("DELETE FROM link WHERE ts < ?", (bucket - settings.KEEP_ALL,))


def keeps_stats(me):
    """Does this node hold the traffic history? Hubs measure it; every node that serves the
    pages keeps a copy, so the graphs look the same whichever of them answers."""
    return bool(me["endpoint"]) or os.path.exists(f"{settings.DIR}/admin.key")


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
        settings.log(f"stats: {e}")


def traffic_totals():
    """[(hub id, peer id, bytes received, bytes sent)] since counting began."""
    try:
        db = stats_db()
        totals = db.execute("SELECT reporter, peer, rx, tx FROM total").fetchall()
        db.close()
        return totals
    except sqlite3.Error:
        return []


def health_table(nodes, nets):
    """Every node's state as reported by itself: [{name, version, ok, problems, seen}]."""
    out = []
    for pk, n in sorted(store.live(nodes).items(), key=lambda kv: kv[1]["id"]):
        if n.get("simple") or n.get("transit"):
            continue
        r = nets.get(pk, {})
        h = r.get("health") or {"ok": None, "problems": []}
        out.append(
            {
                "name": n["name"],
                "version": r.get("code", ""),
                "ok": h["ok"],
                "problems": h["problems"],
                "reported": r.get("seq", 0),
            }
        )
    return out


def events_table(nodes, nets, count=60):
    """The newest events of every node, merged: [{t, node, k, m}]."""
    names = {pk: n["name"] for pk, n in store.live(nodes).items()}
    out = [{**e, "node": names[pk]} for pk, r in nets.items() if pk in names for e in r.get("events", [])]
    return sorted(out, key=lambda e: -e["t"])[:count]


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
    fine = 60 if frm >= now - settings.KEEP_FINE else 600  # older data only exists in 10-minute buckets
    step = max(fine, -(-max(step, (to - frm) // 240) // fine) * fine)
    alive = store.live(store.load())
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
        settings.log(f"stats: {e}")
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
    loc, nodes, nets = store.local(), store.load(), store.load_nets()
    seen, st, alive = system.handshakes(), store.read_json("state.json", {}), store.live(nodes)
    hub = bool(nodes[loc["pub"]]["endpoint"])
    for pk, n in sorted(alive.items(), key=lambda kv: kv[1]["id"]):
        if pk == loc["pub"]:
            link = "this machine"
        elif hub or n["endpoint"]:
            link = "linked" if seen.get(pk, settings.FRESH) < settings.FRESH else "no link"
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
            "ip": str(store.router_ip(loc["mesh"], n["id"])),
            "link": link,
            "eff": max(n["cost"], loc["cost"].get(n["name"], 0)),
            "wants": wants if wants != n["endpoint"] else "",
        }


def topology():
    """The whole mesh as its nodes report it: every node, and every link with state and latency."""
    loc, nodes, nets = store.local(), store.load(), store.load_nets()
    mesh, alive = loc["mesh"], store.live(nodes)
    out = {"nodes": [], "links": [], "mesh": mesh["name"], "edges": []}
    merged = {}  # hosts without a tunnel of their own, as the hubs see them talking through
    for pk, r in nets.items():
        if pk in alive:
            for e in r.get("edges", []):
                key = (e["ip"], e["via"], e["peer"])
                merged[key] = merged.get(key, 0) + e["bytes"]
    names_ = {n["name"] for n in alive.values()}
    out["edges"] = [
        {"ip": ip, "via": via, "peer": peer, "bytes": b}
        for (ip, via, peer), b in sorted(merged.items(), key=lambda kv: -kv[1])[:60]
        if via in names_ and peer in names_
    ]
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
                "ip": str(store.router_ip(mesh, n["id"])),
                "endpoint": n["endpoint"],
                "subnets": n["subnets"],
                "vips": n["vips"],
                "admin": bool(mine.get("admin")),
                "labels": n.get("labels", []),
                "desc": n.get("desc", ""),
                "simple": bool(n.get("simple")),
                "public": n.get("public", ""),
                "transit": bool(n.get("transit")),
                "public_nets": n.get("public_nets", []),
                "exit": store.exit_node(alive) == pk,
            }
        )
        for hpk, h in alive.items():
            if not h["endpoint"] or hpk == pk or (n["endpoint"] and pk > hpk):  # hub pairs once
                continue
            if n.get("transit") and h["name"] != n["via"]:  # a transit router is linked to one hub only
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
    nodes, nets = store.load(), store.load_nets()
    alive, out = store.live(nodes), []
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


def software():
    """Everything the management page shows about versions: what runs where, the release, the log."""
    loc, nets, state_ = store.local(), store.load_nets(), store.read_json("update.json", {})
    return {
        "running": store.code_sha(),
        "release": store.release(),
        "previous": state_.get("was", "") if os.path.exists(store.release_path(state_.get("was", "-"))) else "",
        "nodes": [
            {
                "name": n["name"],
                "code": nets.get(pk, {}).get("code", ""),
                "update": nets.get(pk, {}).get("update") or {},
            }
            for pk, n in sorted(store.live(store.load()).items(), key=lambda kv: kv[1]["id"])
            if not n.get("simple") and not n.get("transit")
        ],
        "log": store.audit_tail(),
        "mesh": loc["mesh"]["name"],
    }
