"""MODEL, machine side: this host's WireGuard interface, routes, firewall, systemd units and packages, and `reconcile`, which makes them match the directory."""

import contextlib, json, os, re, shutil, socket, sqlite3, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network

from . import model, settings, store, updates


def run(*cmd, input=None, check=True, timeout=60):
    """A system command's output. No command may hold the node up for good: one that does not
    finish in `timeout` seconds counts as failed."""
    kw = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    try:
        return subprocess.run(cmd, check=check, text=True, capture_output=True, timeout=timeout, **kw).stdout
    except subprocess.TimeoutExpired:
        settings.log(f"{cmd[0]} did not finish in {timeout}s: {' '.join(cmd[:4])}")
        if check:
            raise subprocess.CalledProcessError(124, cmd, "", f"timed out after {timeout}s")
        return ""


def unit(action, *names):
    """Start, stop or restart systemd units without waiting for the job: this very code often runs
    inside a unit of its own (the timer's), and a blocking request for a job can then wait on itself."""
    run("systemctl", "--no-block", action, *names, check=False)


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
        if link["ifname"] in (settings.IFACE, "mbvip"):
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


def sync_routes(want, src, relay=(), own=()):
    """Route exactly these prefixes into the mesh. Returns the ones this host already sends elsewhere.

    Packets that arrive *from* the mesh are looked up in a table of our own first, so relaying -
    a hub handing traffic on, a gateway receiving it - never depends on what else the host
    routes. That table holds the mesh's prefixes, `relay` prefixes (the internet, on a hub) and
    `own`: the networks this host is attached to or announces, routed the way the host itself
    routes them - so that a relay route for the internet never swallows the LAN. For traffic the
    machine itself originates, the prefixes go into the main table, but only where nothing else
    claims them: a route somebody put there stays.
    """

    def held(*where):
        out = {}
        for r in ip_json("-4", "route", "show", *where):
            with contextlib.suppress(ValueError, KeyError, TypeError):
                out[IPv4Network(r["dst"] if r["dst"] != "default" else "0.0.0.0/0")] = r
        return out

    def host_route(net):  # how the host reaches a network of its own, as route arguments
        for r in ip_json("-4", "route", "get", str(net.network_address + (1 if net.prefixlen < 31 else 0))):
            if r.get("dev") and r["dev"] != settings.IFACE:
                return (["via", r["gateway"]] if r.get("gateway") else []) + ["dev", r["dev"]]
        return None

    table = str(settings.MESH_TABLE)
    wanted = {p: ["dev", settings.IFACE] for p in want | set(relay)}
    for p in own:
        args = host_route(p)
        if args:
            wanted[p] = args
    ours = held("table", table)
    for p, args in wanted.items():
        have = ours.get(p)
        if not have or have.get("dev") != args[-1] or have.get("gateway") != (args[1] if args[0] == "via" else None):
            run("ip", "route", "replace", str(p), *args, "table", table, check=False)
    for p in set(ours) - set(wanted):
        run("ip", "route", "del", str(p), "table", table, check=False)
    if not ip_json("rule", "show", "pref", str(settings.MESH_TABLE)):
        run(
            "ip",
            "rule",
            "add",
            "iif",
            settings.IFACE,
            "lookup",
            str(settings.MESH_TABLE),
            "pref",
            str(settings.MESH_TABLE),
            check=False,
        )

    main, elsewhere = set(held("dev", settings.IFACE)), set()
    for p in want - main:
        try:
            run("ip", "route", "add", str(p), "dev", settings.IFACE, "src", str(src))
        except subprocess.CalledProcessError:
            elsewhere.add(p)  # already routed some other way on this machine: leave that alone
    for p in main - want:
        run("ip", "route", "del", str(p), "dev", settings.IFACE, check=False)
    return sorted(str(p) for p in elsewhere)


def sync_exit(on):
    """Send this host's own internet traffic into the mesh (to the exit node), or stop doing so.

    The tunnel's own packets carry a mark and keep using the main table, so the tunnel does
    not try to carry itself; everything the main table has no specific route for goes to the
    mesh interface. The LAN, the mesh and announced subnets keep their specific routes.
    """
    have = bool(ip_json("rule", "show", "pref", str(settings.EXIT_TABLE)))
    if on and not have:
        run("wg", "set", settings.IFACE, "fwmark", str(settings.EXIT_TABLE), check=False)
        run("ip", "route", "replace", "default", "dev", settings.IFACE, "table", str(settings.EXIT_TABLE), check=False)
        run(
            "ip",
            "rule",
            "add",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
            "pref",
            str(settings.EXIT_TABLE),
            check=False,
        )
        run(
            "ip",
            "rule",
            "add",
            "not",
            "fwmark",
            str(settings.EXIT_TABLE),
            "lookup",
            str(settings.EXIT_TABLE),
            "pref",
            str(settings.EXIT_TABLE + 1),
            check=False,
        )
    elif have and not on:
        for pref in (settings.EXIT_TABLE, settings.EXIT_TABLE + 1):
            run("ip", "rule", "del", "pref", str(pref), check=False)
        run("ip", "route", "flush", "table", str(settings.EXIT_TABLE), check=False)
        run("wg", "set", settings.IFACE, "fwmark", "0", check=False)


def firewall(want):
    """Keep exactly our iptables rules in place (for hosts whose policy is DROP, e.g. with Docker)."""
    if not shutil.which("iptables"):
        return
    had = store.read_json("fw.json", [])
    for rule in had:
        if rule not in want:
            run("iptables", "-D", *rule, check=False)
    for rule in want:
        try:
            run("iptables", "-C", *rule)
        except subprocess.CalledProcessError:
            run("iptables", "-I", *rule, check=False)
    if had != want:
        store.write(f"{settings.DIR}/fw.json", json.dumps(want))


def apply_table(text):
    """Load our nftables table (firewall policy, gateway NAT), or remove it. The table is ours alone; whatever other
    firewall the host has stays as it is, and both have to let a packet through."""
    path = f"{settings.DIR}/policy.nft"
    if text is None:
        if os.path.exists(path):
            run("nft", "delete", "table", "inet", "meshbone", check=False)
            os.remove(path)
        return
    try:
        in_place = os.path.exists(path) and store.read("policy.nft") == text.strip()
        if not (in_place and run("nft", "list", "table", "inet", "meshbone", check=False)):
            run("nft", "-f", "-", input=text)
            store.write(path, text)
        st = store.read_json("state.json", {})
        if st.get("nft_error"):  # in place again after a failure: the problem is over
            store.write(f"{settings.DIR}/state.json", json.dumps({**st, "nft_error": ""}))
    except (OSError, subprocess.CalledProcessError) as e:
        why = str(getattr(e, "stderr", "") or e)[:200]
        if store.read_json("state.json", {}).get("nft_error") != why:  # say it once, not every fifteen seconds
            settings.log(f"nftables table NOT applied (firewall policy, gateway NAT): {why}")
            store.write(
                f"{settings.DIR}/state.json", json.dumps({**store.read_json("state.json", {}), "nft_error": why})
            )


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
    for line in run("wg", "show", settings.IFACE, "latest-handshakes", check=False).splitlines():
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
            settings.IFACE,
            str(store.router_ip(mesh, item[1]["id"])),
            check=False,
        )
        times = [float(t) for t in re.findall(r"time=([\d.]+)", out)]
        return item[0], min(times) if times else None

    with ThreadPoolExecutor(settings.PARALLEL) as pool:
        return {pk: rtt for pk, rtt in pool.map(one, hubs.items()) if rtt is not None}


def record_stats(my_id, alive, nets, rtt):
    """On a hub: add what crossed each link since the last run. Must never get in the tunnel's way."""
    try:
        last, now, bucket = store.read_json("counters.json", {}), {}, int(time.time()) // 60 * 60
        db = model.stats_db()
        for line in run("wg", "show", settings.IFACE, "transfer", check=False).splitlines():
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
        model.stats_upkeep(db)
        db.commit()
        db.close()
        store.write(f"{settings.DIR}/counters.json", json.dumps(now))
    except (sqlite3.Error, ValueError) as e:
        settings.log(f"stats: {e}")


def reconcile():
    """Make the WireGuard link, routes, cluster IPs and firewall match the directory. Idempotent."""
    loc, nodes, nets = store.local(), store.load(), store.load_nets()
    mesh, mypk, me = loc["mesh"], loc["pub"], nodes[loc["pub"]]
    alive = store.live(nodes)
    hub, active = bool(me["endpoint"]), mypk in alive
    my_ip = store.router_ip(mesh, me["id"])
    attached = local_nets()
    seen = handshakes()
    was = store.read_json("state.json", {})
    rtt = probe(mesh, {pk: n for pk, n in alive.items() if n["endpoint"] and pk != mypk}) if active else {}
    table, primary = model.plan(loc, nodes, nets, rtt, seen, was.get("primary")) if active else ({}, None)

    old = nets.get(mypk, {})
    ms = {str(alive[pk]["id"]): round(v) for pk, v in rtt.items()}
    told = old.get("rtt", {})
    if ms.keys() == told.keys() and all(abs(v - told[k]) <= max(3, v // 4) for k, v in ms.items()):
        ms = told  # ordinary jitter is not news worth telling the whole mesh
    # what changed since the last look is worth a line in the events
    links = {pk: seen.get(pk, settings.FRESH) < settings.FRESH for pk in table}
    for pk, up in links.items():
        if was.get("links", {}).get(pk) is not None and was["links"][pk] != up:
            store.event("link", f"{alive[pk]['name']}: {'up' if up else 'down'}")
    if primary != was.get("primary") and (primary or was.get("primary")):
        store.event("route", f"sending through {alive[primary]['name'] if primary else 'no hub'}")
    for pk, n in alive.items():
        if pk not in was.get("known", {}) and was.get("known"):
            store.event("mesh", f"new node {n['name']}")
    for pk, name in was.get("known", {}).items():
        if pk not in alive:
            store.event("mesh", f"node {name} is gone")
    report = {
        "nets": attached,
        "wants": loc.get("wants", ""),
        "rtt": ms,
        "sees": sorted(pk_ for pk_ in [alive[pk]["id"] for pk, up in links.items() if up]) if hub else [],
        "primary": alive[primary]["id"] if primary else None,
        "admin": os.path.exists(f"{settings.DIR}/admin.key"),
        "code": store.code_sha()[:12],
        "update": store.update_report(),
    }

    sync_vips(set(store.held_vips(mesh, me)) if active else set())
    if not active:  # revoked: take everything down
        run("ip", "link", "del", settings.IFACE, check=False)
        run("ip", "rule", "del", "pref", str(settings.MESH_TABLE), check=False)
        sync_exit(False)
        sync_resolver(False)
        firewall([])
        apply_table(None)
        for name in (
            "meshbone-serve.socket",
            "meshbone-admin.socket",
            "meshbone-dns.service",
            "meshbone-https.service",
        ):
            unit("stop", name)
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
            f"[Peer]\nPublicKey = {pk}\nPresharedKey = {model.pair_psk(loc, pk)}\n"
            f"AllowedIPs = {', '.join(str(p) for p in sorted(carried))}\n"
        )
        if n["endpoint"] or n.get("transit"):
            host, _, peer_port = (n["endpoint"] or n["transit"]).rpartition(":")
            endpoint = resolve(host, int(peer_port))  # on DNS failure keep whatever endpoint wg has
            with contextlib.suppress(ValueError, AttributeError):
                underlay.append(IPv4Address(endpoint.rpartition(":")[0]))
            conf += (f"Endpoint = {endpoint}\n" if endpoint else "") + "PersistentKeepalive = 25\n"
    try:
        if not run("ip", "-j", "link", "show", "dev", settings.IFACE, check=False):
            run("ip", "link", "add", settings.IFACE, "type", "wireguard")
        run("wg", "syncconf", settings.IFACE, "/dev/stdin", input=conf)
        run("ip", "addr", "replace", f"{my_ip}/32", "dev", settings.IFACE)
        run("ip", "link", "set", "dev", settings.IFACE, "mtu", str(loc.get("mtu") or 1420), "up")
        run("sysctl", "-qw", f"net.ipv4.conf.{settings.IFACE}.rp_filter=2", check=False)
    except subprocess.CalledProcessError as e:
        settings.log(f"{settings.IFACE}: {e.stderr.strip()}")
    # Send the mesh ranges and other nodes' subnets into the tunnel. Not a subnet that lies within a
    # network this machine is attached to (the local one wins), and not one that contains a hub's
    # public address (the tunnel would try to carry itself). A subnet that merely *contains* a local
    # network is fine: the kernel prefers the more specific local route.
    routes = {store.mesh_net(mesh), store.cluster_net(mesh)} | {
        IPv4Network(s)
        for pk, n in alive.items()
        if pk != mypk
        for s in n["subnets"]
        if not any(IPv4Network(s).subnet_of(IPv4Network(l)) for l in attached)
        and not any(u in IPv4Network(s) for u in underlay)
    }
    via_exit = store.exit_node(alive)
    relay = [IPv4Network("0.0.0.0/0")] if hub and via_exit else []
    # on the gateway hub: the public addresses mapped 1:1 onto nodes, and what counts as "inside"
    public = (
        [(n["public"], store.router_ip(mesh, n["id"])) for n in alive.values() if n.get("public")]
        if via_exit == mypk
        else []
    )
    inside = sorted(routes | {IPv4Network(f"{ip}/32") for ip in [my_ip]})
    own = {IPv4Network(l) for l in attached} | {IPv4Network(s) for s in me["subnets"]}
    elsewhere = sync_routes(routes, my_ip, relay, own)
    sync_exit(bool(me.get("public")) and via_exit in rtt)
    if hub:
        record_stats(me["id"], alive, nets, rtt)
        report["edges"] = edge_hosts(mesh, alive, me)

    serves_admin = hub or os.path.exists(f"{settings.DIR}/admin.key")  # hubs: the map; admin nodes: also /admin
    rules = [["INPUT", "-i", settings.IFACE, "-p", "tcp", "--dport", str(settings.GOSSIP_PORT), "-j", "ACCEPT"]]
    if serves_admin:
        rules.append(["INPUT", "-i", settings.IFACE, "-p", "tcp", "--dport", str(settings.ADMIN_PORT), "-j", "ACCEPT"])
    if port:
        rules.append(["INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    if hub:
        rules += [["INPUT", "-i", settings.IFACE, "-p", p, "--dport", "53", "-j", "ACCEPT"] for p in ("udp", "tcp")]
        rules.append(["INPUT", "-i", settings.IFACE, "-p", "tcp", "--dport", str(settings.HTTPS_PORT), "-j", "ACCEPT"])
    if hub or me["subnets"]:
        rules += [["FORWARD", "-i", settings.IFACE, "-j", "ACCEPT"], ["FORWARD", "-o", settings.IFACE, "-j", "ACCEPT"]]
    firewall(rules)
    apply_table(
        model.mesh_table(
            model.policy_ruleset(mesh, alive, store.policy()),
            model.gateway_ruleset(mesh, me, loc.get("nat", True), public, inside),
        )
    )
    problems = health_problems(loc, alive, me, hub, rtt, seen, attached, via_exit, was)
    if problems != was.get("problems", []):
        for p in problems:
            if p not in was.get("problems", []):
                store.event("health", p)
        if not problems and was.get("problems"):
            store.event("health", "all checks pass again")
    report["health"] = {"ok": not problems, "problems": problems}
    report["events"] = store.recent_events(30)
    if {k: v for k, v in old.items() if k != "seq"} != report:
        nets[mypk] = {**report, "seq": store.next_seq(nets.get(mypk, {}).get("seq", 0))}
        store.save_nets(nets)  # travels with the next gossip round
    now_state = {
        "primary": primary,
        "rtt": rtt,
        "elsewhere": elsewhere,
        "links": links,
        "known": {pk: n["name"] for pk, n in alive.items()},
        "problems": problems,
        "nft_error": was.get("nft_error", ""),
    }
    if now_state != was:
        store.write(f"{settings.DIR}/state.json", json.dumps(now_state))
    wanted = resolver_wanted(loc)
    if wanted != was.get("resolver") or not resolver_in_place(wanted):  # first time, changed, or lost at boot
        sync_resolver(wanted != "off")
        store.write(f"{settings.DIR}/state.json", json.dumps({**store.read_json("state.json", {}), "resolver": wanted}))
    unit("start", "meshbone-serve.socket")
    unit("start" if serves_admin else "stop", "meshbone-admin.socket")
    unit("start" if hub else "stop", "meshbone-dns.service")
    unit("start" if hub else "stop", "meshbone-https.service")


def install_packages():
    try:
        store.ed25519()
        if shutil.which("wg") and shutil.which("nft"):
            return
    except ImportError:
        pass
    if shutil.which("apt-get"):
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(["apt-get", "update", "-q"], env=env)
        subprocess.run(
            ["apt-get", "install", "-y", "-q", "wireguard-tools", "python3-cryptography", "nftables"],
            env=env,
            check=True,
        )
    elif shutil.which("dnf"):
        subprocess.run(["dnf", "install", "-y", "wireguard-tools", "python3-cryptography", "nftables"], check=True)
    else:
        sys.exit("unsupported package manager: install wireguard-tools and python3-cryptography, then re-run")


def install_self(dst):
    src = updates.program_file()
    if src != dst:
        shutil.copy(src, dst)
        os.chmod(dst, 0o755)


def install_units():
    install_self(settings.BIN)
    mesh = store.local()["mesh"]
    for name, text in settings.UNITS.items():
        # sys.executable: /run is mounted noexec, so --once can't exec the script directly
        store.write(
            f"{settings.UNIT_DIR}/{name}",
            text.format(
                py=sys.executable,
                bin=settings.BIN,
                port=settings.GOSSIP_PORT,
                net=mesh["net"],
                vip=store.admin_vip(mesh),
                aport=settings.ADMIN_PORT,
            ),
            0o644,
        )
    run("systemctl", "daemon-reload")
    unit(
        "try-restart", "meshbone-dns.service", "meshbone-https.service"
    )  # long-running services pick up the new program
    run("systemctl", "--no-block", *(["start"] if settings.ONCE else ["enable", "--now"]), "meshbone.timer")


def resolver_manager():
    """Who owns this host's DNS settings: resolved, resolvconf, networkmanager, or file."""
    if (
        shutil.which("resolvectl")
        and run("systemctl", "is-active", "systemd-resolved", check=False).strip() == "active"
    ):
        return "resolved"
    if shutil.which("resolvconf") and os.path.isdir("/run/resolvconf"):
        return "resolvconf"
    try:
        with open("/etc/resolv.conf") as f:
            head = f.read(200)
    except OSError:
        head = ""
    if "NetworkManager" in head and run("systemctl", "is-active", "NetworkManager", check=False).strip() == "active":
        return "networkmanager"
    return "file"


def resolver_wanted(loc):
    """What this host's DNS should be: "off", or the servers and the search domain (the mesh's
    zone, so that bare node names resolve). Comparable, so a change of either is applied."""
    if not loc.get("resolver", True):
        return "off"
    d = store.dns_settings(loc["mesh"])
    fallback = loc.get("fallback") or d["upstream"]  # a host may name its own fallbacks
    return {"servers": [str(store.dns_vip(loc["mesh"]))] + fallback, "zone": d["zone"]}


def glibc_asks_resolved():
    """Whether programs on this host (through glibc) actually consult systemd-resolved: via its
    stub listener in /etc/resolv.conf or the nss-resolve module. If not, resolved's per-link
    settings change nothing for them."""
    try:
        hosts = next((ln for ln in open("/etc/nsswitch.conf") if ln.startswith("hosts:")), "")
        head = open("/etc/resolv.conf").read(2000)
    except OSError:
        return False
    return "resolve" in hosts.split() or "127.0.0.53" in head


def keep_resolv_conf():
    """Remember what /etc/resolv.conf was (a symlink's target, or the content) - once."""
    path, saved = "/etc/resolv.conf", f"{settings.DIR}/resolv.conf.saved"
    if os.path.exists(saved) or "written by meshbone" in (open(path).read() if os.path.exists(path) else ""):
        return
    if os.path.islink(path):
        store.write(saved, "link " + os.readlink(path))
    elif os.path.exists(path):
        store.write(saved, open(path).read())
    else:
        store.write(saved, "")


def restore_resolv_conf():
    """Put /etc/resolv.conf back the way keep_resolv_conf found it, if it was kept."""
    path, saved = "/etc/resolv.conf", f"{settings.DIR}/resolv.conf.saved"
    if not os.path.exists(saved):
        return
    kept = open(saved).read()
    if os.path.lexists(path):
        os.remove(path)
    if kept.startswith("link "):
        os.symlink(kept[5:].strip(), path)
    elif kept:
        store.write(path, kept, 0o644)
    os.remove(saved)


def resolver_in_place(wanted):
    """Whether what sync_resolver did is still in effect. Only systemd-resolved's per-link
    settings can vanish on their own (with the interface, at boot); the files stay."""
    if wanted == "off" or resolver_manager() != "resolved":
        return True
    return wanted["servers"][0] in run("resolvectl", "dns", settings.IFACE, check=False)


def sync_resolver(on):
    """Make the mesh resolver this host's DNS, with the mesh's upstream resolvers as fallback and
    the zone as the search domain - or undo that. Done through whatever manages the host's DNS, so
    it survives the manager's own changes; the plain-file case keeps a copy of what was there.
    Returns what was done."""
    loc = store.local()
    wanted = resolver_wanted({**loc, "resolver": True})
    servers, zone, how = wanted["servers"], wanted["zone"], resolver_manager()
    if how == "resolved":
        if on:
            run("resolvectl", "dns", settings.IFACE, *servers, check=False)
            run("resolvectl", "domain", settings.IFACE, "~.", zone, check=False)  # no ~: a search domain too
            run("resolvectl", "default-route", settings.IFACE, "yes", check=False)
            if not glibc_asks_resolved():  # resolved runs but nothing asks it: point /etc/resolv.conf at its stub
                keep_resolv_conf()
                if os.path.lexists("/etc/resolv.conf"):
                    os.remove("/etc/resolv.conf")
                os.symlink("/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf")
        else:
            run("resolvectl", "revert", settings.IFACE, check=False)
            restore_resolv_conf()
    elif how == "resolvconf":
        if on:  # named lo.* so that resolvconf puts it before the DHCP-provided ones
            text = "".join(f"nameserver {s}\n" for s in servers) + f"search {zone}\noptions timeout:2 attempts:1\n"
            run("resolvconf", "-a", "lo.meshbone", input=text, check=False)
        else:
            run("resolvconf", "-d", "lo.meshbone", check=False)
    elif how == "networkmanager":
        path = "/etc/NetworkManager/conf.d/meshbone.conf"
        text = (
            "# written by meshbone: the mesh resolver first, then its fallbacks, and the mesh's zone to search\n"
            f"[global-dns]\nsearches={zone}\n\n[global-dns-domain-*]\nservers={','.join(servers)}\n"
        )
        if on and (not os.path.exists(path) or open(path).read() != text):
            store.write(path, text, 0o644)
            run(
                "nmcli", "general", "reload", "conf,dns-rc,dns-full", check=False
            )  # the global DNS lives in NM's config
        elif not on and os.path.exists(path):
            os.remove(path)
            run(
                "nmcli", "general", "reload", "conf,dns-rc,dns-full", check=False
            )  # the global DNS lives in NM's config
    else:
        path = "/etc/resolv.conf"
        text = (
            "# written by meshbone; the original is kept beside its state\n"
            + "".join(f"nameserver {s}\n" for s in servers)
            + f"search {zone}\noptions timeout:2 attempts:1\n"
        )
        try:
            current = open(path).read()
        except OSError:
            current = ""
        if on and current != text:
            keep_resolv_conf()
            if os.path.islink(path):
                os.remove(path)
            store.write(path, text, 0o644)
        elif not on and "written by meshbone" in current:
            os.remove(path)
            restore_resolv_conf()
    return (
        f"DNS: the mesh resolver {servers[0]} first, then {', '.join(servers[1:])} (via {how})"
        if on
        else f"DNS: the mesh resolver is no longer used here (via {how})"
    )


def script(path, *args, timeout=240):
    """Run another copy of this program -> (succeeded, the end of what it said)."""
    try:
        r = subprocess.run(
            [sys.executable, path, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode == 0, (r.stdout + r.stderr).strip()[-600:]
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def edge_hosts(mesh, alive, me):
    """Hosts that have no tunnel of their own but talk through this hub: the LAN hosts behind
    gateways, and the internet behind the exit. From connection tracking: [{ip, via, peer, bytes}]
    for the busiest, where `via` is the node they sit behind and `peer` the node they talk to.
    """
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_acct") as f:  # byte counts need accounting switched on
            if f.read().strip() != "1":
                run("sysctl", "-qw", "net.netfilter.nf_conntrack_acct=1", check=False)
        with open("/proc/net/nf_conntrack") as f:
            flows = f.read().splitlines()
    except OSError:
        return []
    addr = {str(store.router_ip(mesh, n["id"])): n["name"] for n in alive.values()}
    owners = [(IPv4Network(s), n["name"]) for n in alive.values() for s in n["subnets"]]
    ranges = (store.mesh_net(mesh), store.cluster_net(mesh))
    exit_pk = store.exit_node(alive)
    internet = next((n["name"] for n in store.transits(alive).values()), alive[exit_pk]["name"] if exit_pk else "")
    seen_ = {}
    for line in flows:
        pairs = re.findall(r"src=([\d.]+) dst=([\d.]+)", line)
        if not pairs or "ipv4" not in line:
            continue
        counts = [int(b) for b in re.findall(r"bytes=(\d+)", line)] or [0]
        src, dst = pairs[0]
        node, host = (addr[src], dst) if src in addr else (addr[dst], src) if dst in addr else (None, None)
        if not node or host in addr or any(IPv4Address(host) in r for r in ranges):
            continue
        via = next((name for net, name in owners if IPv4Address(host) in net), None)
        if via is None:
            if not internet or IPv4Address(host).is_private:
                continue
            via = internet
        key = (host, via, node)
        seen_[key] = seen_.get(key, 0) + sum(counts)
    top = sorted(seen_.items(), key=lambda kv: -kv[1])[:40]
    return [{"ip": ip, "via": via, "peer": peer, "bytes": b} for (ip, via, peer), b in top]


def health_problems(loc, alive, me, hub, rtt, seen, attached, via_exit, was):
    """What is wrong on this node right now, as sentences for the map. Empty when all is well."""
    out = []
    others = {pk: n for pk, n in alive.items() if pk != loc["pub"] and not n.get("simple") and not n.get("transit")}
    hubs = {pk: n for pk, n in others.items() if n["endpoint"]}
    if not hub and hubs and not rtt:
        out.append("no hub answers: this node is cut off from the mesh")
    if hub and others and not any(seen.get(pk, settings.FRESH) < settings.FRESH for pk in others):
        out.append("no node has reached this hub lately: is its endpoint and UDP port open?")
    if not shutil.which("nft"):
        out.append("nftables is not installed: no firewall policy and no gateway NAT here")
    elif was.get("nft_error"):
        out.append(f"nftables table not applied: {was['nft_error'][:100]}")
    for pk, n in hubs.items():
        host = (n["endpoint"] or n.get("transit", "")).rpartition(":")[0]
        if host and not re.fullmatch(r"[\d.]+|\[.*\]", host) and not resolve(host, 1):
            out.append(f"cannot resolve {host}: this host has no working DNS")
            break
    if (hub or me["subnets"]) and open("/proc/sys/net/ipv4/ip_forward").read().strip() != "1":
        out.append("IP forwarding is off, so this node cannot relay or serve as a gateway")
    if hub or via_exit:  # traffic from the mesh for a network of ours must not go back into the tunnel
        for net in attached:
            for r in ip_json(
                "-4",
                "route",
                "get",
                str(IPv4Network(net).network_address + 1),
                "from",
                str(store.router_ip(loc["mesh"], me["id"])),
                "iif",
                settings.IFACE,
            ):
                if r.get("dev") == settings.IFACE:
                    out.append(f"traffic from the mesh for {net} would be sent back into the tunnel")
    u = store.read_json("update.json", {})
    if u and not u.get("ok"):
        out.append(f"the last update ({str(u.get('sha', ''))[:12]}) was refused: {u.get('why', '')[:80]}")
    if not settings.ONCE and run("systemctl", "is-active", "meshbone.timer", check=False).strip() != "active":
        out.append("the sync timer is not running: nothing keeps this node in step after a change")
    try:
        st = os.statvfs(settings.DIR)
        if st.f_bavail * st.f_frsize < 50 << 20:
            out.append("less than 50 MB of disk left where meshbone keeps its state")
    except OSError:
        pass
    return out[:20]


def reachable():
    """Is this node in touch with the mesh right now? A hub: with any peer. A client: with any hub."""
    loc, alive = store.local(), store.live(store.load())
    if loc["pub"] not in alive:
        return False
    others = {pk: n for pk, n in alive.items() if pk != loc["pub"]}
    if alive[loc["pub"]]["endpoint"]:
        return not others or any(age < settings.FRESH for pk, age in handshakes().items() if pk in others)
    hubs = {pk: n for pk, n in others.items() if n["endpoint"]}
    return not hubs or bool(probe(loc["mesh"], hubs))


def deploy_key():
    """This node's own ssh identity, for logins it starts by itself -> (private key file, public key line).
    Made the first time it is needed; the public line is what a target has to accept."""
    path = f"{settings.DIR}/deploy_key"
    if not os.path.exists(path):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"meshbone@{socket.gethostname()}", "-f", path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
        )
    with open(path + ".pub") as f:
        return path, f.read().strip()


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
