"""MODEL, machine side: this host's WireGuard interface, routes, firewall, systemd units and packages, and `reconcile`, which makes them match the directory."""

import contextlib, json, os, re, shutil, socket, sqlite3, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network

from . import model, settings, ssh, store, updates


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


def sync_routes(want, src, relay=()):
    """Route exactly these prefixes into the mesh. Returns the ones this host already sends elsewhere.

    Packets that arrive *from* the mesh are looked up in a table of our own first, so relaying -
    a hub handing traffic on, a gateway receiving it - never depends on what else the host
    routes. For traffic the machine itself originates, the prefixes go into the main table,
    but only where nothing else claims them: a route somebody put there stays. `relay` prefixes
    (the internet, on a hub) go into the relay table only.
    """

    def held(*where):
        out = set()
        for r in ip_json("-4", "route", "show", *where):
            with contextlib.suppress(ValueError, KeyError, TypeError):
                out.add(IPv4Network(r["dst"]))
        return out

    ours, table = held("dev", settings.IFACE, "table", str(settings.MESH_TABLE)), want | set(relay)
    for p in table - ours:
        run("ip", "route", "replace", str(p), "dev", settings.IFACE, "table", str(settings.MESH_TABLE), check=False)
    for p in ours - table:
        run("ip", "route", "del", str(p), "table", str(settings.MESH_TABLE), check=False)
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

    main, elsewhere = held("dev", settings.IFACE), set()
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
    if not shutil.which("nft"):
        for cmd in (["apt-get", "install", "-y", "-q", "nftables"], ["dnf", "install", "-y", "nftables"]):
            if shutil.which(cmd[0]):
                subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True)
    try:
        in_place = os.path.exists(path) and store.read("policy.nft") == text.strip()
        if in_place and run("nft", "list", "table", "inet", "meshbone", check=False):
            return
        run("nft", "-f", "-", input=text)
        store.write(path, text)
    except (OSError, subprocess.CalledProcessError) as e:
        settings.log(f"nftables table NOT applied (firewall policy, gateway NAT): {getattr(e, 'stderr', '') or e}")


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
    report = {
        "nets": attached,
        "wants": loc.get("wants", ""),
        "rtt": ms,
        "sees": sorted(alive[pk]["id"] for pk in table if seen.get(pk, settings.FRESH) < settings.FRESH) if hub else [],
        "primary": alive[primary]["id"] if primary else None,
        "admin": os.path.exists(f"{settings.DIR}/admin.key"),
        "code": store.code_sha()[:12],
        "update": store.update_report(),
    }
    if {k: v for k, v in old.items() if k != "seq"} != report:
        nets[mypk] = {**report, "seq": store.next_seq(nets.get(mypk, {}).get("seq", 0))}
        store.save_nets(nets)  # travels with the next gossip round

    sync_vips(set(store.held_vips(mesh, me)) if active else set())
    if not active:  # revoked: take everything down
        run("ip", "link", "del", settings.IFACE, check=False)
        run("ip", "rule", "del", "pref", str(settings.MESH_TABLE), check=False)
        sync_exit(False)
        firewall([])
        apply_table(None)
        for name in ("meshbone-serve.socket", "meshbone-admin.socket", "meshbone-dns.service"):
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
        if n["endpoint"]:
            host, _, peer_port = n["endpoint"].rpartition(":")
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
    relay = [IPv4Network("0.0.0.0/0")] if hub and via_exit and via_exit != mypk else []
    elsewhere = sync_routes(routes, my_ip, relay)
    sync_exit(bool(me.get("public")) and via_exit in rtt)
    if os.path.exists(f"{settings.DIR}/admin.key") and any(n.get("driver") for n in alive.values()):
        ssh.manage_routers()
    if hub:
        record_stats(me["id"], alive, nets, rtt)

    serves_admin = hub or os.path.exists(f"{settings.DIR}/admin.key")  # hubs: the map; admin nodes: also /admin
    rules = [["INPUT", "-i", settings.IFACE, "-p", "tcp", "--dport", str(settings.GOSSIP_PORT), "-j", "ACCEPT"]]
    if serves_admin:
        rules.append(["INPUT", "-i", settings.IFACE, "-p", "tcp", "--dport", str(settings.ADMIN_PORT), "-j", "ACCEPT"])
    if port:
        rules.append(["INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])
    if hub:
        rules += [["INPUT", "-i", settings.IFACE, "-p", p, "--dport", "53", "-j", "ACCEPT"] for p in ("udp", "tcp")]
    if hub or me["subnets"]:
        rules += [["FORWARD", "-i", settings.IFACE, "-j", "ACCEPT"], ["FORWARD", "-o", settings.IFACE, "-j", "ACCEPT"]]
    firewall(rules)
    apply_table(
        model.mesh_table(
            model.policy_ruleset(mesh, alive, store.policy()), model.gateway_ruleset(mesh, me, loc.get("nat", True))
        )
    )
    if {"primary": primary, "rtt": rtt, "elsewhere": elsewhere} != was:
        store.write(f"{settings.DIR}/state.json", json.dumps({"primary": primary, "rtt": rtt, "elsewhere": elsewhere}))
    unit("start", "meshbone-serve.socket")
    unit("start" if serves_admin else "stop", "meshbone-admin.socket")
    unit("start" if hub else "stop", "meshbone-dns.service")


def install_packages():
    try:
        store.ed25519()
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
    run("systemctl", "--no-block", *(["start"] if settings.ONCE else ["enable", "--now"]), "meshbone.timer")


def set_resolver(on):
    """Point this host at the mesh's resolver for the mesh zone -> what was done, as text.
    Uses systemd-resolved's per-interface settings (split DNS); without it, says what to do."""
    mesh = store.local()["mesh"]
    d = store.dns_settings(mesh)
    if not shutil.which("resolvectl"):
        return (
            f"no systemd-resolved here: point your resolver at {store.dns_vip(mesh)} for the domain {d['zone']} yourself"
            if on
            else "nothing to undo"
        )
    if on:
        run("resolvectl", "dns", settings.IFACE, str(store.dns_vip(mesh)), check=False)
        run("resolvectl", "domain", settings.IFACE, f"~{d['zone']}", "~in-addr.arpa", check=False)
        return f"names under {d['zone']} are resolved through {store.dns_vip(mesh)}"
    run("resolvectl", "revert", settings.IFACE, check=False)
    return "the mesh resolver is no longer used here"


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
