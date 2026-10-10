"""CONTROLLER, commands: what each subcommand does. Each changes the model, then picks a view."""

import argparse, base64, contextlib, hashlib, io, json, os, random, re, secrets, shlex, shutil, socket, subprocess, sys, tarfile, time, zlib, zipfile
from ipaddress import IPv4Address, IPv4Network

from . import cli, model, settings, ssh, store, system, updates, views, wire


def verify_links():
    """Wait for the first WireGuard handshakes: one proves the endpoint, the port forward, both
    keys and the preshared key in a single step."""
    loc, nodes = store.local(), store.load()
    mine = bool(nodes[loc["pub"]]["endpoint"])
    hubs = {pk: n for pk, n in store.live(nodes).items() if pk != loc["pub"] and n["endpoint"]}
    deadline = time.time() + settings.VERIFY_WAIT
    while hubs and time.time() < deadline and not set(hubs) <= set(system.handshakes()):
        time.sleep(1)
    seen = system.handshakes()
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
        with store.locked():
            system.reconcile()
        wire.gossip()


def bootstrap(mesh, key, nodes, nets, a, admin_key=None, conf=None):
    if settings.joined():
        sys.exit("this machine is already in a mesh; run `meshbone leave` first")
    system.install_packages()
    pub = system.run("wg", "pubkey", input=key + "\n").strip()
    if pub not in nodes:
        sys.exit("this config's key does not match any node in it")
    for l in map(IPv4Network, system.local_nets()):
        for reserved in (store.mesh_net(mesh), store.cluster_net(mesh)):
            if l.subnet_of(reserved):
                sys.exit(f"this machine is attached to {l}, which lies inside the mesh's own range {reserved}")
        for k, n in store.live(nodes).items():
            if k != pub and any(IPv4Network(s).subnet_of(l) for s in n["subnets"]):
                print(
                    f"warning: local network {l} overlaps a subnet of {n['name']}; "
                    f"this machine will keep using its local network for it"
                )
    settings.set_mode(getattr(a, "once", False))
    os.makedirs(settings.DIR, mode=0o700, exist_ok=True)
    opts = {k: getattr(a, k) for k in ("listen_port", "mtu") if getattr(a, k, None)}
    if getattr(a, "nat", None):
        opts["nat"] = a.nat == "on"
    store.write(f"{settings.DIR}/node.json", json.dumps({"mesh": mesh, "key": key, "pub": pub, "cost": {}, **opts}))
    if admin_key:
        store.write(f"{settings.DIR}/admin.key", admin_key)
    store.save(nodes)
    store.save_nets(nets)
    store.write(f"{settings.DIR}/conf.json", json.dumps(conf or {}))
    system.install_units()
    with store.locked():
        system.reconcile()
    me = nodes[pub]
    print(
        f"{me['name']}: {'hub' if me['endpoint'] else 'client'} in mesh {mesh['name']}, "
        f"address {store.router_ip(mesh, me['id'])}"
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
    with store.locked():
        loc, nodes, nets = store.admin()
        had_hub = any(n["endpoint"] for n in store.live(nodes).values())
        yield loc, nodes, nets
        if had_hub and not any(n["endpoint"] for n in store.live(nodes).values()):
            sys.exit("that would leave the mesh without a hub; make another node a hub first")
        store.save(nodes)
        system.reconcile()
    wire.gossip(flood=True)


def confirm_hub(name):
    """A node only stays a hub if somebody outside can really dial it: wait until a client reports
    a ping through its endpoint, otherwise take the endpoint away so it is an ordinary client again."""
    loc, deadline = store.local(), time.time() + settings.CONFIRM_WAIT
    while True:
        with store.locked():
            system.reconcile()
        wire.gossip()
        alive, nets = store.live(store.load()), store.load_nets()
        pk, n = store.by_name(store.load(), name)
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
            loc["pub"] in testers and pk in store.read_json("state.json", {}).get("rtt", {})
        ):
            print(f"{name} is reachable at {n['endpoint']}: it is a hub now")
            return
        if time.time() > deadline:
            break
        time.sleep(3)
    with editing() as (loc, nodes, nets):
        pk, n = store.by_name(nodes, name)
        endpoint, n["endpoint"], n["seq"] = n["endpoint"], "", store.next_seq(n["seq"])
        store.sign(pk, n)
    sys.exit(
        f"no client could reach {name} at {endpoint} within {settings.CONFIRM_WAIT}s (port forward? firewall? "
        f"listen port?), so it stays a client. --no-verify skips this test"
    )


def set_password(new):
    if len(new) < 8:
        sys.exit("the password needs at least 8 characters")
    if not os.path.exists(f"{settings.DIR}/admin.key"):
        sys.exit(
            "the password protects this page on nodes that hold the admin key; here you sign in with the key itself"
        )
    with store.locked():
        store.admin()
        salt = secrets.token_bytes(16)
        hashed = hashlib.scrypt(new.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        store.conf_put("admin_pw", store.password_box().encrypt(salt + hashed).decode())
    wire.gossip(flood=True)


def cmd_install():
    system.install_packages()
    system.install_self(settings.SBIN)
    print(f"installed {settings.SBIN}; next: `meshbone create ...` or `meshbone join FILE`")


def cmd_create(a):
    system.install_packages()
    from cryptography.hazmat.primitives import serialization as ser

    key, psk = system.run("wg", "genkey").strip(), system.run("wg", "genpsk").strip()
    pub = system.run("wg", "pubkey", input=key + "\n").strip()
    password = secrets.token_urlsafe(16)
    signer = store.ed25519().Ed25519PrivateKey.generate()
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
    if not store.valid_mesh(mesh):
        sys.exit("bad --mesh, --net (a /20 to /23) or --cluster-net (must not overlap --net)")
    me = store.checked(
        mesh,
        {},
        {},
        pub,
        {
            "name": a.name,
            "id": store.id_pool(mesh, bool(a.endpoint))[0],
            "endpoint": a.endpoint,
            "subnets": a.subnet,
            "vips": [],
            "cost": 0,
            "seq": store.next_seq(),
            "desc": getattr(a, "desc", None) or "",
            "labels": getattr(a, "label", None) or [],
        },
    )
    me["sig"] = base64.b64encode(signer.sign(store.signable(pub, me))).decode()
    bootstrap(mesh, key, {pub: me}, {}, a, admin_key)
    print(
        f"mesh map: http://{store.admin_vip(mesh)}:{settings.ADMIN_PORT}/ (any hub answers, from inside the mesh)\n"
        f"management: http://{store.router_ip(mesh, me['id'])}:{settings.ADMIN_PORT}/admin, user admin, password {password}\n"
        f"(change it there or with `meshbone passwd`)\n"
        f"this machine holds {settings.DIR}/admin.key, the key that controls the mesh"
    )


def cmd_invite(a):
    with editing() as (loc, nodes, nets):
        mesh = loc["mesh"]
        key = system.run("wg", "genkey").strip()
        pub = system.run("wg", "pubkey", input=key + "\n").strip()
        used = {n["id"] for n in nodes.values()}  # ids of revoked nodes are never reused
        if getattr(a, "ip", ""):
            try:
                node_id = int(IPv4Address(a.ip)) - int(store.mesh_net(mesh).network_address)
            except ValueError as e:
                sys.exit(f"bad --ip: {e}")
            if not 0 < node_id < store.mesh_net(mesh).num_addresses - 1 or node_id in used:
                sys.exit(f"{a.ip} is not a free address in {mesh['net']}")
        else:
            # random so that two admins inviting at the same moment rarely collide
            free = sorted(set(store.id_pool(mesh, bool(a.endpoint))) - used)
            if not free:
                sys.exit("the mesh range has no free address for this role")
            node_id = random.choice(free)
        simple, transit = getattr(a, "simple", False), getattr(a, "transit", "") or ""
        if simple and (a.endpoint or a.subnet or a.vip or a.admin):
            sys.exit("a simple client only gets an address: no endpoint, subnets, cluster IPs or admin key")
        if transit and not os.path.exists(f"{settings.DIR}/admin.key"):
            sys.exit("a transit router is added on a node that holds the admin key, which keeps the router's key")
        nodes[pub] = store.sign(
            pub,
            store.checked(
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
                    "seq": store.next_seq(),
                    "desc": getattr(a, "desc", "") or "",
                    "labels": getattr(a, "label", []) or [],
                    "dns": getattr(a, "dns", []) or [],
                    **({"public": a.public} if getattr(a, "public", "") else {}),
                    **({"simple": True} if simple else {}),
                    **({"transit": transit, "via": a.via, "public_nets": a.net} if transit else {}),
                },
            ),
        )
        if simple or transit:
            settings.ISSUED[a.name] = key
            if os.path.exists(f"{settings.DIR}/admin.key"):  # kept with the admin nodes, to show the config again
                store.conf_put(f"node_{node_id}", store.password_box().encrypt(key.encode()).decode())
    if simple or transit:
        return
    out = a.out or f"{a.name}.mesh.json"
    cfg = {**store.state(), "mesh": mesh, "key": key}
    if a.admin:
        if not os.path.exists(f"{settings.DIR}/admin.key"):
            sys.exit("--admin hands over the admin key file, and this machine does not hold it")
        cfg["admin_key"] = store.read("admin.key")
    store.write(out, json.dumps(cfg, indent=1))
    print(
        f"wrote {out} - it holds {a.name}'s private key: copy it over a secure channel, "
        f"run `meshbone join {os.path.basename(out)}` there, then delete it"
    )


def cmd_deploy(a):
    """Invite a node and install it over ssh."""
    hops = ssh.parse_chain(a.remote)
    chain, secret, tmp = [d for d, _ in hops], hops[-1][1], None
    cfg = f"{settings.DIR}/{a.name}.deploy.json"
    with contextlib.redirect_stdout(io.StringIO()):
        cmd_invite(argparse.Namespace(**{**vars(a), "out": cfg}))
    identity = getattr(a, "identity", None)
    if identity and "PRIVATE KEY" not in identity:  # the command line gives a file, the page the key itself
        with open(identity) as f:
            identity = f.read()
    with ssh.ssh_session(hops, identity) as base:
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
                tar.add(updates.program_file(), "meshbone.pyz")
                tar.add(cfg, "mesh.json")
            made = (
                subprocess.run(
                    ssh.remote_argv(base, chain, 'umask 077 && d=$(mktemp -d) && tar -xf - -C "$d" && echo "$d"', jump),
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
                f"python3 {tmp}/meshbone.pyz join {tmp}/mesh.json"
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
                ssh.remote_argv(
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
                    ssh.remote_argv(base, chain, f"rm -rf {tmp}", jump), stdin=subprocess.DEVNULL, capture_output=True
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
    with store.locked():
        system.reconcile()
    print(f"{a.name} is installed and has joined")
    if a.endpoint and getattr(a, "verify", True):
        confirm_hub(a.name)


def cmd_join(a):
    with open(a.file) as f:
        cfg = json.load(f)
    if (
        cfg.get("v") != settings.VERSION
        or not store.valid_mesh(cfg.get("mesh"))
        or not re.fullmatch(settings.KEY_RE, str(cfg.get("key")))
    ):
        sys.exit(f"{a.file} is not a meshbone v{settings.VERSION} config")
    nodes = {pk: n for pk, n in cfg["nodes"].items() if store.valid(cfg["mesh"], pk, n)}
    nets = {pk: r for pk, r in cfg.get("nets", {}).items() if store.valid_nets(pk, r)}
    conf = {k: r for k, r in cfg.get("conf", {}).items() if store.valid_conf(cfg["mesh"], k, r)}
    bootstrap(cfg["mesh"], cfg["key"], nodes, nets, a, cfg.get("admin_key"), conf)


def cmd_set(a):
    with editing() as (loc, nodes, nets):
        pk, n = store.by_name(nodes, a.name)
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
        if getattr(a, "dns", None) is not None:
            n["dns"] = a.dns
        if getattr(a, "public", None) is not None:
            n["public"] = a.public

        n["seq"] = store.next_seq(n["seq"])
        store.sign(pk, store.checked(loc["mesh"], nodes, nets, pk, n, had))
    if n["endpoint"] and not was and getattr(a, "verify", True):
        confirm_hub(a.name)


def cmd_local(a):
    with store.locked():
        loc = store.local()
        for k in ("listen_port", "mtu"):
            if getattr(a, k) is not None:
                loc[k] = getattr(a, k)  # 0 puts it back to automatic
        if a.nat:
            loc["nat"] = a.nat == "on"
        if a.resolver:
            loc["resolver"] = a.resolver == "on"
        store.write(f"{settings.DIR}/node.json", json.dumps(loc))
        system.reconcile()
    print(
        f"listen port {loc.get('listen_port') or 'automatic'}, mtu {loc.get('mtu') or 1420}, "
        f"gateway NAT {'on' if loc.get('nat', True) else 'off'}, mesh resolver {'on' if loc.get('resolver') else 'off'}"
    )
    if a.resolver:
        print(system.set_resolver(a.resolver == "on"))


def cmd_promote(a):
    wants = store.norm_endpoint(a.endpoint)
    with store.locked():
        loc = store.local()
        store.write(f"{settings.DIR}/node.json", json.dumps({**loc, "wants": wants}))
        system.reconcile()
    wire.gossip()
    if wants:
        print(
            f"asked to become a hub at {wants}; on an admin node run `meshbone approve "
            f"{store.load()[loc['pub']]['name']}` (or use the admin page)"
        )


def cmd_approve(a):
    with editing() as (loc, nodes, nets):
        pk, n = store.by_name(nodes, a.name)
        wants, was = nets.get(pk, {}).get("wants", ""), n["endpoint"]
        if not wants or wants == n["endpoint"]:
            sys.exit(f"{a.name} has no pending request")
        n["endpoint"], n["seq"] = wants, store.next_seq(n["seq"])
        store.sign(pk, store.checked(loc["mesh"], nodes, nets, pk, n, n["subnets"]))
    if not was and getattr(a, "verify", True):
        confirm_hub(a.name)


def cmd_revoke(a):
    with editing() as (loc, nodes, nets):
        pk, n = store.by_name(nodes, a.name)
        if pk == loc["pub"]:
            sys.exit("revoke this node from another admin node, or run `meshbone leave` here")
        n["gone"], n["seq"] = True, store.next_seq(n["seq"])
        store.sign(pk, n)


def cmd_cost(a):
    with store.locked():
        loc = store.local()
        store.by_name(store.load(), a.name)
        loc["cost"] = {k: v for k, v in {**loc["cost"], a.name: a.value}.items() if v}
        store.write(f"{settings.DIR}/node.json", json.dumps(loc))
        system.reconcile()


def cmd_policy(a):
    """Show or change the firewall policy: who may open connections to whom across the mesh."""
    pol = store.policy()
    if a.clear or a.default or a.add or a.delete is not None:
        with store.locked():
            loc, nodes, _ = store.admin()
            mesh, alive = loc["mesh"], store.live(nodes)
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
                model.members(src, mesh, alive), model.members(dst, mesh, alive), model.parse_ports(rule["ports"])
                pol["rules"].insert((a.at or len(pol["rules"]) + 1) - 1, rule)
            store.conf_put("policy", json.dumps(pol))
            system.reconcile()
        wire.gossip(flood=True)
    print(views.view_policy(pol))


def cmd_dns(a):
    """Show or change the mesh's DNS: its zone and where other names are looked up."""
    loc = store.local()
    if a.zone or a.upstream:
        with store.locked():
            store.admin()
            d = store.dns_settings(loc["mesh"])
            if a.zone:
                if not model.dns_name(a.zone):
                    sys.exit(f"{a.zone!r} is not a domain name")
                d["zone"] = model.dns_name(a.zone)
            if a.upstream:
                try:
                    d["upstream"] = [str(IPv4Address(u)) for u in store.listed(a.upstream)]
                except ValueError as e:
                    sys.exit(f"bad upstream: {e}")
            store.conf_put("dns", json.dumps(d))
            system.reconcile()
        wire.gossip(flood=True)
    print(views.view_dns(store.dns_settings(loc["mesh"]), model.dns_records(loc["mesh"], store.load())))


def cmd_transit(a):
    """Add a transit router, or print its WireGuard configuration again."""
    if not any(n["name"] == a.name for n in store.live(store.load()).values()):
        if not (a.endpoint and a.via and a.net):
            sys.exit("a new transit router needs --endpoint HOST:PORT, --via HUB and at least one --net")
        cmd_invite(
            argparse.Namespace(
                name=a.name,
                endpoint="",
                subnet=[],
                vip=[],
                cost=0,
                admin=False,
                out=None,
                simple=False,
                transit=a.endpoint,
                via=a.via,
                net=a.net,
                desc=a.desc,
                label=a.label,
                ip="",
                dns=[],
                public="",
            )
        )
    text, n, gateway = model.transit_config(a.name)
    if a.out:
        store.write(a.out, text)
    print(views.view_transit(a.name, n, gateway, store.local()["mesh"], text))


def cmd_simple(a):
    """Create a simple client, or export an existing one again (e.g. through another hub)."""
    if not any(n["name"] == a.name for n in store.live(store.load()).values()):
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
    text, hub, hubs = model.simple_config(a.name, a.hub, settings.ISSUED.get(a.name))
    out = a.out or f"{a.name}.conf"
    store.write(out, text)
    print(
        f"wrote {out}: a standard WireGuard config for {a.name}, connecting through {hub}"
        + (f" (other hubs: {', '.join(h for h in hubs if h != hub)})" if len(hubs) > 1 else "")
        + ". It holds the device's private key - delete it once imported"
    )
    if a.qr:
        print(system.qr(text, "ansiutf8") or "(no QR code: qrencode is not installed)")


def cmd_sync():
    with store.locked():
        system.reconcile()
    wire.gossip()
    updates.maybe_update()


def cmd_status():
    loc = store.local()
    notes = model.warnings() + [
        f"this machine already routes {p} some other way, so its own traffic there does not use the mesh "
        f"(traffic it relays for others does)"
        for p in store.read_json("state.json", {}).get("elsewhere", [])
    ]
    print(
        views.view_status(
            loc["mesh"],
            list(model.rows()),
            notes,
            settings.ONCE,
            os.path.exists(f"{settings.DIR}/admin.key"),
            store.code_sha(),
        )
    )


def cmd_leave():
    units = [
        "meshbone.timer",
        "meshbone.service",
        "meshbone-serve.socket",
        "meshbone-admin.socket",
        "meshbone-dns.service",
    ]
    system.run("systemctl", "disable", "--now", *units, check=False)
    system.firewall([])
    system.apply_table(None)
    system.run("ip", "rule", "del", "pref", str(settings.MESH_TABLE), check=False)
    system.sync_exit(False)
    for ifn in (settings.IFACE, "mbvip"):
        system.run("ip", "link", "del", ifn, check=False)
    for path in [f"{settings.UNIT_DIR}/{name}" for name in settings.UNITS]:
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)
    shutil.rmtree(settings.DIR, ignore_errors=True)
    system.run("systemctl", "daemon-reload", check=False)
    print("left the mesh; run `meshbone revoke` for this node on an admin node so its key stops being accepted")


def cmd_upgrade():
    """Run from the new script: replaces the installed copy and units, keeps the mesh state."""
    system.install_units()
    with store.locked():
        system.reconcile()


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
    loc, nodes, nets = store.local(), store.load(), store.load_nets()
    mesh = loc["mesh"]
    if not store.valid_mesh(mesh) or loc["pub"] not in nodes:
        sys.exit("this version cannot read the node's own settings")
    unreadable = [n.get("name", pk) for pk, n in nodes.items() if not store.valid(mesh, pk, n)]
    if unreadable:
        sys.exit(f"this version rejects directory entries the node accepts today: {', '.join(unreadable)}")
    table, _ = model.plan(loc, nodes, nets, {}, {}) if loc["pub"] in store.live(nodes) else ({}, None)
    for pk in table:
        model.pair_psk(loc, pk)
    topo = model.topology()
    views.view_map(mesh, topo), views.view_traffic(mesh), views.view_api(mesh), views.view_metrics(
        topo, model.traffic_totals()
    )
    views.view_status(mesh, list(model.rows()), model.warnings(), settings.ONCE, False, store.code_sha())
    if os.path.exists(f"{settings.DIR}/admin.key"):
        views.view_admin(
            mesh,
            nodes[loc["pub"]]["name"],
            list(model.rows()),
            "x",
            "",
            model.software(),
            None,
            True,
            "",
            store.policy(),
            store.dns_settings(mesh),
        )
    records = model.dns_records(mesh, nodes)
    model.dns_answer(
        records,
        store.dns_settings(mesh)["zone"],
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03map\x00\x00\x01\x00\x01",
    )
    views.view_dns(store.dns_settings(mesh), records)
    model.mesh_table(
        model.policy_ruleset(mesh, store.live(nodes), store.policy()),
        model.gateway_ruleset(mesh, nodes[loc["pub"]], True),
    )
    views.view_policy(store.policy())
    views.view_login(mesh, "s", "p", 0, "")
    for text in settings.UNITS.values():
        text.format(py="p", bin="b", port=1, net=mesh["net"], vip="v", aport=2)
    cli.build_parser()
    print("ok")


def cmd_health():
    sys.exit(0 if system.reachable() else "this node is not in touch with the mesh")


def cmd_update(a):
    """Fetch a version, prove it on this node first, then hand it to the whole mesh."""
    store.admin()
    if a.rollback:
        sha, source = store.read_json("update.json", {}).get("was", ""), "rollback"
        if not sha or not os.path.exists(store.release_path(sha)):
            sys.exit("there is no earlier version on this node to go back to")
    else:
        if a.file:
            source = os.path.abspath(a.file)
            if os.path.isdir(a.file):  # a source tree: the package directory, or the one holding it
                tree = a.file if os.path.isfile(os.path.join(a.file, "cli.py")) else os.path.join(a.file, "meshbone")
                data = updates.build_archive(tree)
            else:
                with open(a.file, "rb") as f:
                    data = f.read()
        else:
            data, source = updates.fetch_source(a.url or "", a.ref)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                compile(z.read("meshbone/cli.py"), "cli.py", "exec")
        except (SyntaxError, ValueError, KeyError, OSError, zipfile.BadZipFile) as e:
            sys.exit(f"{source} is not a program this node can run: {e}")
        sha = hashlib.sha256(data).hexdigest()
        store.store_code(sha, base64.b64encode(zlib.compress(data)).decode())
    store.audit("fetched", node=socket.gethostname(), sha=sha, source=source)
    if sha != store.code_sha():
        ok, why = updates.apply_release(sha)
        if not ok:
            sys.exit(f"version {sha[:12]} was not accepted on this node, so it was not rolled out: {why}")
    with store.locked():
        store.conf_put("release", json.dumps({"sha": sha, "source": source, "time": time.strftime("%Y-%m-%d %H:%M")}))
        system.reconcile()
    wire.gossip(flood=True)
    store.audit("published", node=socket.gethostname(), sha=sha, source=source)
    print(
        f"version {sha[:12]} runs on this node and is rolling out to the others; the management page shows how it goes"
    )
