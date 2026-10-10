"""CONTROLLER, HTTP: one request in, one response out - the map, the API, the management page - and one gossip connection."""

import argparse, base64, contextlib, hashlib, hmac, io, json, os, re, socket, subprocess, sys, time, urllib.parse

from . import commands, model, settings, store, system, views, wire


def simple_response(mesh, query, key=None):
    name, hub = query.get("name", [""])[0], query.get("hub", [None])[0]
    try:
        text, hub, hubs = model.simple_config(name, hub, key)
    except SystemExit as e:
        return "404 Not Found", f"{e}\n".encode(), "text/plain; charset=utf-8", ""
    stored = os.path.exists(f"{settings.DIR}/admin.key")
    return (
        "200 OK",
        views.view_simple(mesh, name, hub, hubs, text, system.qr(text, "SVG"), stored),
        "text/html; charset=utf-8",
        "",
    )


def respond(method, path, headers, body, peer="127.0.0.1"):
    """One HTTP request -> (status, body, content type, extra headers).

    Everything but /admin is read-only and open to the mesh: the map, traffic,
    the JSON API and /metrics. /admin works on every node. Where the admin key
    is stored it asks for the page password; anywhere else it asks for the key
    itself, which the browser turns into a short-lived token (see view_login).
    """
    loc = store.local()
    mesh = loc["mesh"]
    route, _, qs = path.partition("?")
    route, query = route.rstrip("/") or "/", urllib.parse.parse_qs(qs)

    def page(content):
        return "200 OK", content, "text/html; charset=utf-8", ""

    def data(value):
        return "200 OK", json.dumps(value, indent=1).encode(), "application/json", ""

    public = {
        "/": lambda: page(views.view_map(mesh, model.topology())),
        "/traffic": lambda: page(views.view_traffic(mesh)),
        "/api": lambda: page(views.view_api(mesh)),
        "/api/nodes": lambda: data(model.api_nodes(query)),
        "/api/topology": lambda: data(model.topology()),
        "/api/policy": lambda: data(store.policy()),
        "/api/dns": lambda: data(
            {
                **store.dns_settings(mesh),
                "records": {k: [str(x) for x in v] for k, v in model.dns_records(mesh, store.load()).items()},
            }
        ),
        "/api/traffic": lambda: data(model.api_traffic(query)),
        "/metrics": lambda: (
            "200 OK",
            views.view_metrics(model.topology(), model.traffic_totals()),
            "text/plain; version=0.0.4; charset=utf-8",
            "",
        ),
    }
    if not route.startswith("/admin"):
        return public.get(route, public["/"])()

    form = (
        {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()}
        if method == "POST"
        else {}
    )
    sid = (re.search(r"(?:^|;\s*)mb=([\w-]{10,60})", headers.get("cookie", "")) or [None, None])[1]
    held, now = os.path.exists(f"{settings.DIR}/admin.key"), int(time.time())
    if route == "/admin/logout":
        store.session_close(sid)
        return "303 See Other", b"", "text/plain", "Location: /admin\r\nSet-Cookie: mb=; Path=/admin; Max-Age=0\r\n"
    if route == "/admin/login" and method == "POST":
        try:
            nbf, exp = int(form.get("nbf", "")), int(form.get("exp", ""))
        except ValueError:
            nbf = exp = 0
        if store.session_grant(mesh, form.get("sid", ""), peer, nbf, exp, form.get("sig", "")):
            cookie = f"mb={form['sid']}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={exp - now}"
            return "303 See Other", b"", "text/plain", f"Location: /admin\r\nSet-Cookie: {cookie}\r\n"
        return page(views.view_login(mesh, *store.session_open(peer), now, "that token was not accepted; try again"))
    session = store.session_use(sid, peer)
    if route == "/admin/login" or not (session or held):
        return page(views.view_login(mesh, *store.session_open(peer), now, ""))
    if session:
        settings.SESSION, secret, until = session[:2], sid, session[2]
    else:
        try:
            secret = base64.b64decode(headers.get("authorization", "").split()[1]).decode().partition(":")[2]
        except Exception:
            secret = ""
        if not secret or not store.check_password(secret):
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
        subnets, labels = store.listed(form.get("subnets", "")), store.listed(form.get("labels", ""))
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
            zone=form.get("zone", ""),
            upstream=form.get("upstream", ""),
            dns=store.listed(form.get("dns", "")) if "dns" in form else None,
            public=form.get("public", "").strip() if "public" in form else None,
            exit=None,
            once=False,
            listen_port=None,
            mtu=None,
            simple=form.get("simple") == "1",
            new1=form.get("new1", ""),
            new2=form.get("new2", ""),
            source=form.get("source", ""),
            ref=form.get("ref", ""),
            out=f"{settings.DIR}/.invite-{os.getpid()}.json",
        )
        actions = {
            "set": web_set,
            "revoke": commands.cmd_revoke,
            "approve": commands.cmd_approve,
            "invite": web_invite,
            "passwd": web_passwd,
            "update": web_update,
            "rollback": web_update,
            "policy_add": web_policy,
            "policy_del": web_policy,
            "policy_default": web_policy,
            "dns": web_dns,
        }
        try:
            a.cost = int(form.get("cost") or 0)
            if a.action not in actions:
                sys.exit("unknown action")
            with contextlib.redirect_stdout(io.StringIO()) as said:
                actions[a.action](a)
            if a.action == "invite" and a.simple:
                return simple_response(mesh, {"name": [a.name]}, settings.ISSUED.get(a.name))
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
    me = store.load()[loc["pub"]]["name"]
    try:
        origin = system.deploy_key()[1] if os.geteuid() == 0 else ""
    except (OSError, subprocess.CalledProcessError):
        origin = ""
    return page(
        views.view_admin(
            mesh,
            me,
            list(model.rows()),
            csrf,
            note,
            model.software(),
            until,
            held,
            origin,
            store.policy(),
            store.dns_settings(mesh),
        )
    )


def web_passwd(a):
    if a.new1 != a.new2:
        sys.exit("the two entries differ")
    commands.set_password(a.new1)
    print("password changed - log in again with the new one")


def web_set(a):
    vips = store.by_name(store.load(), a.name)[1]["vips"]  # the page has no field for these; leave them alone
    commands.cmd_set(argparse.Namespace(**{**vars(a), "vip": vips, "no_vip": not vips}))


def web_invite(a):
    if a.simple and a.remote:
        sys.exit("a simple client is not installed over ssh: scan its QR code or import its config")
    commands.cmd_deploy(a) if a.remote else commands.cmd_invite(a)


def web_update(a):
    commands.cmd_update(argparse.Namespace(url=a.source, ref=a.ref, file=None, rollback=a.action == "rollback"))


def web_policy(a):
    commands.cmd_policy(
        argparse.Namespace(
            clear=False,
            default=a.default if a.action == "policy_default" else None,
            add=[a.src, a.dst, a.verdict] if a.action == "policy_add" else None,
            ports=a.ports,
            at=None,
            delete=int(a.rule) if a.action == "policy_del" else None,
        )
    )


def web_dns(a):
    commands.cmd_dns(argparse.Namespace(zone=a.zone, upstream=a.upstream))


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


def cmd_serve():
    """One exchange on the connection systemd handed us (Accept=yes socket)."""
    sock = socket.fromfd(0, socket.AF_INET, socket.SOCK_STREAM)
    reply, changed = wire.handle(sock.getpeername()[0], sock.makefile("rb").readline(8 << 20))
    if reply:
        sock.sendall(reply)
    sock.close()
    wire.settle(changed)
