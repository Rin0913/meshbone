"""The wire protocol between nodes: exchanging directories, traffic history and program versions."""

import json, os, re, socket
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address

from . import model, settings, store, system


def exchange(mesh, peer, msg):
    """Send our state to a peer over the mesh and return its state."""
    with socket.create_connection((str(store.router_ip(mesh, peer["id"])), settings.GOSSIP_PORT), timeout=3) as s:
        s.sendall(json.dumps(msg).encode() + b"\n")
        return json.loads(s.makefile("rb").readline(8 << 20))


def handle(ip, line):
    """Answer one exchange -> (reply, changed).

    There is no application-level auth: WireGuard only lets a packet in if its
    source address belongs to the peer it came from, so inside the mesh the
    source address *is* the peer's identity.
    """
    try:
        node_id = int(IPv4Address(ip)) - int(store.mesh_net(store.local()["mesh"]).network_address)
    except ValueError:
        return None, False
    with store.locked():
        nodes = store.load()
        peer = next((pk for pk, n in store.live(nodes).items() if n["id"] == node_id), None)
        if not peer:
            return None, False
        try:
            msg = json.loads(line)
            changed = store.merge(msg, None if nodes[peer]["endpoint"] else peer)
        except ValueError:
            return None, False
        reply, me = store.state(), nodes[store.local()["pub"]]
        if not isinstance(msg, dict):
            msg = {}
        if type(msg.get("stats_since")) is int and me["endpoint"]:
            reply.update(
                model.stats_export(me["id"], msg["stats_since"])
            )  # for whoever keeps a copy of the traffic history
        if re.fullmatch(r"[0-9a-f]{64}", str(msg.get("want_code"))):
            reply["code"] = store.offer_code(
                msg["want_code"]
            )  # not secret, and the asker checks it against the signed release
        return json.dumps(reply).encode() + b"\n", changed


def gossip(flood=False):
    """Push-pull with every hub; a hub that has news (flood) also pushes it down to its clients."""
    loc = store.local()
    mypk, nodes = loc["pub"], store.load()
    hub = bool(nodes[mypk]["endpoint"])
    peers = [  # simple clients run no meshbone, nothing to tell them
        (pk, n)
        for pk, n in store.live(nodes).items()
        if pk != mypk and not n.get("simple") and (n["endpoint"] or (hub and flood))
    ]
    msg, want = store.state(), store.wanted_code()
    copies = model.keeps_stats(nodes[mypk])
    since = model.stats_cursors() if copies else {}
    if want:
        msg["want_code"] = want

    def one(peer):
        try:
            ask = {**msg, "stats_since": since.get(peer[1]["id"], 0)} if copies and peer[1]["endpoint"] else msg
            return peer[0], exchange(loc["mesh"], peer[1], ask)
        except (OSError, ValueError):
            return peer[0], None  # down or not linked yet; the next round will do

    with ThreadPoolExecutor(settings.PARALLEL) as pool:
        results = list(pool.map(one, peers))
    with store.locked():
        changed = [store.merge(got, None if nodes[pk]["endpoint"] else pk) for pk, got in results]
        for pk, got in results:
            if copies and nodes[pk]["endpoint"] and isinstance(got, dict):
                model.stats_import(nodes[pk]["id"], got)
            if want and isinstance(got, dict) and got.get("code") and not os.path.exists(store.release_path(want)):
                store.store_code(want, got["code"])
        if any(changed):
            system.reconcile()
    if any(changed) and hub:
        gossip(flood=True)


def settle(changed):
    """After accepting news: apply it here and, on a hub, pass it on to everyone."""
    if changed:
        with store.locked():
            system.reconcile()
        gossip(flood=True)
