"""The resolver served on the hubs' cluster IP."""

import os, select, socket, struct
from concurrent.futures import ThreadPoolExecutor

from . import model, settings, store


def resolver_loop(address):
    """The DNS service: answer the zone from the directory, pass everything else upstream.
    Serves UDP and TCP on `address`:53 until the process is stopped."""
    loc = store.local()
    mesh = loc["mesh"]
    cache = {"stamp": None, "records": {}, "zone": "", "upstream": []}

    def current():
        try:
            stamp = (
                os.stat(f"{settings.DIR}/nodes.json").st_mtime_ns,
                os.stat(f"{settings.DIR}/conf.json").st_mtime_ns,
            )
        except OSError:
            stamp = None
        if stamp != cache["stamp"]:
            d = store.dns_settings(mesh)
            cache.update(
                stamp=stamp, records=model.dns_records(mesh, store.load()), zone=d["zone"], upstream=d["upstream"]
            )
        return cache

    def reply(query, tcp):
        c = current()
        return model.dns_answer(c["records"], c["zone"], query) or model.dns_forward(c["upstream"], query, tcp)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for s in (udp, tcp):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND: the cluster IP may appear a moment later
        s.bind((address, 53))
    tcp.listen(16)

    def over_tcp(conn):
        with conn:
            try:
                conn.settimeout(10)
                size = struct.unpack("!H", conn.recv(2))[0]
                query = b""
                while len(query) < size:
                    part = conn.recv(size - len(query))
                    if not part:
                        return
                    query += part
                out = reply(query, True)
                conn.sendall(struct.pack("!H", len(out)) + out)
            except (OSError, struct.error):
                pass

    def over_udp(query, peer):
        try:
            udp.sendto(reply(query, False), peer)
        except OSError:
            pass

    with ThreadPoolExecutor(settings.PARALLEL) as pool:
        while True:
            ready, _, _ = select.select([udp, tcp], [], [])
            for s in ready:
                if s is udp:
                    query, peer = udp.recvfrom(4096)
                    if len(query) >= 12:
                        pool.submit(over_udp, query, peer)
                else:
                    conn, _ = tcp.accept()
                    pool.submit(over_tcp, conn)


def cmd_dnsd():
    """The resolver process, on hubs; started by `sync`, kept alive by systemd."""
    resolver_loop(str(store.dns_vip(store.local()["mesh"])))
