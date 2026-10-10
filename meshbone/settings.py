"""Constants, paths and the few switches set once per process."""

import os, sys


VERSION = 6


IFACE = "mb0"


DEFAULT_PORT = 51820


GOSSIP_PORT = 7947  # TCP, reachable only from mesh addresses


ADMIN_PORT = 7948  # HTTP: the mesh map on every hub, plus /admin on the admin nodes


FRESH = 180  # a WireGuard peer with a handshake this recent (s) counts as reachable


VERIFY_WAIT = 20  # how long join waits for the first handshakes (s)


CONFIRM_WAIT = 60  # how long a new hub has to be reached from outside before it is demoted again (s)


UPDATE_SETTLE = 10  # seconds a freshly upgraded node gets before its health is judged


MESH_TABLE = 7948  # routing table (and rule priority) for packets that arrive from the mesh


EXIT_TABLE = 7949  # routing table (and fwmark) for a node whose internet goes out through the mesh


SESSIONS = "/run/meshbone-sessions"  # web sessions that hold a token; gone at reboot


SESSION_MAX = 12 * 3600  # the longest a token may be valid (s)


SESSION = None  # (key, delegation) while a command or request may sign changes without the admin key file


ISSUED = {}  # private keys of simple clients created by this process: name -> key


KEEP_FINE = 2 * 86400  # traffic history: per-minute buckets this long, 10-minute buckets after that


KEEP_ALL = 90 * 86400


PARALLEL = 16


SBIN = "/usr/local/sbin/meshbone"


KEY_RE = r"[A-Za-z0-9+/]{43}="


NAME_RE = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}"


ENDPOINT_RE = r"(|(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):\d{1,5})"


LABEL_RE = r"[A-Za-z0-9][A-Za-z0-9_.:=/-]{0,47}"


UNITS = {
    "meshbone.service": """[Unit]
Description=meshbone: reconcile links and sync the mesh directory
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={py} {bin} sync
TimeoutStartSec=120
""",
    "meshbone.timer": """[Unit]
Description=meshbone periodic sync

[Timer]
OnBootSec=3
OnCalendar=*:*:0/15
AccuracySec=1
RandomizedDelaySec=3

[Install]
WantedBy=timers.target
""",
    # the sockets are started and stopped by `meshbone sync`, only the timer is enabled
    "meshbone-serve.socket": """[Unit]
Description=meshbone directory exchange

[Socket]
ListenStream=0.0.0.0:{port}
Accept=yes
MaxConnections=32
IPAddressDeny=any
IPAddressAllow={net}
""",
    "meshbone-serve@.service": """[Unit]
Description=meshbone directory exchange (per connection)

[Service]
ExecStart={py} {bin} serve
StandardInput=socket
StandardOutput=journal
StandardError=journal
RuntimeMaxSec=60
""",
    "meshbone-admin.socket": """[Unit]
Description=meshbone admin page

[Socket]
ListenStream=0.0.0.0:{aport}
Accept=yes
MaxConnections=16
IPAddressDeny=any
IPAddressAllow={net} 127.0.0.0/8
""",
    "meshbone-dns.service": """[Unit]
Description=meshbone DNS: the mesh's names, everything else forwarded
After=network.target

[Service]
ExecStart={py} {bin} dnsd
Restart=always
RestartSec=3
""",
    "meshbone-admin@.service": """[Unit]
Description=meshbone admin page (per connection)

[Service]
ExecStart={py} {bin} admin
StandardInput=socket
StandardOutput=journal
StandardError=journal
RuntimeMaxSec=300
""",
}


def set_mode(once):
    global ONCE, DIR, UNIT_DIR, BIN
    ONCE = once
    if once:
        DIR, UNIT_DIR, BIN = "/run/meshbone", "/run/systemd/system", "/run/meshbone/meshbone"
    else:
        DIR, UNIT_DIR, BIN = "/etc/meshbone", "/etc/systemd/system", SBIN


def archive():
    """The archive (meshbone.pyz) this program runs from, or None when it runs from source files."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return here if os.path.isfile(here) else None


def package_dir():
    """Where this program's own modules are - inside the archive or a source tree."""
    return os.path.dirname(os.path.abspath(__file__))


def joined():
    return any(os.path.exists(f"{d}/node.json") for d in ("/etc/meshbone", "/run/meshbone"))


def log(*a):
    print(*a, file=sys.stderr, flush=True)


set_mode(os.path.exists("/run/meshbone/node.json"))
