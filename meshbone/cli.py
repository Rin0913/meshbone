"""The command line: argument parsing and dispatch."""

import argparse, os, socket, sys

from . import commands, dns, egress, http, proxy, settings


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def node_options(s):
        s.add_argument("--subnet", action="append", default=[], help="network behind the node to announce")
        s.add_argument("--vip", action="append", default=[], help="cluster IP the node holds")
        s.add_argument(
            "--cost", type=int, default=0, help="ms added to this hub's ping when choosing a hub (may be negative)"
        )
        s.add_argument(
            "--dns", action="append", default=[], help="extra DNS name for the node (bare: under the mesh zone)"
        )
        s.add_argument("--public", default="", help="public address the exit router maps 1:1 onto this node")
        s.add_argument("--desc", default="", help="free-text description")
        s.add_argument("--label", action="append", default=[], help="label, repeatable")
        s.add_argument("--ip", default="", help="mesh address to give the node (default: a free one)")
        s.add_argument(
            "--no-verify",
            dest="verify",
            action="store_false",
            help="keep a new hub's endpoint even if no client could reach it",
        )

    def local_options(s):
        s.add_argument("--listen-port", type=int, help="local UDP port, if it differs from the endpoint's")
        s.add_argument("--mtu", type=int, help="tunnel MTU (default 1420)")
        s.add_argument(
            "--nat", choices=("on", "off"), help="as a gateway, hide the mesh behind this node's address (default on)"
        )
        s.add_argument(
            "--resolver",
            choices=("on", "off"),
            help="use the mesh resolver as this host's DNS, fallbacks after it (default on)",
        )
        s.add_argument(
            "--fallback",
            help="this host's fallback resolvers after the mesh one, e.g. '9.9.9.9 1.1.1.1' ('' = the mesh's)",
        )

    s = sub.add_parser("create")
    s.add_argument("--endpoint", default="", help="public HOST:PORT of this machine, if it is to be a hub")
    s.add_argument("--name", default=socket.gethostname().split(".")[0])
    s.add_argument("--subnet", action="append", default=[], help="network behind this node to announce")
    s.add_argument("--desc", default="")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("--mesh", default="mesh")
    s.add_argument("--net", default="10.253.254.0/23", help="node addresses: first /24 hubs, rest clients")
    s.add_argument("--cluster-net", default="10.253.253.0/24", help="cluster (anycast) IPs")
    local_options(s)
    s = sub.add_parser("invite")
    s.add_argument("name")
    s.add_argument("--endpoint", default="", help="public HOST:PORT; makes the new node a hub")
    node_options(s)
    s.add_argument("--admin", action="store_true", help="the new node also gets admin.key and can manage the mesh")
    s.add_argument("-o", "--out")
    s = sub.add_parser("gateway", aliases=["transit"])
    s.add_argument("name")
    s.add_argument("--endpoint", default="", help="the router's WireGuard HOST:PORT (needed the first time)")
    s.add_argument("--via", default="", help="the hub the router is linked to (needed the first time)")
    s.add_argument(
        "--net", action="append", default=[], help="public network the router delivers, e.g. 203.0.113.64/26"
    )
    s.add_argument("--desc", default="")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("-o", "--out", help="also write the router's WireGuard config to this file")
    s = sub.add_parser("deploy")
    s.add_argument("name")
    s.add_argument(
        "--remote",
        required=True,
        metavar="USER[:PASSWORD]@HOST[;...]",
        help="ssh destination, optionally behind jump hosts separated by ';'",
    )
    s.add_argument("--endpoint", default="")
    node_options(s)
    local_options(s)
    s.add_argument("--admin", action="store_true")
    s.add_argument("--identity", help="private key file to log in with, for this deploy only")
    s.add_argument("--once", action="store_true")
    s = sub.add_parser("join")
    s.add_argument("file")
    s.add_argument("--once", action="store_true")
    local_options(s)
    s = sub.add_parser("set")
    s.add_argument("name")
    s.add_argument("--endpoint")
    s.add_argument("--subnet", action="append", default=[])
    s.add_argument("--no-subnet", action="store_true")
    s.add_argument("--vip", action="append", default=[])
    s.add_argument("--no-vip", action="store_true")
    s.add_argument("--cost", type=int)
    s.add_argument("--desc")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("--no-label", action="store_true")
    s.add_argument("--no-verify", dest="verify", action="store_false")
    s.add_argument("--dns", action="append", help="extra DNS names; --dns '' removes them")
    s.add_argument("--public", help="public address for the node; --public '' removes it")
    local_options(sub.add_parser("local"))
    s = sub.add_parser("promote")
    s.add_argument("--endpoint", required=True, help="stable public HOST:PORT of this node; '' withdraws")
    s = sub.add_parser("simple")
    s.add_argument("name")
    s.add_argument("--hub", help="hub to connect through (default: the one that sees the device, else the cheapest)")
    s.add_argument("--qr", action="store_true", help="also print a QR code for the WireGuard phone app")
    s.add_argument("-o", "--out")
    s.add_argument("--desc", default="")
    s.add_argument("--label", action="append", default=[])
    s.add_argument("--ip", default="")
    s = sub.add_parser("approve")
    s.add_argument("name")
    s.add_argument("--no-verify", dest="verify", action="store_false")
    sub.add_parser("revoke").add_argument("name")
    s = sub.add_parser("https")
    s.add_argument(
        "--add", nargs=2, metavar=("NAME", "URL"), help="serve NAME (bare: under the zone) by proxying to URL"
    )
    s.add_argument("--del", dest="delete", metavar="NAME", help="stop serving NAME")
    s.add_argument("--ca", action="store_true", help="print the mesh CA certificate")
    s.add_argument(
        "--letsencrypt",
        metavar="EMAIL",
        help="a public certificate (wildcard for the zone) from Let's Encrypt, renewed here",
    )
    s.add_argument(
        "--cloudflare-token", help="Cloudflare API token that may edit the zone's DNS (for the dns-01 challenge)"
    )
    s.add_argument("--staging", action="store_true", help="use Let's Encrypt's staging CA (for trying it out)")
    s.add_argument("--cert", metavar="FILE", help="use this certificate chain (PEM) instead, with --key")
    s.add_argument("--key", metavar="FILE", help="the certificate's private key (PEM)")
    s.add_argument("--mesh-ca", action="store_true", help="back to a certificate from the mesh's own CA")
    s = sub.add_parser("proxy")
    s.add_argument("name", nargs="?", help="the node that runs the proxy (without: list them)")
    s.add_argument("--port", type=int, help="port on the node's mesh address (default 3128)")
    s.add_argument("--user", help="user name (default meshbone)")
    s.add_argument("--rotate", action="store_true", help="make a new password")
    s.add_argument("--off", action="store_true", help="switch the proxy off on this node")
    s = sub.add_parser("dns")
    s.add_argument("--zone", help="domain under which every node has a name (default <mesh>.internal)")
    s.add_argument("--upstream", help="resolvers for every other name, e.g. '1.1.1.1 8.8.8.8'")
    s = sub.add_parser("policy")
    s.add_argument("--default", choices=("allow", "deny"), help="what happens to a new connection no rule matches")
    s.add_argument("--add", nargs=3, metavar=("FROM", "TO", "ACTION"), help="add a rule; ACTION is allow or deny")
    s.add_argument("--ports", help="limit the rule being added, e.g. 'tcp/22,443 udp/53'")
    s.add_argument("--at", type=int, help="position for the rule being added (default: last)")
    s.add_argument("--del", dest="delete", type=int, metavar="N", help="remove rule N")
    s.add_argument("--clear", action="store_true", help="remove every rule and allow everything again")
    s = sub.add_parser("cost")
    s.add_argument("name")
    s.add_argument("value", type=int)
    s = sub.add_parser("update")
    s.add_argument("url", nargs="?", help="https://github.com/OWNER/REPO, or a direct https link to meshbone.py")
    s.add_argument("--ref", help="branch, tag or commit (default main)")
    s.add_argument("--file", help="take the new version from a local file instead")
    s.add_argument("--rollback", action="store_true", help="publish the version this node ran before")
    plain = (
        "install",
        "sync",
        "serve",
        "admin",
        "status",
        "leave",
        "upgrade",
        "passwd",
        "check",
        "health",
        "dnsd",
        "httpsd",
        "proxyd",
    )
    for c in plain:
        sub.add_parser(c)
    return p, plain


def main():
    p, plain = build_parser()
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("meshbone must run as root")
    if a.cmd not in ("install", "create", "join") and not settings.joined():
        sys.exit("this machine is not in a mesh yet (see `meshbone create` / `meshbone join`)")
    fn = next(
        getattr(mod, f"cmd_{a.cmd}") for mod in (commands, http, dns, proxy, egress) if hasattr(mod, f"cmd_{a.cmd}")
    )
    fn() if a.cmd in plain else fn(a)
