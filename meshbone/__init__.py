#!/usr/bin/env python3
"""meshbone - WireGuard mesh backbone without a controller.

Every node has one WireGuard interface (mb0) and, if it is a hub, one UDP
port. Which peer carries which prefix is computed on every node from a signed
directory, so there is no routing daemon and no single machine to lose.

Roles
  hub      public host: other nodes dial its --endpoint (HOST:PORT; one
           forwarded UDP port is enough) and it relays between them.
           A hub holds no authority over the mesh.
  client   node behind NAT. Stays linked to every hub, sends through the one
           with the best ping and moves to another within seconds if it dies.
  admin    any node that holds admin.key. The directory is signed with that
           key, so only admin nodes can add, change or revoke nodes - keep it
           off the exposed machines.
  subnet   a network announced into the mesh by a hub or client acting as gateway.
  external gateway  a router (VyOS, say) that owns public addresses and runs plain WireGuard
           to one hub. That hub maps public addresses 1:1 onto nodes (`--public`), whose
           internet traffic leaves and enters through the gateway; the router only forwards.
  cluster IP  an address several nodes hold at once (anycast): traffic goes to
           one that is alive. Every hub holds the first two: .1 is the mesh
           map, traffic graphs and JSON API, .2 the Prometheus /metrics
           (both http, port 7948, read-only).

Addresses come from the mesh range (default 10.253.254.0/23, first /24 for
hubs, the rest for clients); cluster IPs from 10.253.253.0/24.

Any machine
  meshbone install              packages + /usr/local/sbin/meshbone, nothing else
  meshbone create [--endpoint HOST:PORT] [--name N] [--subnet CIDR]... [--mesh NAME] [--net CIDR] [--cluster-net CIDR]
                                this machine becomes the first node and the first admin
  meshbone join FILE [--once]   FILE is the mesh config written by `invite`;
                                --once keeps everything in /run (gone after reboot or `leave`)
  meshbone local [--listen-port N] [--mtu N] [--nat on|off] [--resolver on|off] [--fallback 'IP IP']
                                this machine's own network settings (also accepted by create, join and deploy)
  meshbone promote --endpoint HOST:PORT   ask to become a hub at this stable public address
  meshbone cost NAME MS         local penalty in ms for sending via hub NAME (0 = automatic)
  meshbone status | leave | upgrade

Managing (the commands below, or http://10.253.253.1:7948/admin on any node)
  Changes are signed. A node that holds admin.key signs directly. Anywhere else you paste the
  admin key into the page - it stays in the browser, which signs a token of limited life for
  that node - or type it when a command asks.
  meshbone passwd               change the management page's password, on every admin node
  meshbone update URL [--ref REF] | --file PATH | --rollback
                                fetch a version (https://github.com/OWNER/REPO at a branch, tag or commit),
                                install and health-check it here first, then sign it and let every node
                                do the same; a node that fails keeps its old version and logs why
  meshbone invite NAME [--endpoint HOST:PORT] [--subnet CIDR]... [--vip IP]... [--cost MS] [--admin] [-o FILE]
  meshbone deploy NAME --remote 'USER[:PASSWORD]@HOST[;USER[:PASSWORD]@HOST]...' [invite options] [--once]
                                invite + install + join over ssh, through any number of jump hosts
  (invite, deploy and set also take --desc TEXT and --label L...; invite and deploy take --ip ADDRESS.
   Giving a node an endpoint makes it a hub once a client has reached it there; --endpoint '' makes
   it a client again. A mesh always keeps at least one hub.)
  meshbone set NAME [--endpoint HOST:PORT] [--subnet CIDR]... [--no-subnet] [--vip IP]... [--no-vip] [--cost MS]
  meshbone simple NAME [--hub HUB] [--qr] [-o FILE]
                                a client for a phone or any device that only runs plain WireGuard:
                                writes a standard config (and shows a QR code); run it again to re-export
  meshbone approve NAME         accept a `promote` request
  meshbone gateway NAME [--endpoint HOST:PORT --via HUB --net CIDR...]
                                add an external gateway (or print its config again): plain WireGuard config
                                and VyOS commands for the router's operator
  meshbone https [--add NAME URL] [--del NAME] [--ca] [--letsencrypt EMAIL --cloudflare-token T] [--cert F --key F] [--mesh-ca]
                                the HTTPS gateway on cluster IP .4: NAME.<zone> is served with the mesh's
                                own certificate and proxied to URL inside the mesh; --ca prints the CA
                                certificate to install in browsers (also http://<map>/ca.crt)
  meshbone dns [--zone DOMAIN] [--upstream 'IP IP']
                                the mesh's names: every node is <name>.<zone> (plus --dns names and labels);
                                the resolver is cluster IP .3 on every hub, other names go upstream
  meshbone policy [--default allow|deny] [--add FROM TO allow|deny [--ports P] [--at N]] [--del N] [--clear]
                                the firewall: who may open connections to whom across the mesh. FROM and TO
                                are groups: a label, @name, nodes, hubs, clients, subnets, LABEL+net, any,
                                or an address. First matching rule decides.
  meshbone revoke NAME

The file is laid out as model, view, controller - see the banners below.
"""

import sys as _sys
import types as _types

from . import acme, cli, egress, commands, dns, http, model, proxy, settings, ssh, store, system, updates, views, wire

MODULES = (settings, store, model, system, ssh, wire, updates, dns, proxy, acme, egress, views, http, commands, cli)


class _Facade(_types.ModuleType):
    """`import meshbone` gives one namespace over every module: reading a name finds it in the
    module that defines it, assigning one replaces it *there* - so a test can swap `host.run`
    or `store.DIR` the way it would on a single file."""

    def __getattr__(self, name):
        for mod in MODULES:
            if name in vars(mod):
                return getattr(mod, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        for mod in MODULES:
            if name in vars(mod):
                setattr(mod, name, value)
                return
        _types.ModuleType.__setattr__(self, name, value)


_sys.modules[__name__].__class__ = _Facade
