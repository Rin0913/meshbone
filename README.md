# meshbone

A WireGuard mesh backbone without a controller, in one Python file.

Every node keeps a full, signed copy of the mesh directory and computes its own
WireGuard configuration from it. There is no coordination server to run, no
routing daemon, and a public node needs exactly one forwarded UDP port.

```
           hub A  ─────────  hub B          hubs: public endpoint, relay traffic
          ╱  │  ╲           ╱  │
   laptop   phone  home-gw ─╯  server      clients: behind NAT, linked to every hub
                      │
                 192.168.50.0/24            subnets: announced by any node as gateway
```

## Concepts

| Role | What it is |
|---|---|
| **hub** | A node other nodes can dial (`HOST:PORT`). Hubs link to every node and relay between them. A hub holds no authority over the mesh. |
| **client** | A node behind NAT. It stays linked to every hub, sends through the one with the best ping, and moves to another within seconds if that hub dies. |
| **simple client** | A phone or any device that only runs plain WireGuard. It gets a standard config (file or QR code) and uses a single hub. |
| **admin** | Whoever has the admin key. Every directory entry is signed with it, directly on a node that stores `admin.key`, or through a short-lived token made in the browser. |
| **subnet** | A network behind a node, announced into the mesh. |
| **cluster IP** | An address held by several nodes at once (anycast). Every hub holds two: the mesh map and the metrics endpoint. |

Addresses come from the mesh range (default `10.253.254.0/23`: the first /24 for
hubs, the rest for clients) and cluster IPs from `10.253.253.0/24`.

## Requirements

- Linux with systemd and WireGuard in the kernel (5.6 or newer)
- Python 3.9 or newer (tested on 3.11 and 3.13)
- `wireguard-tools` and `python3-cryptography` (installed automatically with apt or dnf)
- `qrencode`, only on admin nodes and only for QR codes

## Quick start

Create the mesh on a machine you trust. It does not have to be public; keeping
the admin key off exposed hosts is the point.

```bash
sudo python3 meshbone.py create --name laptop
```

Add a hub. `deploy` invites the node, copies the script over ssh, installs it
and joins it, through any number of jump hosts:

```bash
sudo meshbone deploy vps1 --remote root@203.0.113.9 --endpoint vps1.example.net:51820
sudo meshbone deploy home --remote 'me@jump.example.net;10.0.0.10' --endpoint home.example.net:51533
```

Add clients, either the same way without `--endpoint`, or by carrying a config
file to the machine yourself:

```bash
sudo meshbone invite nas --subnet 192.168.50.0/24      # writes nas.mesh.json
sudo python3 meshbone.py join nas.mesh.json            # on the new machine
```

Add a phone:

```bash
sudo meshbone simple phone --qr
```

Then look at the mesh from any node: `http://10.253.253.1:7948/`.

## Commands

On any machine:

| Command | Effect |
|---|---|
| `install` | Install packages and `/usr/local/sbin/meshbone`, nothing else |
| `create [--endpoint HOST:PORT] [--name N] [--mesh NAME] [--net CIDR] [--cluster-net CIDR]` | Start a mesh; this machine becomes its first node and first admin |
| `join FILE [--once]` | Join with a config written by `invite`; `--once` keeps everything in `/run` |
| `local [--listen-port N] [--mtu N]` | This machine's own network settings |
| `promote --endpoint HOST:PORT` | Ask to become a hub |
| `cost NAME MS` | Local penalty for sending through hub NAME |
| `status`, `leave`, `upgrade` | |

On an admin node:

| Command | Effect |
|---|---|
| `invite NAME [options]` | Add a node and write its config file |
| `deploy NAME --remote CHAIN [options]` | Invite, install and join over ssh |
| `simple NAME [--hub HUB] [--qr]` | Add a plain-WireGuard device, or export its config again |
| `set NAME [options]` | Change a node |
| `approve NAME`, `revoke NAME` | Accept a `promote` request; remove a node |
| `dns [--zone DOMAIN] [--upstream 'IP IP']` | The mesh's names, see below |
| `policy [--default allow\|deny] [--add FROM TO allow\|deny [--ports P] [--at N]] [--del N] [--clear]` | The firewall, see below |
| `passwd` | Change the management page password |
| `update URL [--ref REF]`, `update --file PATH`, `update --rollback` | Roll out a new version of meshbone itself, see below |

Node options: `--endpoint HOST:PORT`, `--subnet CIDR`, `--vip IP`, `--cost MS`,
`--desc TEXT`, `--label L`, `--dns NAME`, `--ip ADDRESS`, `--admin`.

A node with an endpoint is a hub. Giving a client an endpoint makes it a hub
once another client has actually reached it there; otherwise the endpoint is
taken away again (`--no-verify` skips the test). A mesh always keeps at least
one hub.

`--remote` is `USER[:PASSWORD]@HOST[;USER[:PASSWORD]@HOST]...`. Each hop is
reached through the one before it. Without passwords, each hop may also log in
to the next with its own keys.

## Web pages and API

Served on port 7948, reachable only from inside the mesh.

| Where | What |
|---|---|
| `http://10.253.253.1:7948/` on every hub | Mesh map, node and link tables |
| `/traffic` | Per-link traffic graphs with a time range |
| `/api/nodes`, `/api/topology`, `/api/traffic`, `/api/policy`, `/api/dns` | Read-only JSON; `/api/nodes` filters by `label`, `role`, `name` |
| `http://10.253.253.2:7948/metrics` on every hub | Prometheus text format |
| `http://10.253.253.1:7948/admin` | Management page, on every node (see below) |

Traffic is counted per link by the hub at one end. Traffic between two clients
shows up on both of their links to the hub that relayed it; there is no
per-pair matrix.

## Managing from any node

Changes to the mesh are signed. There are two ways to be allowed to sign:

- **A node that holds `admin.key`** signs directly. Its management page asks for
  the page password; its command line just works.
- **Any other node**, hubs included, shows a sign-in page that asks for the admin
  key itself. The key stays in the browser: the page uses it once to sign a
  token for a session key that exists only on that node, valid for the minutes
  you choose (at most 12 hours), from your address only. The node then signs
  your changes with the session key, and every node accepts them because the
  token carries the admin key's signature. Nothing but the token is sent.

So the management page works through the cluster IP on whichever hub answers,
no machine has to stay up for the mesh to be manageable, and the admin key can
live in a password manager instead of on a server. On a terminal, admin
commands on a node without `admin.key` ask for the key instead.

What a token session cannot do: show a simple client's config a second time
(the device key is only kept where `admin.key` is), hand out `--admin`, or
change the page password.

A node that is already compromised when you sign in can serve a page that
steals the key. The token protects against everything else: someone listening
on the way, and a node compromised later.

## Gateways

A node that announces a network becomes a gateway for it without further
setup: IP forwarding is switched on, forwarding through the mesh interface is
allowed where the host filters it, and traffic from the mesh into the
announced network is masqueraded behind the node's own address there. The
hosts in that network therefore need no route to the mesh. If their router
does have one and you want them to see the real source addresses, turn the
masquerade off on the gateway with `meshbone local --nat off`.

## DNS

Every hub runs a resolver on the third cluster IP (`10.253.253.3` by default,
also `dns.<zone>`), written in the script itself. It answers the mesh's zone
from the directory and forwards everything else to the upstream resolvers.

| Name | Resolves to |
|---|---|
| `<node>.<zone>` | the node's mesh address |
| a node's own `--dns` names (bare: under the zone; dotted: as written) | the node |
| `<label>.<zone>`, for labels that are valid host names | every node carrying the label |
| `map.<zone>`, `metrics.<zone>`, `dns.<zone>` | the hubs' service addresses |
| reverse names of mesh addresses | the node's name |

The zone defaults to `<mesh>.internal`; `meshbone dns --zone home.example
--upstream '9.9.9.9 1.1.1.1'` changes it for the whole mesh. Simple clients
get the resolver and the zone in their config. On a full node,
`meshbone local --resolver on` points systemd-resolved at it for the zone only.

## Firewall

A policy says who may open connections to whom across the mesh. Groups are
labels, so regrouping a node is a matter of changing its labels.

```bash
sudo meshbone policy --add subnets nodes deny                    # the mesh reaches into subnets, not the other way
sudo meshbone policy --add ops servers allow --ports 'tcp/22,443'
sudo meshbone policy --default deny                              # anything no rule matches
sudo meshbone policy                                             # show it
```

| Group | Stands for |
|---|---|
| a label, e.g. `ops` | the addresses of the nodes carrying it |
| `@name` | one node |
| `nodes`, `hubs`, `clients` | all nodes, the hubs, the clients |
| `subnets` | every network announced behind a node |
| `LABEL+net`, `@name+net` | the networks behind those nodes instead of the nodes |
| `any`, `10.1.1.0/24` | everything; a literal address or network |

Rules are tried from the top and the first match decides. The policy is signed
like the rest of the directory, and every node compiles it into the same
nftables table (its own table, next to whatever firewall the host already
has). It is enforced on the node a connection is for, on the hub that relays
it, and on the gateway of a subnet - so it also covers simple clients.

Always allowed: answers to permitted connections, ping, and the mesh's own two
ports between nodes. A policy therefore cannot lock you out of the management
page.

## Deploying over ssh

`deploy` logs in to the target and has three ways to prove itself:

- a password in the destination: `user:password@host`;
- a private key for that one login: `--identity FILE`, or pasted into the page;
- otherwise the identity of whoever is asking: at a terminal under `sudo`, your
  own ssh (agent, keys, config). From the management page, the deploy key of the
  node serving the page; the page shows its public line, to be added to the
  target's `~/.ssh/authorized_keys`.

## Updating

```bash
sudo meshbone update https://github.com/OWNER/REPO --ref v1.2    # or from the management page
```

1. The admin node fetches `meshbone.py` at that branch, tag or commit.
2. The new version must pass its own dry run (`check`) against the node's real
   state and Python. Then it is installed, and the node must still be in touch
   with the mesh afterwards. If not, the previous version is put back and
   nothing is published.
3. Only then is the version's checksum signed with the admin key. Every node
   fetches the file from its peers, verifies it against the signed checksum and
   goes through the same steps on its own.
4. A node where it fails keeps its old version, does not retry that version,
   and reports why. The management page shows what each node runs.

Every step is appended to `/etc/meshbone/audit.log` on the node it happened
on. `update --rollback` publishes the version the admin node ran before.

Pin `--ref` to a tag or commit you have reviewed: whatever is at that URL will
run as root on every node.

## How it works

- **Directory.** A last-writer-wins map of node entries, each signed with the
  admin key. Nodes exchange their full copy with every hub every 15 seconds, and
  a hub that learns something new pushes it to everyone at once.
- **Routing.** Each node has one WireGuard interface, `mb0`. A hub gives every
  prefix to the peer that owns it. A client keeps each hub's own prefixes on
  that hub and sends the rest through its primary hub, chosen by ping. Because
  WireGuard drops packets whose source is outside a peer's allowed IPs, the same
  table is the anti-spoofing filter.
- **Keys.** Each link has its own preshared key, derived from the mesh secret
  and the two nodes' key exchange, so a third node cannot compute it.
- **Boot.** A systemd timer reconciles the interface, routes, firewall rules
  and sockets with the directory. Everything is idempotent.

## Security model

All devices are assumed to belong to one owner, but one compromised node must
not take the mesh down.

| Compromised | Cannot | Can |
|---|---|---|
| client | change the directory, use another node's addresses | reach services other nodes expose on the mesh |
| hub | change the directory, add or revoke nodes, read other nodes' keys | read or drop the traffic it relays, until it is revoked |
| admin node | | everything |

WireGuard encrypts hop by hop, so a hub sees relayed traffic in clear. Use TLS
or SSH for anything sensitive. That includes the management page: its password
travels in clear through whichever hub relays it, so open it from the admin
node itself when you can. The mesh is a flat network: restrict what each
node exposes on `mb0` with its own firewall.

## Limitations

- Traffic crosses one hub. Two clients behind NAT never connect directly.
- A simple client uses one hub and a static config. Export it again after
  adding hubs or subnets.
- IPv4 only inside the mesh.
- All nodes follow a published version at once; there is no staged rollout beyond "the admin node first".
- `deploy` accepts host keys it has not seen before.

## Code layout

`meshbone.py` stays a single file because `deploy` and `update` ship exactly
one file to a node. Inside, it is laid out as model, view, controller:

| Layer | Holds |
|---|---|
| **Model** | The signed directory, what nodes report, traffic history, versions, and the rules over them. A second part wraps the machine: WireGuard, routes, firewall, systemd, ssh. |
| **View** | `view_*` functions and page assets. They format the data they are given and read or change nothing. |
| **Controller** | `cmd_*` for the command line, `respond` for HTTP, `handle` and `gossip` for other nodes. They change the model, then pick a view. |

## Development

```bash
python3 tests/test_meshbone.py --units    # multi-node logic test with ip, wg, systemctl and ssh stubbed
python3 tools/preview.py OUTDIR           # render the map and traffic pages with a made-up mesh
python3 tools/push.py 'me@jump;10.0.0.10' # upgrade a remote node
black . && pyflakes3 meshbone.py
```

Node ids are random, so run the test several times. Nodes may run older Python
than your workstation: avoid syntax newer than 3.9.

## License

MIT, see [LICENSE](LICENSE).
