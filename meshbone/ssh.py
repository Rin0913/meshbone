"""Logins to other machines: ssh chains with jump hosts and passwords, and the routers we configure (VyOS)."""

import contextlib, hashlib, json, os, re, shlex, shutil, subprocess, sys, tempfile, time

from . import model, settings, store, system


def parse_chain(text):
    """'user:password@host;user@host2;host3' -> [(ssh destination, password or None)].
    The older 'user@host:user@host2' spelling (no passwords) still works."""
    text = re.sub(r"^ssh(://|:?\s+)", "", text.strip())  # "ssh user@host" and "ssh: user@host" mean the same
    legacy = ";" not in text and ("@" in text.split(":")[0] or "@" not in text)
    chain = []
    for part in text.split(":" if legacy else ";"):
        cred, _, host = part.strip().rpartition("@")
        user, _, password = cred.partition(":")
        dest = f"{user}@{host}" if user else host
        if not re.fullmatch(r"([\w.-]+@)?[\w.-]+", dest):
            sys.exit(
                "--remote is USER[:PASSWORD]@HOST[;USER[:PASSWORD]@HOST]... (ports and options belong in ssh_config)"
            )
        chain.append((dest, password or None))
    return chain


@contextlib.contextmanager
def ssh_session(hops, identity=None):
    """Yields the argv prefix for ssh, with the identity that fits who is asking:

    - a private key handed over for this one deploy, if there is one;
    - else, for a person at a terminal (sudo), their own ssh: agent, keys, config, known_hosts;
    - else - the management page, on whichever node serves it - that node's own deploy key.

    Passwords in the destination are answered by an askpass helper, so they never appear on a
    command line. Whatever is written for the session is removed when it ends.
    """
    person = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
    person = None if person == "root" else person
    front, ssh = (["sudo", "-u", person] if person else []), ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    known = dict(sorted(((d, p) for d, p in hops if p), key=lambda kv: -len(kv[0])))
    box = tempfile.mkdtemp(prefix="meshbone-ssh-")
    try:
        if identity:
            store.write(f"{box}/key", identity.replace("\r\n", "\n").strip() + "\n")
            ssh += ["-i", f"{box}/key", "-o", "IdentitiesOnly=yes"]
        elif not person and os.geteuid() == 0:
            ssh += ["-i", system.deploy_key()[0]]
        if known:
            store.write(
                f"{box}/askpass",
                "#!/usr/bin/env python3\nimport sys\nfor who, password in %r.items():\n"
                "    if who in sys.argv[1]:\n        print(password)\n        break\n" % known,
                0o700,
            )
            front += ["env", f"SSH_ASKPASS={box}/askpass", "SSH_ASKPASS_REQUIRE=force"]
            ssh += ["-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=publickey,password"]
        if person:
            for path in [box] + [os.path.join(box, name) for name in os.listdir(box)]:
                shutil.chown(path, person)
        yield front + ssh
    finally:
        shutil.rmtree(box, ignore_errors=True)


def remote_argv(base, chain, command, jump, tty=False):
    """argv that runs a shell command on the last host of an ssh chain.

    jump: every hop is authenticated from this machine (ssh -J). Otherwise each
    hop logs in to the next one with its own keys, the way one would by hand -
    which is what works when only the jump host is authorized on the inner one.
    """
    opts = ["-t"] if tty else []
    if jump:
        return [*base, *opts, "-J", ",".join(chain[:-1]), chain[-1], command]
    for hop in reversed(chain[1:]):
        command = shlex.join(["ssh", *opts, hop, command])
    return [*base, *opts, chain[0], command]


def router_run(opts, identity, command, stdin=None):
    """Run a command on a managed router over ssh -> its output. Raises on failure."""
    hops = parse_chain(opts["ssh"])
    with ssh_session(hops, identity) as base:
        argv = remote_argv(
            base + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"], [d for d, _ in hops], command, len(hops) > 1
        )
        r = subprocess.run(
            argv,
            input=(stdin or "").encode(),
            capture_output=True,
            timeout=120,
        )
        if r.returncode:
            raise OSError(
                (r.stderr or r.stdout).decode("utf-8", "replace").strip()[-300:] or f"ssh exit {r.returncode}"
            )
        return r.stdout.decode("utf-8", "replace")


def manage_routers():
    """On an admin node: keep every managed router configured, and report what it sees.

    The router's configuration is derived from the directory the same way a hub's own is;
    it is pushed when it changes (or hourly, in case somebody edited the router by hand),
    and its WireGuard handshakes stand in for the `sees` report a hub would send itself.
    """
    loc, nodes, nets = store.local(), store.load(), store.load_nets()
    mesh, alive = loc["mesh"], store.live(nodes)
    state_ = store.read_json("managed.json", {})
    changed = False
    for pk, opts in store.managed(mesh, nodes).items():
        n, st = alive[pk], state_.setdefault(pk, {})
        try:
            key = store.kept_key(n["id"])
            identity = store.managed_ssh_key()[0]
            sets = model.vyos_commands(mesh, nodes, pk, key, opts)
            digest = hashlib.sha256("\n".join(sets).encode()).hexdigest()
            if st.get("applied") != digest or time.time() - st.get("at", 0) > 3600:
                current = router_run(
                    opts, identity, "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands"
                )
                out = router_run(opts, identity, "vbash -s", model.vyos_script(model.vyos_deletes(current, opts), sets))
                if "MESHBONE-APPLIED" not in out:
                    raise OSError("the router refused the configuration: " + out.strip()[-300:])
                st.update(applied=digest, at=int(time.time()), error="")
                store.audit("router-configured", node=n["name"], peers=len(sets))
            shakes = router_run(opts, identity, f"sudo wg show {opts.get('wg', 'wg0')} latest-handshakes")
            now, sees = time.time(), []
            for line in shakes.splitlines():
                peer, _, ts = line.partition("\t")
                if ts.strip().isdigit() and int(ts) and now - int(ts) < settings.FRESH and peer in alive:
                    sees.append(alive[peer]["id"])
            report = {"nets": [], "wants": "", "sees": sorted(sees), "code": "managed"}
            if {k: v for k, v in nets.get(pk, {}).items() if k != "seq"} != report:
                nets[pk] = {**report, "seq": store.next_seq(nets.get(pk, {}).get("seq", 0))}
                changed = True
            st["error"] = ""
        except (OSError, KeyError, ValueError, subprocess.TimeoutExpired) as e:
            if st.get("error") != str(e)[:200]:
                settings.log(f"managed router {n['name']}: {e}")
            st["error"] = str(e)[:200]
    if changed:
        store.save_nets(nets)
    store.write(f"{settings.DIR}/managed.json", json.dumps(state_))
    return state_
