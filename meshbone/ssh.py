"""Logins to other machines: ssh chains with jump hosts and passwords, and the routers we configure (VyOS)."""

import contextlib, os, re, shlex, shutil, sys, tempfile

from . import store, system


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
