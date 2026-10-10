"""Upgrade meshbone on a remote node over an ssh chain:  python3 push.py 'admin@jump.example.net;10.0.0.10'"""

import os, io, re, subprocess, sys, tarfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import meshbone as m

hops = m.parse_chain(sys.argv[1])
chain = [d for d, _ in hops]
with m.ssh_session(hops) as base:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(m.updates.program_file(), "meshbone.py")
    tmp = (
        subprocess.run(
            m.remote_argv(base, chain, 'umask 077 && d=$(mktemp -d) && tar -xf - -C "$d" && echo "$d"', False),
            input=buf.getvalue(),
            stdout=subprocess.PIPE,
            check=True,
        )
        .stdout.decode()
        .split()[-1]
    )
    assert re.fullmatch(r"/[\w./-]+", tmp)
    r = subprocess.run(
        m.remote_argv(
            base,
            chain,
            f"sudo python3 {tmp}/meshbone.py upgrade; rc=$?; rm -rf {tmp}; sudo meshbone sync && echo SYNC_OK; sudo meshbone status; exit $rc",
            False,
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    print(r.stdout.strip(), r.stderr.strip()[-400:], f"exit {r.returncode}", sep="\n")
