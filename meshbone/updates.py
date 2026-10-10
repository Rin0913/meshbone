"""Software updates: fetching a version, proving it on this node, rolling back, following the published release."""

import fcntl, io, json, os, re, shutil, socket, sys, tarfile, tempfile, time, urllib.parse, urllib.request

from . import settings, store, system, wire


def build_archive(package):
    """The program as one runnable file -> bytes: a zip of the package with a shebang, built the
    same way every time (fixed timestamps, sorted entries) so that one source gives one checksum."""
    import zipfile

    buf = io.BytesIO()
    buf.write(b"#!/usr/bin/env python3\n")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in sorted(os.walk(package)):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                inside = os.path.join("meshbone", os.path.relpath(path, package))
                info = zipfile.ZipInfo(inside, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
                with open(path, "rb") as f:
                    z.writestr(info, f.read())
        info = zipfile.ZipInfo("__main__.py", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
        z.writestr(info, "from meshbone.cli import main\n\nmain()\n")
    return buf.getvalue()


def program_file():
    """The one file that *is* this program: the archive it runs from, or - running from a source
    tree - an archive built from it just now. What deploy ships and `update --file` installs."""
    if settings.archive():
        return settings.archive()
    built = os.path.join(tempfile.gettempdir(), f"meshbone-{os.getpid()}.pyz")
    with open(os.open(built, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700), "wb") as f:
        f.write(build_archive(settings.package_dir()))
    return built


def fetch_source(url, ref):
    """A version of the program -> (archive bytes, where exactly it came from).

    From a GitHub repository (https://github.com/OWNER/REPO, at a branch, tag or commit) the
    source tree is downloaded and built into the archive here; a direct https link must point
    at a ready archive (meshbone.pyz).
    """
    m = re.fullmatch(r"https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?", url)
    if m:
        url = f"https://github.com/{m[1]}/{m[2]}/archive/{urllib.parse.quote(ref or 'main', safe='')}.tar.gz"
    elif not url.startswith("https://"):
        sys.exit("the source must be https://github.com/OWNER/REPO or a direct https:// link to meshbone.pyz")
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read(64 << 20)
    except (OSError, ValueError) as e:
        sys.exit(f"cannot fetch {url}: {e}")
    if not m:
        return data, url
    with tempfile.TemporaryDirectory() as tmp:
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                tar.extractall(tmp, filter="data")
        except (tarfile.TarError, OSError, TypeError) as e:
            sys.exit(f"{url} is not a source tree: {e}")
        trees = [
            os.path.join(tmp, d, "meshbone") for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, d, "meshbone"))
        ]
        if not trees:
            sys.exit(f"{url} holds no meshbone package")
        return build_archive(trees[0]), url


def apply_release(sha):
    """Install a version on this node -> (ok, why not).

    The new version first has to pass its own dry run against this node's real
    state. Then it is installed, and if the node is worse off afterwards - the
    upgrade fails, or the node was in touch with the mesh before and is not any
    more - the version it ran before is put back. Either way the log says so.
    """
    path, node = store.release_path(sha), socket.gethostname()
    with open(f"{settings.DIR}/update.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = store.code_sha()
        if store.code_sha(path) != sha:
            return False, "the file does not match the checksum of the release"
        ok, said = system.script(path, "check")
        if not ok:
            store.audit("rejected", node=node, sha=sha, why="dry run failed: " + said)
            store.write(
                f"{settings.DIR}/update.json",
                json.dumps({"sha": sha, "ok": False, "why": "dry run failed: " + said[-200:], "was": old}),
            )
            return False, "dry run failed: " + said
        os.makedirs(f"{settings.DIR}/releases", mode=0o700, exist_ok=True)
        if old and not os.path.exists(store.release_path(old)):
            shutil.copy(settings.BIN, store.release_path(old))  # the way back, and what other nodes may ask us for
        was_fine = system.reachable()
        ok, said = system.script(path, "upgrade")
        if ok:
            time.sleep(settings.UPDATE_SETTLE)
            ok, said = system.script(settings.BIN, "sync")
        if ok and was_fine and not system.script(settings.BIN, "health")[0]:
            ok, said = False, "the node lost touch with the mesh after the upgrade"
        if not ok:
            restored = bool(old) and system.script(store.release_path(old), "upgrade")[0]
            store.audit("rolled-back", node=node, sha=sha, back_to=old, restored=restored, why=said)
            store.write(
                f"{settings.DIR}/update.json", json.dumps({"sha": sha, "ok": False, "why": said[-200:], "was": old})
            )
            return False, said
        store.audit("updated", node=node, sha=sha, was=old)
        store.write(f"{settings.DIR}/update.json", json.dumps({"sha": sha, "ok": True, "why": "", "was": old}))
        return True, ""


def update_busy():
    """Is an update being applied on this node right now? (The sync that apply_release runs to
    judge a fresh version must not start a second update - it would wait on the first forever.)"""
    try:
        with open(f"{settings.DIR}/update.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
    except OSError:
        return True


def maybe_update():
    """Follow the published release, once per version: a version that failed here is not retried."""
    r = store.release()
    if (
        not r
        or r["sha"] == store.code_sha()
        or store.read_json("update.json", {}).get("sha") == r["sha"]
        or update_busy()
    ):
        return
    if os.path.exists(store.release_path(r["sha"])):  # otherwise gossip is still fetching it
        apply_release(r["sha"])
        with store.locked():
            system.reconcile()  # tell the mesh how it went
        wire.gossip()
