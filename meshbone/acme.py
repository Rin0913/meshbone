"""A certificate for the HTTPS gateway from a public CA (Let's Encrypt by default) instead of the
mesh's own: ACME with the dns-01 challenge, the TXT records placed through the Cloudflare API, so
the names need not be reachable from the internet - a wildcard for the mesh's zone is asked for.
The account key and the API token are kept in the mesh's settings, encrypted under the admin key,
and an admin node renews the certificate by itself a month before it expires."""

import base64, hashlib, http.client, json, random, socket, struct, time, urllib.error, urllib.parse, urllib.request

from . import model, settings, store

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CLOUDFLARE = "https://api.cloudflare.com/client/v4"
RENEW_DAYS = 30  # renew when less than this is left
RETRY = 6 * 3600  # seconds between attempts after a failure


class AcmeError(Exception):
    pass


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def request(url, data=None, headers=None, method=None):
    """One request -> (status, headers, body); an HTTP error is an answer too, not an exception."""
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "meshbone", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        raise AcmeError(f"{url}: {e}")


def jwk(key):
    """The account key's public half as a JWK (EC P-256)."""
    nums = key.public_key().public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64(nums.x.to_bytes(32, "big")), "y": b64(nums.y.to_bytes(32, "big"))}


def thumbprint(key):
    return b64(hashlib.sha256(json.dumps(jwk(key), separators=(",", ":"), sort_keys=True).encode()).digest())


class Client:
    """An ACME account: signed requests to the CA's directory."""

    def __init__(self, directory, key, email=""):
        self.key, self.email, self.kid, self.nonce = key, email, None, None
        status, _, body = request(directory)
        if status != 200:
            raise AcmeError(f"directory {directory}: HTTP {status}")
        self.dir = json.loads(body)

    def fresh_nonce(self):
        status, headers, _ = request(self.dir["newNonce"], method="HEAD")
        self.nonce = headers.get("Replay-Nonce")
        if not self.nonce:
            raise AcmeError("the CA gave no nonce")
        return self.nonce

    def signed(self, url, payload):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        protected = {"alg": "ES256", "nonce": self.nonce or self.fresh_nonce(), "url": url}
        protected.update({"kid": self.kid} if self.kid else {"jwk": jwk(self.key)})
        p64 = b64(json.dumps(protected).encode())
        b = "" if payload is None else b64(json.dumps(payload).encode())  # None: POST-as-GET
        r, s = decode_dss_signature(self.key.sign(f"{p64}.{b}".encode(), ec.ECDSA(hashes.SHA256())))
        sig = b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return json.dumps({"protected": p64, "payload": b, "signature": sig}).encode()

    def post(self, url, payload=None, accept="application/json"):
        """A signed request -> (status, headers, parsed or raw body); a stale nonce is retried once."""
        for attempt in range(2):
            status, headers, body = request(
                url, self.signed(url, payload), {"Content-Type": "application/jose+json", "Accept": accept}
            )
            self.nonce = headers.get("Replay-Nonce")
            kind = headers.get("Content-Type", "")
            if "json" in kind:
                body = json.loads(body) if body else {}
                if status >= 400 and body.get("type", "").endswith(":badNonce") and attempt == 0:
                    self.fresh_nonce()
                    continue
            if status >= 400:
                detail = body.get("detail", body) if isinstance(body, dict) else body[:200]
                raise AcmeError(f"{url}: HTTP {status}: {detail}")
            return status, headers, body

    def register(self):
        contact = [f"mailto:{self.email}"] if self.email else []
        _, headers, _ = self.post(self.dir["newAccount"], {"termsOfServiceAgreed": True, "contact": contact})
        self.kid = headers.get("Location")
        if not self.kid:
            raise AcmeError("the CA gave no account URL")

    def wait(self, url, done=("valid",), failed=("invalid",), tries=30):
        """Poll an authorization or order until it settles."""
        for _ in range(tries):
            _, _, obj = self.post(url)
            if obj.get("status") in done:
                return obj
            if obj.get("status") in failed:
                err = next(
                    (c.get("error", {}) for c in obj.get("challenges", []) if "error" in c), obj.get("error", {})
                )
                raise AcmeError(f"{obj.get('status')}: {err.get('detail', err) if isinstance(err, dict) else err}")
            time.sleep(2)
        raise AcmeError(f"{url} did not settle in time")


def cloudflare(token, method, path, payload=None):
    status, _, body = request(
        CLOUDFLARE + path,
        json.dumps(payload).encode() if payload is not None else None,
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method,
    )
    try:
        reply = json.loads(body)
    except ValueError:
        reply = {}
    if status >= 400 or not reply.get("success"):
        errors = "; ".join(e.get("message", str(e)) for e in reply.get("errors", [])) or f"HTTP {status}"
        raise AcmeError(f"Cloudflare {method} {path}: {errors}")
    return reply["result"]


def cloudflare_zone(token, name):
    """The Cloudflare zone holding `name`: the longest suffix that is a zone of this account."""
    labels = name.split(".")
    for i in range(len(labels) - 1):
        found = cloudflare(token, "GET", "/zones?name=" + ".".join(labels[i:]))
        if found:
            return found[0]["id"]
    raise AcmeError(f"no Cloudflare zone of this token holds {name}")


def txt_visible(name, value, resolvers=("1.1.1.1", "8.8.8.8")):
    """Whether a TXT record with this value can already be looked up."""
    q = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", 16, 1)
    try:
        return value.encode() in model.dns_forward(list(resolvers), q)
    except (OSError, socket.error):
        return False


def obtain(cfg, names):
    """A certificate for `names` from the CA in `cfg` -> (chain PEM, key PEM). The TXT records
    are placed on Cloudflare for the challenge and removed afterwards."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    box = store.password_box()
    token = box.decrypt(cfg["token"].encode()).decode()
    key = ser.load_pem_private_key(box.decrypt(cfg["account_key"].encode()), None)
    client = Client(cfg["directory"], key, cfg.get("email", ""))
    client.register()
    _, headers, order = client.post(
        client.dir["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]}
    )
    order_url = headers.get("Location")
    placed = []  # (zone id, record id)
    try:
        pending = []
        for url in order["authorizations"]:
            _, _, authz = client.post(url)
            if authz.get("status") == "valid":
                continue
            chal = next((c for c in authz["challenges"] if c["type"] == "dns-01"), None)
            if not chal:
                raise AcmeError(f"{authz['identifier']['value']}: the CA offers no dns-01 challenge")
            host = "_acme-challenge." + authz["identifier"]["value"]
            value = b64(hashlib.sha256(f"{chal['token']}.{thumbprint(key)}".encode()).digest())
            zone = cloudflare_zone(token, authz["identifier"]["value"])
            rec = cloudflare(
                token, "POST", f"/zones/{zone}/dns_records", {"type": "TXT", "name": host, "content": value, "ttl": 60}
            )
            placed.append((zone, rec["id"]))
            pending.append((url, chal["url"], host, value))
        for url, chal_url, host, value in pending:
            for _ in range(45):  # give the record time to show; the CA asks the authoritative servers anyway
                if txt_visible(host, value):
                    break
                time.sleep(2)
            client.post(chal_url, {})
        for url, *_ in pending:
            client.wait(url)
        cert_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(cert_key, hashes.SHA256())
        )
        client.post(order["finalize"], {"csr": b64(csr.public_bytes(ser.Encoding.DER))})
        order = client.wait(order_url, done=("valid",), failed=("invalid",))
        _, _, chain = client.post(order["certificate"], accept="application/pem-certificate-chain")
        chain = chain.decode() if isinstance(chain, bytes) else chain
        key_pem = cert_key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()
        return chain, key_pem
    finally:
        for zone, rid in placed:
            try:
                cloudflare(token, "DELETE", f"/zones/{zone}/dns_records/{rid}")
            except AcmeError:
                pass


def wanted_names(mesh):
    """The zone and everything one label under it: the gateway's names all live there."""
    zone = store.dns_settings(mesh)["zone"]
    return [zone, f"*.{zone}"]


def fetch_cert(mesh):
    """The certificate the settings ask for -> (chain, key); on an admin node that holds admin.key.
    Network work: do it outside the lock."""
    cfg = store.acme_settings()
    if not cfg:
        raise AcmeError("no ACME account is set up (meshbone https --letsencrypt)")
    return obtain(cfg, wanted_names(mesh))


def renew(mesh):
    """Get the certificate and publish it to the mesh (the caller holds the lock, or does not care)."""
    chain, key_pem = fetch_cert(mesh)
    store.put_https_material(chain, key_pem)
    store.event("https", f"certificate renewed: {store.https_cert_info(mesh)}")


def days_left(mesh):
    from cryptography import x509
    import datetime

    pem = store.https_material(mesh)[0]
    if not pem:
        return 0
    cert = x509.load_pem_x509_certificate(pem.encode())
    until = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after  # < 42
    return (until.replace(tzinfo=None) - datetime.datetime.utcnow()).days


def maybe_renew():
    """From sync on an admin node: renew in time, and not more often than RETRY after a failure."""
    mesh = store.local()["mesh"]
    cfg = store.acme_settings()
    if not cfg or not store.has_admin_key() or days_left(mesh) > RENEW_DAYS:
        return
    st = store.read_json("state.json", {})
    if time.time() - st.get("acme_tried", 0) < RETRY:
        return
    store.write(
        f"{settings.DIR}/state.json", json.dumps({**store.read_json("state.json", {}), "acme_tried": time.time()})
    )
    try:
        chain, key_pem = fetch_cert(mesh)
        with store.locked():
            store.put_https_material(chain, key_pem)
        store.event("https", f"certificate renewed: {store.https_cert_info(mesh)}")
    except (AcmeError, OSError, ValueError, KeyError) as e:
        store.event("https", f"certificate renewal failed: {e}")
