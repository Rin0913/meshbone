"""Build the program as one runnable file:  python3 tools/build.py [OUT]   (default dist/meshbone.pyz)"""

import hashlib, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from meshbone import settings, updates  # noqa: E402

out = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dist", "meshbone.pyz")
)
data = updates.build_archive(settings.package_dir())
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "wb") as f:
    f.write(data)
os.chmod(out, 0o755)
print(f"{out}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()[:12]}")
