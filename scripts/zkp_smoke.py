"""Prove and verify one model update with ppflx and a built proof service.

Checks, against whichever ppflx is importable (run with ``python -I`` from
outside the source tree to test an installed wheel):

1. The pinned verifying keys and manifest ship in the package and match the
   hashes the manifest records.
2. A prover and a separate verifier, started from ``FL_GNARK_BINARY`` under the
   local key set in ``FL_ZKP_KEYS_DIR`` / ``FL_ZKP_PK_DIR`` (docs/ZKP.md, 7.1),
   report the expected role and manifest.
3. A small update, with one layer larger than the norm circuit so it is
   chunked, is proved by the prover and verifies on the verifier, both with the
   values (``verify_gnark_proofs``) and from public inputs alone
   (``verify_gnark_proofs_light``).
4. The same proofs do not verify against a changed update.

Exits non-zero on any failure.
"""

import hashlib
import importlib.metadata
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import requests


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start(binary: Path, role: str, keys_dir: Path, manifest_sha256: str, pk_dir: Path = None):
    port = _free_port()
    cmd = [str(binary), "serve", "--role", role, "--keys-dir", str(keys_dir), "--port", str(port)]
    if pk_dir is not None:
        cmd += ["--pk-dir", str(pk_dir)]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    url = f"http://127.0.0.1:{port}"
    # Loading the full-size ElGamal proving key takes a while.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"{role} exited during startup: {proc.stderr.read()}")
        try:
            health = requests.get(f"{url}/health", timeout=2)
        except requests.RequestException:
            time.sleep(0.5)
            continue
        info = health.json() if health.ok else {}
        if info.get("role") != role or info.get("manifest_sha256") != manifest_sha256:
            proc.terminate()
            raise SystemExit(f"{url} is not a {role} under the expected manifest: {info}")
        return proc, url
    proc.terminate()
    raise SystemExit(f"{role} did not answer /health within 300 s")


def _check_packaged_keys(packaged_dir: Path) -> None:
    manifest_path = packaged_dir / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"packaged manifest missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["circuits"]:
        vk = packaged_dir / entry["vk_file"]
        if not vk.is_file():
            raise SystemExit(f"packaged verifying key missing: {vk}")
        digest = hashlib.sha256(vk.read_bytes()).hexdigest()
        if digest != entry["vk_sha256"]:
            raise SystemExit(f"{vk}: sha256 {digest} does not match the manifest's {entry['vk_sha256']}")
    print(f"packaged keys: {manifest_path} and {len(manifest['circuits'])} verifying keys match their hashes")


def main() -> None:
    for var in ("FL_GNARK_BINARY", "FL_ZKP_KEYS_DIR", "FL_ZKP_PK_DIR"):
        if not os.environ.get(var):
            raise SystemExit(f"{var} is not set")
    binary = Path(os.environ["FL_GNARK_BINARY"]).expanduser()
    keys_dir = Path(os.environ["FL_ZKP_KEYS_DIR"]).expanduser()
    pk_dir = Path(os.environ["FL_ZKP_PK_DIR"]).expanduser()

    import ppflx
    from ppflx.core import gnark_keys
    from ppflx.core.zkp_gnark import generate_gnark_proofs, verify_gnark_proofs, verify_gnark_proofs_light

    print(f"ppflx {importlib.metadata.version('ppflx')} from {Path(ppflx.__file__).parent}")
    _check_packaged_keys(gnark_keys.PACKAGED_KEYS_DIR)

    manifest_sha256 = gnark_keys.manifest_sha256()
    norm_n = gnark_keys.circuit_size(gnark_keys.NORM_CIRCUIT)
    prover, prover_url = _start(binary, "prover", keys_dir, manifest_sha256, pk_dir)
    verifier, verifier_url = _start(binary, "verifier", keys_dir, manifest_sha256)
    try:
        rng = np.random.default_rng(0)
        state = {
            "fc.weight": rng.normal(0.0, 0.05, size=(norm_n // 16 + 4, 16)).astype(np.float32),
            "fc.bias": rng.normal(0.0, 0.05, size=(16,)).astype(np.float32),
        }
        assert state["fc.weight"].size > norm_n, "the weight layer must be chunked"

        proofs, proof_bytes = generate_gnark_proofs(state, service_url=prover_url)
        names, values = list(state), list(state.values())
        ok, failures = verify_gnark_proofs(values, names, proofs, service_url=verifier_url)
        if not ok:
            raise SystemExit(f"proofs did not verify: {failures}")
        ok, failures = verify_gnark_proofs_light(proofs, service_url=verifier_url)
        if not ok:
            raise SystemExit(f"proofs did not verify from public inputs: {failures}")

        changed = [v.copy() for v in values]
        changed[0].flat[0] += 0.5
        ok, failures = verify_gnark_proofs(changed, names, proofs, service_url=verifier_url)
        if ok:
            raise SystemExit("proofs verified against a changed update")

        print(
            f"ZKP smoke test passed: {len(proofs)} proofs ({proof_bytes} bytes) from the prover "
            f"verified on the separate verifier; a changed update was rejected ({failures})"
        )
    finally:
        for proc in (prover, verifier):
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
