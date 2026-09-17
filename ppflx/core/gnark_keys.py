"""
Pinned Groth16 key manifest (docs/ZKP.md, section 7).

`gnark_service setup` (gnark-gradient-prover) writes `manifest.json` and the
verifying keys into a keys directory, and the proving keys into a proving-key
directory. Python never reads key material: it reads the manifest so the
server can pin which verifying key each proof must be checked under, and so
both sides agree on each circuit's fixed size.

The pinned keys packaged with this library have no proving keys outside the
machine that made them. To prove, make a local key set outside every
repository and point both variables at it:

    gnark_service setup --keys-dir ~/.cache/ppflx/keys --pk-dir ~/.cache/ppflx/pk
    export FL_ZKP_KEYS_DIR=~/.cache/ppflx/keys FL_ZKP_PK_DIR=~/.cache/ppflx/pk

Environment:
    FL_ZKP_KEYS_DIR  manifest and verifying keys (default: the pinned keys
                     packaged with this library)
    FL_ZKP_PK_DIR    proving keys for the prover role
                     (default: ~/.cache/ppflx/pk)
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict

NORM_CIRCUIT = "norm"
ELGAMAL_CIRCUIT = "elgamal"

KEYS_DIR_ENV = "FL_ZKP_KEYS_DIR"
PK_DIR_ENV = "FL_ZKP_PK_DIR"
# The manifest and verifying keys come from the environment, else the pinned
# keys shipped with this package, which are the trust anchor for deployments.
# The service itself is pointed at the same keys with --keys-dir.
PACKAGED_KEYS_DIR = Path(__file__).resolve().parent / "gnark_keys_data"
DEFAULT_PK_DIR = Path.home() / ".cache" / "ppflx" / "pk"
LOCAL_SETUP = (
    "gnark_service setup --keys-dir ~/.cache/ppflx/keys --pk-dir ~/.cache/ppflx/pk, then "
    f"export {KEYS_DIR_ENV}=~/.cache/ppflx/keys {PK_DIR_ENV}=~/.cache/ppflx/pk"
)

_cache: Dict[tuple, dict] = {}


def keys_dir() -> Path:
    """The pinned keys directory: FL_ZKP_KEYS_DIR, else the packaged keys."""
    from_env = os.environ.get(KEYS_DIR_ENV)
    return Path(from_env).expanduser() if from_env else PACKAGED_KEYS_DIR


def pk_dir() -> Path:
    """The proving-key directory: FL_ZKP_PK_DIR, else ~/.cache/ppflx/pk."""
    from_env = os.environ.get(PK_DIR_ENV)
    return Path(from_env).expanduser() if from_env else DEFAULT_PK_DIR


def load_manifest() -> dict:
    """Parsed manifest plus its SHA-256. Raises if keys were never set up."""
    path = keys_dir() / "manifest.json"
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"No ZKP key manifest at {path}. Point {KEYS_DIR_ENV} at the keys directory the proof "
            f"service was started with. For a local key set outside the repositories: {LOCAL_SETUP}"
        ) from exc
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _cache:
        raw = path.read_bytes()
        manifest = json.loads(raw)
        by_circuit = {}
        for entry in manifest.get("circuits", []):
            if entry["circuit"] in by_circuit:
                raise ValueError(f"{path}: circuit {entry['circuit']!r} listed more than once")
            by_circuit[entry["circuit"]] = entry
        for circuit in (NORM_CIRCUIT, ELGAMAL_CIRCUIT):
            if circuit not in by_circuit:
                raise ValueError(f"{path}: no entry for circuit {circuit!r}")
        _cache.clear()
        _cache[key] = {"sha256": hashlib.sha256(raw).hexdigest(), "circuits": by_circuit, "raw": manifest}
    return _cache[key]


def manifest_sha256() -> str:
    return load_manifest()["sha256"]


def circuit_size(circuit: str) -> int:
    """Fixed number of values one proof of this circuit covers."""
    return int(load_manifest()["circuits"][circuit]["n"])


def pinned_vk_sha256(circuit: str) -> str:
    """SHA-256 of the verifying key every proof of this circuit must be checked under."""
    return load_manifest()["circuits"][circuit]["vk_sha256"]


def missing_proving_keys() -> list:
    """Proving-key files named in the manifest that are absent from the local cache."""
    return [
        entry["pk_file"]
        for entry in load_manifest()["circuits"].values()
        if not (pk_dir() / entry["pk_file"]).exists()
    ]
