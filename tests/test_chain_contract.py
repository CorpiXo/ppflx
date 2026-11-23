"""End-to-end FLLedger.sol + Web3Chain integration tests against a local Anvil node.

Skipped automatically unless ``web3``, ``anvil``, and ``solc`` (>=0.8.19) are
available.  Override binary discovery with ``FL_ANVIL_BINARY`` and
``FL_SOLC_BINARY`` (matching the ``FL_GNARK_BINARY`` pattern in conftest.py).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from ppflx.chain import Web3Chain, sha256_hex
from tests.conftest import _free_port

CONTRACT_PATH = (
    Path(__file__).resolve().parents[1] / "ppflx" / "chain_contract" / "FLLedger.sol"
)

# Default Anvil account #0 private key (well-known local dev key, test-only).
ANVIL_DEV_PRIVATE_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)


def _find_anvil() -> Path | None:
    if "FL_ANVIL_BINARY" in os.environ:
        val = os.environ["FL_ANVIL_BINARY"].strip()
        if not val:
            return None
        p = Path(val).expanduser()
        return p if p.is_file() else None
    found = shutil.which("anvil")
    if found:
        return Path(found)
    fallback = Path.home() / ".foundry" / "bin" / "anvil"
    return fallback if fallback.is_file() else None


def _find_solc() -> Path | None:
    if "FL_SOLC_BINARY" in os.environ:
        val = os.environ["FL_SOLC_BINARY"].strip()
        if not val:
            return None
        p = Path(val).expanduser()
        return p if p.is_file() else None
    found = shutil.which("solc")
    if found:
        return Path(found)
    # Check Foundry's svm cache for a compatible 0.8.x compiler (>= 0.8.19).
    svm_dirs = [
        Path.home() / "Library" / "Application Support" / "svm",
        Path.home() / ".svm",
    ]
    candidates: list[tuple[tuple[int, ...], Path]] = []
    for root in svm_dirs:
        if not root.is_dir():
            continue
        for ver_dir in root.iterdir():
            if not ver_dir.is_dir():
                continue
            parts = ver_dir.name.split(".")
            if len(parts) != 3 or not all(p.isdigit() for p in parts):
                continue
            ver = tuple(int(p) for p in parts)
            if ver < (0, 8, 19) or ver[0] != 0 or ver[1] != 8:
                continue
            binary = ver_dir / f"solc-{ver_dir.name}"
            if binary.is_file():
                candidates.append((ver, binary))
    if candidates:
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]
    return None


WEB3_AVAILABLE = importlib.util.find_spec("web3") is not None
ANVIL_BINARY = _find_anvil()
SOLC_BINARY = _find_solc()


def _missing_tools_reason() -> str:
    missing = []
    if not WEB3_AVAILABLE:
        missing.append("web3")
    if ANVIL_BINARY is None:
        missing.append("anvil")
    if SOLC_BINARY is None:
        missing.append("solc")
    return f"Contract tests require {', '.join(missing)}"


pytestmark = pytest.mark.skipif(
    not (WEB3_AVAILABLE and ANVIL_BINARY is not None and SOLC_BINARY is not None),
    reason=_missing_tools_reason(),
)


def _compile_contract() -> tuple[list[dict], str]:
    proc = subprocess.run(
        [str(SOLC_BINARY), "--combined-json", "abi,bin", str(CONTRACT_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"solc failed:\n{proc.stderr}"
    payload = json.loads(proc.stdout)
    contract_entry = next(
        v for k, v in payload["contracts"].items() if k.endswith(":FLLedger")
    )
    abi = contract_entry["abi"]
    if isinstance(abi, str):
        abi = json.loads(abi)
    bytecode = contract_entry["bin"]
    assert bytecode, "solc produced empty bytecode for FLLedger"
    return abi, bytecode


@pytest.fixture(scope="module")
def anvil_contract():
    from web3 import Web3

    abi, bytecode = _compile_contract()
    port = _free_port()
    rpc_url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [str(ANVIL_BINARY), "--host", "127.0.0.1", "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        for _ in range(100):
            if proc.poll() is not None:
                pytest.fail(f"anvil exited early: {proc.stderr.read()}")
            if w3.is_connected():
                break
            time.sleep(0.1)
        else:
            pytest.fail("anvil did not become reachable")

        deployer = w3.eth.accounts[0]
        factory = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = factory.constructor().transact({"from": deployer})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        assert receipt["status"] == 1
        contract_addr = receipt["contractAddress"]
        contract = w3.eth.contract(address=contract_addr, abi=abi)
        yield rpc_url, contract_addr, w3, contract
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _find_client_id_with_prefix(prefix_hex: str) -> str:
    for i in range(10000):
        cid = f"client-{i}"
        if hashlib.sha256(cid.encode()).hexdigest().startswith(prefix_hex):
            return cid
    raise AssertionError(f"Could not find client ID with SHA-256 prefix {prefix_hex}")


def test_commit_model_anchor_45_proofs_and_reject_duplicate_round(anvil_contract):
    rpc_url, contract_addr, w3, contract = anvil_contract
    chain = Web3Chain(rpc_url=rpc_url, contract_addr=contract_addr)

    # Include leading '0' nibble and leading '00' byte digests to verify no
    # hex corruption occurs end-to-end.
    model_hash = "0x0a" + "11" * 31
    client_hashes = [
        "0x00" + "22" * 31,
        "0x0f" + "33" * 31,
        "0xab" + "44" * 31,
    ]

    commit_tx = chain.commit_model(
        round=1,
        model_hash=model_hash,
        client_hashes=client_hashes,
        metadata={"mode": "he_elgamal_zkp"},
    )
    assert commit_tx.startswith("0x")
    assert contract.functions.getModelHash(1).call() == bytes.fromhex(model_hash[2:])
    assert contract.functions.getClientHashes(1).call() == [
        bytes.fromhex(h[2:]) for h in client_hashes
    ]
    assert contract.functions.getCommittedRounds().call() == [1]

    # Duplicate commitModel for round 1 must fail closed.
    with pytest.raises(RuntimeError, match="Gas estimation failed"):
        chain.commit_model(round=1, model_hash="0x" + "ff" * 32, client_hashes=[])
    assert contract.functions.getCommittedRounds().call() == [1]

    # Anchor 45 proofs (exceeds the old 500_000 gas limit; requires dynamic estimation).
    cid_zero_nibble = _find_client_id_with_prefix("0a")
    cid_zero_byte = _find_client_id_with_prefix("00")
    proof_hashes = [
        "0x00" + f"{0:062x}",
        "0x0a" + f"{1:062x}",
        *(sha256_hex(f"proof-{i}".encode()) for i in range(2, 45)),
    ]
    client_ids = [
        cid_zero_byte,
        cid_zero_nibble,
        *(f"client-{i}" for i in range(2, 45)),
    ]

    anchor_tx = chain.anchor_proofs(
        round=1,
        proof_hashes=proof_hashes,
        client_ids=client_ids,
    )
    assert anchor_tx.startswith("0x")
    receipt = w3.eth.get_transaction_receipt(anchor_tx)
    assert receipt["status"] == 1
    assert receipt["gasUsed"] > 500_000

    stored_proofs = contract.functions.getProofHashes(1).call()
    stored_cids = contract.functions.getProofClientIds(1).call()
    assert stored_proofs == [bytes.fromhex(h[2:]) for h in proof_hashes]
    assert stored_cids == [hashlib.sha256(cid.encode()).digest() for cid in client_ids]
    assert contract.functions.getAnchoredRounds().call() == [1]

    # Duplicate anchorProofs for round 1 must revert and leave state untouched.
    with pytest.raises(RuntimeError, match="Gas estimation failed"):
        chain.anchor_proofs(
            round=1,
            proof_hashes=["0x" + "ee" * 32],
            client_ids=["attacker"],
        )
    assert contract.functions.getProofHashes(1).call() == stored_proofs
    assert contract.functions.getAnchoredRounds().call() == [1]


def test_signed_transaction_path_with_private_key(anvil_contract):
    rpc_url, contract_addr, _, contract = anvil_contract
    chain = Web3Chain(
        rpc_url=rpc_url,
        private_key=ANVIL_DEV_PRIVATE_KEY,
        contract_addr=contract_addr,
    )

    model_hash = "0x00" + "cd" * 31
    proof_hash = "0x0b" + "ef" * 31
    chain.commit_model(round=2, model_hash=model_hash, client_hashes=[])
    chain.anchor_proofs(
        round=2,
        proof_hashes=[proof_hash],
        client_ids=["signed-client"],
    )

    assert contract.functions.getModelHash(2).call() == bytes.fromhex(model_hash[2:])
    assert contract.functions.getProofHashes(2).call() == [
        bytes.fromhex(proof_hash[2:])
    ]
    assert contract.functions.getAnchoredRounds().call() == [1, 2]
