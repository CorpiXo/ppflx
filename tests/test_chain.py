"""Unit tests for ppflx.chain hex encoding and ledger helpers.

No Ethereum node and no web3 package are required for these unit tests.
"""

from __future__ import annotations

import hashlib

import pytest

from ppflx.chain import Web3Chain, sha256_hex

# ── _to_bytes32 unit tests (no node, no web3) ────────────────────────────────


def test_to_bytes32_valid_digest():
    digest_hex = "0x" + "ab" * 32
    assert Web3Chain._to_bytes32(digest_hex) == bytes.fromhex("ab" * 32)


def test_to_bytes32_valid_digest_without_prefix():
    digest_hex = "cd" * 32
    assert Web3Chain._to_bytes32(digest_hex) == bytes.fromhex("cd" * 32)


def test_to_bytes32_leading_single_zero_nibble():
    # A digest starting with a single '0' hex digit (e.g. 0x0a...) must not
    # have that leading nibble stripped into an odd-length hex string.
    digest_hex = "0x0a" + "bc" * 31
    expected = bytes.fromhex("0a" + "bc" * 31)
    assert len(expected) == 32
    assert Web3Chain._to_bytes32(digest_hex) == expected


def test_to_bytes32_leading_zero_byte():
    # A digest starting with 0x00... must preserve the leading zero byte
    # rather than shifting left and zero-padding the end.
    digest_hex = "0x00" + "ef" * 31
    expected = b"\x00" + bytes.fromhex("ef" * 31)
    assert len(expected) == 32
    assert Web3Chain._to_bytes32(digest_hex) == expected


def test_to_bytes32_all_zeros():
    digest_hex = "0x" + "00" * 32
    assert Web3Chain._to_bytes32(digest_hex) == b"\x00" * 32


@pytest.mark.parametrize(
    "bad_hex",
    [
        "",
        "0x",
        "0x" + "ab" * 31,  # 31 bytes (too short)
        "0x" + "ab" * 33,  # 33 bytes (too long)
        "0x" + "a" * 63,  # odd length (63 hex chars)
        "0x" + "a" * 65,  # odd length (65 hex chars)
        "0x" + "zz" * 32,  # non-hex characters
        "0x" + "ab " * 32,  # embedded whitespace
    ],
)
def test_to_bytes32_rejects_wrong_length_or_invalid_hex(bad_hex):
    with pytest.raises(ValueError):
        Web3Chain._to_bytes32(bad_hex)


def test_sha256_hex_roundtrips_through_to_bytes32_for_leading_zero_digests():
    # Find real inputs whose SHA-256 starts with a single '0' nibble and '00' byte
    # to confirm sha256_hex -> _to_bytes32 never corrupts real digests.
    found_single_zero = False
    found_zero_byte = False
    for i in range(10000):
        raw = hashlib.sha256(f"client-{i}".encode()).digest()
        hex_digest = sha256_hex(f"client-{i}".encode())
        if raw[0] == 0x00:
            assert Web3Chain._to_bytes32(hex_digest) == raw
            found_zero_byte = True
        elif raw[0] < 0x10:
            assert Web3Chain._to_bytes32(hex_digest) == raw
            found_single_zero = True
        if found_single_zero and found_zero_byte:
            break
    assert found_single_zero and found_zero_byte


def test_send_tx_fails_closed_when_gas_estimation_fails():
    class _FailingFn:
        def estimate_gas(self, params):
            raise ValueError(
                "execution reverted: FLLedger: round proofs already anchored"
            )

    chain = Web3Chain.__new__(Web3Chain)
    chain._account = "0x" + "11" * 20
    chain._use_signer = False

    with pytest.raises(RuntimeError, match="Gas estimation failed"):
        chain._send_tx(_FailingFn())


def test_send_tx_applies_gas_margin_above_estimate():
    sent_params = {}

    class _FakeEth:
        def wait_for_transaction_receipt(self, tx_hash, timeout=60):
            return {"transactionHash": bytes.fromhex("ab" * 32), "status": 1}

    class _FakeW3:
        eth = _FakeEth()

    class _StubFn:
        def estimate_gas(self, params):
            return 2_000_000

        def transact(self, params):
            sent_params.update(params)
            return b"\xab" * 32

    chain = Web3Chain.__new__(Web3Chain)
    chain._account = "0x" + "11" * 20
    chain._use_signer = False
    chain._w3 = _FakeW3()

    tx_hash = chain._send_tx(_StubFn())
    assert tx_hash == "0x" + "ab" * 32
    assert sent_params["gas"] > 2_000_000
    assert sent_params["gas"] == int(2_000_000 * Web3Chain._GAS_ESTIMATE_MARGIN)

