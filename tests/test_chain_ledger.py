"""Hash encoding of the web3 audit ledger.

A SHA-256 digest starts with a zero digit one time in sixteen. The ledger must
record every digest unchanged, whatever its leading digits, and refuse anything
that is not one: a hash the chain stores differently from the one the run
recorded is worse than no record.
"""

import pytest

from ppflx.chain import Web3Chain, sha256_hex

# Digests whose leading digits the old prefix stripping consumed.
LEADING_ZERO = "0x0" + "ab" * 31 + "c"
LEADING_ZEROS = "0x00" + "cd" * 31
LEADING_X_LIKE = "0x" + "00" * 31 + "01"


@pytest.mark.parametrize("digest", [LEADING_ZERO, LEADING_ZEROS, LEADING_X_LIKE, sha256_hex(b"ppflx")])
def test_digest_round_trips_to_its_own_32_bytes(digest):
    assert Web3Chain._to_bytes32(digest) == bytes.fromhex(digest[2:])


def test_every_leading_digit_round_trips():
    for i in range(4096):
        digest = sha256_hex(str(i).encode())
        assert Web3Chain._to_bytes32(digest).hex() == digest[2:]


@pytest.mark.parametrize(
    "bad",
    [
        "0x" + "ab" * 31,  # 31 bytes: was zero-padded
        "0x" + "ab" * 33,  # 33 bytes: was truncated
        "0x" + "a" * 63,  # odd length
        "0xzz" + "00" * 31,  # not hex
    ],
)
def test_anything_but_a_32_byte_digest_is_refused(bad):
    with pytest.raises(ValueError):
        Web3Chain._to_bytes32(bad)


class _Contract:
    """Records the arguments each contract function is called with."""

    def __init__(self):
        self.calls = []
        self.functions = self

    def commitModel(self, *args):
        self.calls.append(("commitModel", args))
        return args

    def anchorProofs(self, *args):
        self.calls.append(("anchorProofs", args))
        return args


def _chain():
    chain = Web3Chain.__new__(Web3Chain)
    chain._contract = _Contract()
    chain._ledger = []
    chain._send_tx = lambda fn: "0x" + "11" * 32
    return chain


def test_commit_model_sends_the_digests_it_records():
    chain = _chain()

    chain.commit_model(round=1, model_hash=LEADING_ZERO, client_hashes=[LEADING_ZEROS, LEADING_X_LIKE])

    [(name, (rnd, model, clients))] = chain._contract.calls
    assert name == "commitModel" and rnd == 1
    assert model == bytes.fromhex(LEADING_ZERO[2:])
    assert clients == [bytes.fromhex(LEADING_ZEROS[2:]), bytes.fromhex(LEADING_X_LIKE[2:])]


def test_anchor_proofs_sends_unchanged_proof_and_client_id_hashes():
    # Find client ids whose SHA-256 starts with a zero digit, the case the old
    # stripping broke for client ids.
    cids = [c for c in (f"client-{i}" for i in range(200)) if sha256_hex(c.encode())[2] == "0"][:2]
    assert len(cids) == 2
    chain = _chain()

    chain.anchor_proofs(round=3, proof_hashes=[LEADING_ZERO, LEADING_ZEROS], client_ids=cids)

    [(name, (rnd, proofs, ids))] = chain._contract.calls
    assert name == "anchorProofs" and rnd == 3
    assert proofs == [bytes.fromhex(LEADING_ZERO[2:]), bytes.fromhex(LEADING_ZEROS[2:])]
    assert ids == [bytes.fromhex(sha256_hex(c.encode())[2:]) for c in cids]
