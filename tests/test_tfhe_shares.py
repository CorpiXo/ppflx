"""Concrete TFHE aggregation: values survive encryption at any number of
contributions, and the server role never loads the secret key.

Each upload is divided by num_clients before encryption so that the sum of
num_clients uploads fits the ring. A ciphertext records that share, and
decryption divides by the summed shares, so a single upload (the round-1 model
one client sends) and a partial aggregate decrypt to the right values instead
of 1/num_clients or k/num_clients of them.
"""

import numpy as np
import pytest

pytest.importorskip("concrete.fhe")

from ppflx.core.concrete_agg import ConcreteAggregationContext, ConcreteAggregator  # noqa: E402

N_CLIENTS = 3
SHAPE = (6,)
STEP = 10.0 / (2**14 - 1)  # one quantization step over the fixed range [-5, 5]


@pytest.fixture(scope="module")
def contexts(tmp_path_factory):
    keys = tmp_path_factory.mktemp("tfhe_keys")
    mp = pytest.MonkeyPatch()
    mp.setenv("FL_CONCRETE_TFHE_KEYS_DIR", str(keys))
    client = ConcreteAggregationContext(bit_width=14, num_clients=N_CLIENTS)
    client.private_key, _ = client.generate_keys()
    # A client compiles the circuit and writes the evaluation keys first, as in a run.
    client.encrypt_tensor(np.zeros(SHAPE, dtype=np.float32), client.private_key)
    server = ConcreteAggregationContext(bit_width=14, num_clients=N_CLIENTS, role="server")
    yield client, server
    mp.undo()


def _aggregate(server, uploads):
    agg = ConcreteAggregator(server, num_clients=len(uploads))
    for enc in uploads:
        agg.add_encrypted([enc])
    return agg.get_result()[0]


def test_single_upload_decrypts_to_itself(contexts):
    client, _ = contexts
    w = np.array([-0.2, -0.1, 0.0, 0.05, 0.1, 0.2], dtype=np.float32)
    back = client.decrypt_tensor(client.encrypt_tensor(w, client.private_key), client.private_key)
    # Dividing by num_clients before encryption costs up to num_clients steps.
    np.testing.assert_allclose(back, w, atol=(N_CLIENTS + 1) * STEP)


def test_full_and_partial_aggregates_decrypt_to_the_mean(contexts):
    client, server = contexts
    rng = np.random.default_rng(0)
    ws = [rng.uniform(-0.3, 0.3, SHAPE).astype(np.float32) for _ in range(N_CLIENTS)]
    uploads = [client.encrypt_tensor(w, client.private_key) for w in ws]
    for k in (N_CLIENTS, 2):
        back = client.decrypt_tensor(_aggregate(server, uploads[:k]), client.private_key)
        np.testing.assert_allclose(back, np.mean(ws[:k], axis=0), atol=(N_CLIENTS + 1) * STEP)


def test_more_than_num_clients_contributions_are_refused(contexts):
    client, server = contexts
    enc = client.encrypt_tensor(np.zeros(SHAPE, dtype=np.float32), client.private_key)
    with pytest.raises(ValueError, match="shares"):
        client.decrypt_tensor(_aggregate(server, [enc] * (N_CLIENTS + 1)), client.private_key)


def test_server_role_never_loads_the_secret_key(contexts, monkeypatch):
    client, _ = contexts
    server = ConcreteAggregationContext(bit_width=14, num_clients=N_CLIENTS, role="server")

    def secret_key_loaded(*args, **kwargs):
        raise AssertionError("the server loaded the secret key")

    monkeypatch.setattr(server, "_load_secret_keys_into_client", secret_key_loaded)
    uploads = [client.encrypt_tensor(np.full(SHAPE, 0.1, np.float32), client.private_key) for _ in range(2)]
    _aggregate(server, uploads)
    with pytest.raises(RuntimeError, match="secret key"):
        server.decrypt_tensor(uploads[0], None)
    with pytest.raises(RuntimeError, match="secret key"):
        server.encrypt_tensor(np.zeros(SHAPE, np.float32), None)


def test_server_role_does_not_compile(tmp_path, monkeypatch):
    monkeypatch.setenv("FL_CONCRETE_TFHE_KEYS_DIR", str(tmp_path))
    server = ConcreteAggregationContext(bit_width=14, num_clients=N_CLIENTS, role="server")
    with pytest.raises(RuntimeError, match="never compiles"):
        server._get_server(SHAPE)
