# ppflx

Privacy-preserving federated learning on [Flower](https://flower.ai): each
privacy mechanism is a plugin, so a run combines homomorphic encryption,
zero-knowledge proofs of bounded model updates, and differential privacy
without the training code knowing which is in use.

Proofs are produced and checked by
[gnark-gradient-prover](https://github.com/CorpiXo/gnark-gradient-prover);
benchmarks across datasets and modes live in
[ppflx-bench](https://github.com/CorpiXo/ppflx-bench).

## What the modes guarantee

| Mode | Confidentiality | Integrity | Membership privacy |
|---|---|---|---|
| `baseline` | — | — | — |
| `he_tenseal`, `he_concrete_tfhe` | server sees only ciphertexts | — | — |
| `zkp` | — | update bound to the downloaded model, norm bounded | — |
| `he_elgamal_zkp`, `he_elgamal_zkp_sampled` | additively homomorphic ciphertexts | **proof bound to the aggregated ciphertext** | — |
| `he_*_zkp` (CKKS/TFHE composites) | server sees only ciphertexts | none — the proof is not bound to the ciphertext | — |
| `dp` | — | — | (ε, δ)-DP on the published model |
| `he_*_zkp_dp` | server sees only ciphertexts | none | (ε, δ)-DP |

`docs/ZKP.md` documents the protocols, the update bound, the circuits and the
limitations in full. Read [SECURITY.md](SECURITY.md) before relying on any of
these properties.

## Install

```bash
pip install ppflx                 # core: Flower, TenSEAL, torch
pip install "ppflx[tfhe]"         # adds Concrete-ML — see the licence note below
```

Python 3.12 (Concrete-ML requires < 3.13; Flower 1.36 requires > 3.11).

## Use

```python
from ppflx import FLConfig, get_privacy_mode
from ppflx.server import make_strategy
from ppflx.client import make_client

config = FLConfig(dataset="healthcare", privacy_mode="zkp", num_rounds=3)
mode = get_privacy_mode(config.privacy_mode)

strategy = make_strategy(config, mode, testloader)      # in a Flower ServerApp
client = make_client("0", trainloaders, valloaders, mode, config)  # in a ClientApp
```

`ppflx_bench` shows a complete ServerApp and ClientApp built on these.

Key generation:

```bash
python -m ppflx.keys generate he_tenseal
python -m ppflx.keys generate dp --output keys/dp/dp_params.json
```

## Proof service

ZKP modes talk to the prover and verifier over HTTP:

```bash
export FL_ZKP_PROVER_URL=http://127.0.0.1:9000     # clients prove here
export FL_ZKP_VERIFIER_URL=http://127.0.0.1:9001   # the server verifies here
```

The verifying keys and manifest this library pins ship in
`ppflx/core/gnark_keys_data/`; a proof made under any other key is rejected.
Point `FL_ZKP_KEYS_DIR` elsewhere to pin different keys.

## Tests

```bash
pytest tests
```

Tests that need proofs run against a built proof service; set
`FL_GNARK_BINARY` to its binary, or they skip.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 CorpiXo.

Concrete-ML (the `tfhe` extra) is BSD-3-Clause-Clear, which grants no patent
rights; Zama requires a commercial patent licence for commercial use. See
[NOTICE](NOTICE).
