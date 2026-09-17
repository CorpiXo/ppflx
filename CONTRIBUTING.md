# Contributing

Thanks for your interest. This project implements cryptographic protocols, so
contributions are held to a stricter standard than the average Python library:
a claim about what a mode guarantees has to be backed by a test.

## Contributor Licence Agreement

Before a pull request can be merged you must sign the CLA, which the CLA
assistant will prompt for on your first pull request. It licenses your
contribution to CorpiXo, which holds copyright for the project, so the project
can be relicensed or dual-licensed in future without tracking down every
contributor. You keep the copyright in your own work.

## Development setup

Python 3.12 is required (Concrete-ML needs < 3.13, Flower 1.36 needs > 3.11).
The proof service is a separate repository,
[gnark-gradient-prover](https://github.com/CorpiXo/gnark-gradient-prover).

```bash
conda create -n ppflx python=3.12 -y && conda activate ppflx
pip install -e . pytest
# Proof service, built in its own checkout; the ZKP tests skip without it
(cd ../gnark-gradient-prover && go build -o gnark_service .)
export FL_GNARK_BINARY=$(realpath ../gnark-gradient-prover/gnark_service)
```

The tests make their own small keys in temporary directories. To run ZKP modes
outside the tests, make a local key set as described in
[docs/ZKP.md, section 7.1](docs/ZKP.md#71-setup).

## Before opening a pull request

1. `pytest tests` passes (the ZKP tests skip unless `FL_GNARK_BINARY` is set).
2. If you changed a privacy mode or the strategy, run the modes your change
   affects end to end from ppflx-bench and say so in the pull request:
   `python compare.py --dataset healthcare --modes <modes> --rounds 2 --num-clients 2`
3. New behaviour in a security-relevant path comes with a test that fails
   without your change.
4. `ppflx/core/gnark_keys_data/` changes only together with the pinned keys in
   gnark-gradient-prover, in the same set of pull requests.

## What the project expects of a change

- **Fail closed.** On error or ambiguity in a security-relevant path, abort;
  do not continue with a weaker guarantee.
- **Claims match tests.** Do not describe a property as verified unless a test
  exercises it. Prover and verifier timings are cost measurements, not
  soundness results.
- **Numbers come from raw results.** `results/**/comparison_report.json` is the
  source of truth for benchmark figures; documentation follows it, not the
  other way round.
- **No key material or datasets in commits.** Keys are generated locally;
  datasets are downloaded from their own sources.

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md).
