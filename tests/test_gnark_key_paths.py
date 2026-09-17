"""Where the ZKP keys and the proof service binary are looked up."""

from pathlib import Path

import pytest

from ppflx.core import gnark_keys
from ppflx.keys import he_elgamal


def test_keys_dir_is_the_environment_else_the_packaged_pinned_keys(monkeypatch, tmp_path):
    monkeypatch.delenv(gnark_keys.KEYS_DIR_ENV, raising=False)
    assert gnark_keys.keys_dir() == gnark_keys.PACKAGED_KEYS_DIR
    assert (gnark_keys.PACKAGED_KEYS_DIR / "manifest.json").is_file()

    monkeypatch.setenv(gnark_keys.KEYS_DIR_ENV, str(tmp_path))
    assert gnark_keys.keys_dir() == tmp_path


def test_keys_dir_from_the_environment_never_falls_back_to_the_packaged_keys(monkeypatch, tmp_path):
    empty = tmp_path / "keys"
    monkeypatch.setenv(gnark_keys.KEYS_DIR_ENV, str(empty))
    assert gnark_keys.keys_dir() == empty
    with pytest.raises(FileNotFoundError) as exc:
        gnark_keys.load_manifest()
    message = str(exc.value)
    assert str(empty) in message
    assert "--force" not in message
    assert gnark_keys.KEYS_DIR_ENV in message and gnark_keys.PK_DIR_ENV in message


def test_pk_dir_is_the_environment_else_the_ppflx_cache(monkeypatch, tmp_path):
    monkeypatch.delenv(gnark_keys.PK_DIR_ENV, raising=False)
    assert gnark_keys.pk_dir() == Path.home() / ".cache" / "ppflx" / "pk"

    monkeypatch.setenv(gnark_keys.PK_DIR_ENV, str(tmp_path))
    assert gnark_keys.pk_dir() == tmp_path


def test_key_dirs_expand_a_home_prefix(monkeypatch):
    monkeypatch.setenv(gnark_keys.KEYS_DIR_ENV, "~/k")
    monkeypatch.setenv(gnark_keys.PK_DIR_ENV, "~/p")
    assert gnark_keys.keys_dir() == Path.home() / "k"
    assert gnark_keys.pk_dir() == Path.home() / "p"


def test_gnark_binary_has_no_default(monkeypatch):
    monkeypatch.delenv(he_elgamal.BINARY_ENV, raising=False)
    with pytest.raises(FileNotFoundError, match=he_elgamal.BINARY_ENV):
        he_elgamal.gnark_binary()


def test_elgamal_generate_keeps_existing_keys_when_the_binary_is_missing(monkeypatch, tmp_path):
    secret, public = tmp_path / "secret_key.json", tmp_path / "public_key.json"
    secret.write_text("old secret")
    public.write_text("old public")
    monkeypatch.setenv(he_elgamal.BINARY_ENV, str(tmp_path / "missing"))
    with pytest.raises(FileNotFoundError, match=he_elgamal.BINARY_ENV):
        he_elgamal.generate(str(secret), str(public), overwrite=True)
    assert secret.read_text() == "old secret" and public.read_text() == "old public"
