"""Round-trip tests for the Sequoia (sq) decryption backend."""
import os
import subprocess

import pytest

from pgp_backend import SequoiaBackend  # type: ignore[import-not-found]

pytestmark = pytest.mark.skipif(
    not SequoiaBackend.is_available(),
    reason="sq CLI not available",
)

PLAINTEXT = '{"password":"hunter2","description":""}'


def _generate_key(home, password_file=None):
    """Generate a fresh key under SEQUOIA_HOME=home, return path to key file."""
    key_file = home / "key.asc"
    rev_file = home / "key.rev"
    cmd = [
        "sq", "key", "generate",
        "--own-key",
        "--name", "Test", "--email", "test@example.com",
        "--output", str(key_file),
        "--rev-cert", str(rev_file),
    ]
    if password_file is None:
        cmd.append("--without-password")
    else:
        cmd += ["--new-password-file", str(password_file)]
    env = {**os.environ, "SEQUOIA_HOME": str(home)}
    subprocess.run(cmd, check=True, capture_output=True, env=env)
    return key_file


def _encrypt(key_file, plaintext):
    result = subprocess.run(
        ["sq", "encrypt", "--for-file", str(key_file), "--without-signature"],
        input=plaintext,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.fixture(scope="module")
def keypair_no_pass(tmp_path_factory):
    home = tmp_path_factory.mktemp("sq_home_nopass")
    return _generate_key(home)


@pytest.fixture(scope="module")
def keypair_with_pass(tmp_path_factory):
    home = tmp_path_factory.mktemp("sq_home_pass")
    pass_file = home / "pass.txt"
    passphrase = "test-passphrase-123"
    pass_file.write_text(passphrase)
    return _generate_key(home, password_file=pass_file), passphrase


def test_is_available_true():
    assert SequoiaBackend.is_available() is True


def test_decrypt_no_passphrase(keypair_no_pass):
    ciphertext = _encrypt(keypair_no_pass, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(keypair_no_pass))
    assert backend.decrypt(ciphertext).strip() == PLAINTEXT


def test_decrypt_with_passphrase(keypair_with_pass):
    key_file, passphrase = keypair_with_pass
    ciphertext = _encrypt(key_file, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(key_file), passphrase=passphrase)
    assert backend.decrypt(ciphertext).strip() == PLAINTEXT


def test_per_call_passphrase_overrides_instance(keypair_with_pass):
    key_file, passphrase = keypair_with_pass
    ciphertext = _encrypt(key_file, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(key_file), passphrase="ignored")
    assert backend.decrypt(ciphertext, passphrase=passphrase).strip() == PLAINTEXT


def test_wrong_passphrase_raises(keypair_with_pass):
    key_file, _ = keypair_with_pass
    ciphertext = _encrypt(key_file, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(key_file), passphrase="wrong")
    with pytest.raises(RuntimeError):
        backend.decrypt(ciphertext)


def test_garbage_input_raises(keypair_no_pass):
    backend = SequoiaBackend(key_file=str(keypair_no_pass))
    with pytest.raises(RuntimeError, match="sq decrypt failed"):
        backend.decrypt("not a valid OpenPGP message")
