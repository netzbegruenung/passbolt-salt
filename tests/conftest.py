import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))


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


@pytest.fixture(scope="session")
def sq_encrypt():
    """Encrypt plaintext for the recipient in key_file, returning the armor."""
    def encrypt(key_file, plaintext):
        result = subprocess.run(
            # Same isolation flags as the production code, so the test never
            # reads the invoking user's cert/key store.
            ["sq", "--cert-store", "none", "--key-store", "none",
             "encrypt", "--for-file", str(key_file), "--without-signature"],
            input=plaintext,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    return encrypt


@pytest.fixture(scope="session")
def keypair_no_pass(tmp_path_factory):
    home = tmp_path_factory.mktemp("sq_home_nopass")
    return _generate_key(home)


@pytest.fixture(scope="session")
def keypair_with_pass(tmp_path_factory):
    home = tmp_path_factory.mktemp("sq_home_pass")
    pass_file = home / "pass.txt"
    passphrase = "test-passphrase-123"
    pass_file.write_text(passphrase)
    return _generate_key(home, password_file=pass_file), passphrase
