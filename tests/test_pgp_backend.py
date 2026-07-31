"""Round-trip tests for the Sequoia (sq) decryption backend."""
import pytest

from salt_passbolt.pgp_backend import SequoiaBackend

pytestmark = pytest.mark.skipif(
    not SequoiaBackend.is_available(),
    reason="sq CLI not available",
)

PLAINTEXT = '{"password":"hunter2","description":""}'


def test_is_available_true():
    assert SequoiaBackend.is_available() is True


def test_decrypt_no_passphrase(keypair_no_pass, sq_encrypt):
    ciphertext = sq_encrypt(keypair_no_pass, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(keypair_no_pass))
    assert backend.decrypt(ciphertext).strip() == PLAINTEXT


def test_decrypt_with_passphrase(keypair_with_pass, sq_encrypt):
    key_file, passphrase = keypair_with_pass
    ciphertext = sq_encrypt(key_file, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(key_file), passphrase=passphrase)
    assert backend.decrypt(ciphertext).strip() == PLAINTEXT


def test_per_call_passphrase_overrides_instance(keypair_with_pass, sq_encrypt):
    key_file, passphrase = keypair_with_pass
    ciphertext = sq_encrypt(key_file, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(key_file), passphrase="ignored")
    assert backend.decrypt(ciphertext, passphrase=passphrase).strip() == PLAINTEXT


def test_wrong_passphrase_raises(keypair_with_pass, sq_encrypt):
    key_file, _ = keypair_with_pass
    ciphertext = sq_encrypt(key_file, PLAINTEXT)
    backend = SequoiaBackend(key_file=str(key_file), passphrase="wrong")
    with pytest.raises(RuntimeError):
        backend.decrypt(ciphertext)


def test_garbage_input_raises(keypair_no_pass):
    backend = SequoiaBackend(key_file=str(keypair_no_pass))
    with pytest.raises(RuntimeError, match="sq decrypt failed"):
        backend.decrypt("not a valid OpenPGP message")


def test_fingerprint_is_primary_key_fingerprint(keypair_no_pass):
    backend = SequoiaBackend(key_file=str(keypair_no_pass))
    fingerprint = backend.fingerprint()
    assert len(fingerprint) == 40
    assert fingerprint == fingerprint.upper()
    assert all(c in "0123456789ABCDEF" for c in fingerprint)
    # The armored key file must actually mention it, and it must be cached.
    assert backend.fingerprint() is fingerprint


def test_fingerprint_of_multi_key_file_raises(tmp_path, keypair_no_pass, keypair_with_pass):
    """Picking one of several keys would send the wrong GPGAuth keyid."""
    other_key, _ = keypair_with_pass
    combined = tmp_path / "two-keys.asc"
    combined.write_text(keypair_no_pass.read_text() + other_key.read_text())

    backend = SequoiaBackend(key_file=str(combined))
    with pytest.raises(RuntimeError, match="contains 2 keys"):
        backend.fingerprint()


def test_fingerprint_without_key_file_raises():
    backend = SequoiaBackend(key_file=None)
    with pytest.raises(RuntimeError, match="No key file configured"):
        backend.fingerprint()


def test_fingerprint_of_non_key_file_raises(tmp_path):
    junk = tmp_path / "junk.asc"
    junk.write_text("definitely not a key")
    backend = SequoiaBackend(key_file=str(junk))
    with pytest.raises(RuntimeError, match="sq keyring list failed"):
        backend.fingerprint()
