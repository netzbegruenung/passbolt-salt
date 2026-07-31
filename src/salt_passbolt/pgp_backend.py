"""
Sequoia PGP backend for decryption using the `sq` CLI.

Each decryption runs in its own process, so concurrent pillar renders do not
contend on a single gpg-agent.
"""

import logging
import os
import re
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Keep sq stateless: never touch the user's cert store, never start a key store
# server. Everything is read from the key file we pass explicitly.
_ISOLATION = ["--cert-store", "none", "--key-store", "none"]

_FINGERPRINT_RE = re.compile(r"\b[0-9A-F]{40}\b")


class SequoiaBackend:
    """
    Sequoia PGP backend that shells out to `sq decrypt` per call.

    The passphrase is handed to `sq` via an anonymous pipe (read end inherited
    by the child as /dev/fd/<n>). It never touches disk and never appears on
    any process command line.
    """

    def __init__(
        self,
        key_file: Optional[str],
        passphrase: Optional[str] = None,
    ):
        if not self.is_available():
            raise RuntimeError("sq CLI not available. SequoiaBackend cannot be used.")
        self.key_file = key_file
        self.passphrase = passphrase
        self._fingerprint: Optional[str] = None

    def decrypt(self, encrypted_data: str, passphrase: Optional[str] = None) -> str:
        """
        Decrypt ASCII-armored OpenPGP data via `sq decrypt`.
        """
        effective_passphrase = passphrase if passphrase is not None else self.passphrase

        cmd = ["sq"] + _ISOLATION
        pass_fds: Tuple[int, ...] = ()
        pass_r: Optional[int] = None

        try:
            if effective_passphrase:
                # Pass the passphrase through an in-memory pipe; the child
                # reads it as /dev/fd/<n> via sq's global --password-file.
                pass_r, pass_w = os.pipe()
                try:
                    os.write(pass_w, effective_passphrase.encode("utf-8"))
                finally:
                    os.close(pass_w)
                pass_fds = (pass_r,)
                cmd += ["--password-file", f"/dev/fd/{pass_r}"]

            cmd += ["decrypt"]
            if self.key_file:
                cmd += ["--recipient-file", self.key_file]

            try:
                result = subprocess.run(
                    cmd,
                    input=encrypted_data,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                    pass_fds=pass_fds,
                )
            except subprocess.TimeoutExpired as e:
                raise RuntimeError("sq decrypt timed out") from e
        finally:
            if pass_r is not None:
                os.close(pass_r)

        if result.returncode != 0:
            stderr = result.stderr or "Unknown error"
            raise RuntimeError(f"sq decrypt failed: {stderr}")
        return result.stdout

    def fingerprint(self) -> str:
        """
        The primary key fingerprint of `key_file`, as 40 upper-case hex chars.

        Used as the GPGAuth keyid when the config does not pin one explicitly.
        """
        if self._fingerprint is not None:
            return self._fingerprint
        if not self.key_file:
            raise RuntimeError("No key file configured, cannot determine fingerprint.")

        try:
            result = subprocess.run(
                ["sq"] + _ISOLATION + ["keyring", "list", self.key_file],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError("sq keyring list timed out") from e
        if result.returncode != 0:
            stderr = result.stderr or "Unknown error"
            raise RuntimeError(f"sq keyring list failed for {self.key_file}: {stderr}")

        # `sq keyring list` prints one line per cert, starting with the primary
        # key fingerprint: "0. B2011423418A5B26CF9C56A9905B7682340C3A7D Test"
        fingerprints = list(dict.fromkeys(_FINGERPRINT_RE.findall(result.stdout)))
        if not fingerprints:
            raise RuntimeError(f"Could not read a key fingerprint from {self.key_file}.")
        if len(fingerprints) > 1:
            # Guessing here would send the wrong GPGAuth keyid and the server
            # would answer with an unrelated "unknown user" error.
            raise RuntimeError(
                f"{self.key_file} contains {len(fingerprints)} keys "
                f"({', '.join(fingerprints)}). Set USER_FINGERPRINT to select one, or point "
                "USER_PRIVATE_KEY_FILE at a file holding only the Salt master's key."
            )
        self._fingerprint = fingerprints[0]
        return self._fingerprint

    @classmethod
    def is_available(cls) -> bool:
        """Whether the sq CLI is on PATH and runnable."""
        try:
            subprocess.run(
                ["sq", "--help"],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
