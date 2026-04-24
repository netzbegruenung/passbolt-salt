"""
Sequoia PGP backend for decryption using the `sq` CLI.

Each decryption runs in its own process, so concurrent pillar renders do not
contend on a single gpg-agent.
"""

import logging
import os
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


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

    def decrypt(self, encrypted_data: str, passphrase: Optional[str] = None) -> str:
        """
        Decrypt ASCII-armored OpenPGP data via `sq decrypt`.
        """
        effective_passphrase = passphrase if passphrase is not None else self.passphrase

        cmd = ["sq"]
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
