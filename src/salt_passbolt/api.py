"""
Minimal Passbolt API client performing GPGAuth login with Sequoia (`sq`).

Only the read paths this module needs are implemented: authenticate, then GET
JSON. Decryption of the GPGAuth challenge is delegated to the same
SequoiaBackend that decrypts the secrets themselves, so no GnuPG keyring and no
gpg-agent are involved anywhere in the flow.
"""

import logging
import urllib.parse

import requests

from .pgp_backend import SequoiaBackend

logger = logging.getLogger(__name__)

LOGIN_URL = "/auth/login.json"
_ME_URL = "/users/me.json"
_DEFAULT_TIMEOUT = 30


class PassboltError(Exception):
    """
    Passbolt secrets could not be fetched.

    Always fatal: callers must let this propagate so that the pillar render
    fails instead of handing states a pillar with missing secrets.
    """


class PassboltAuthError(PassboltError):
    """The GPGAuth handshake with the Passbolt server failed."""


class PassboltClient:
    """
    Authenticated, read-only session against a Passbolt server.

    Usage:
        with PassboltClient(config, backend) as client:
            client.get("/resources.json")
    """

    def __init__(self, config: dict, backend: SequoiaBackend):
        server = config.get("SERVER")
        if not server:
            raise ValueError("Missing value for SERVER in passbolt.ini.")
        self.server_url = server.rstrip("/")
        self.backend = backend
        self.timeout = _DEFAULT_TIMEOUT
        self.fingerprint = self._resolve_fingerprint(config, backend)

        self._session = requests.Session()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @staticmethod
    def _resolve_fingerprint(config: dict, backend: SequoiaBackend) -> str:
        """
        The GPGAuth keyid: USER_FINGERPRINT if configured, else derived from the
        private key file.
        """
        configured = config.get("USER_FINGERPRINT")
        if configured:
            return configured.upper().replace(" ", "")
        fingerprint = backend.fingerprint()
        logger.debug(f"USER_FINGERPRINT not configured, using {fingerprint} from the key file.")
        return fingerprint

    def login(self):
        """
        Run the GPGAuth handshake and prepare the session for API calls.

        Raises PassboltAuthError if the server does not hand out a challenge or
        the resulting session is not usable.
        """
        token = self._solve_challenge()
        response = self._session.post(
            self.server_url + LOGIN_URL,
            json={"gpg_auth": {"keyid": self.fingerprint, "user_token_result": token}},
            timeout=self.timeout,
        )
        if response.headers.get("X-GPGAuth-Authenticated") != "true":
            # Not fatal on its own: header naming has varied across server
            # versions, and the /users/me.json call below is the real proof.
            logger.warning(
                "Passbolt did not confirm authentication in the GPGAuth headers "
                f"({self._gpgauth_details(response)}). Verifying the session anyway."
            )
        self._verify_session()
        logger.debug(f"Authenticated against {self.server_url} as {self.fingerprint}.")

    def _solve_challenge(self) -> str:
        """
        GPGAuth stage 1: ask for a challenge token and decrypt it.
        """
        response = self._session.post(
            self.server_url + LOGIN_URL,
            json={"gpg_auth": {"keyid": self.fingerprint}},
            timeout=self.timeout,
        )
        encrypted_token = response.headers.get("X-GPGAuth-User-Auth-Token")
        if not encrypted_token:
            raise PassboltAuthError(
                "Passbolt did not return a GPGAuth challenge for fingerprint "
                f"{self.fingerprint} ({self._gpgauth_details(response)}). Verify that "
                "the key is registered with the Passbolt user."
            )
        try:
            token = self.backend.decrypt(_unescape_token(encrypted_token)).strip()
        except Exception as e:
            raise PassboltAuthError(f"Could not decrypt the GPGAuth challenge: {e}") from e
        if not token:
            raise PassboltAuthError("Decrypted GPGAuth challenge was empty.")
        return token

    def _verify_session(self):
        """
        Confirm the session works and pick up the CSRF cookie for later calls.
        """
        response = self._session.get(
            self.server_url + _ME_URL,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if response.status_code == requests.codes.forbidden and _mfa_required(response):
            raise PassboltAuthError(
                "Passbolt requires MFA for this account, which is not supported. "
                "Disable MFA for the Salt master's Passbolt user."
            )
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise PassboltAuthError(f"GPGAuth login was rejected: {_describe(response)}") from e

    def get(self, url: str) -> dict:
        """
        GET a Passbolt API endpoint and return the decoded JSON body.
        """
        response = self._session.get(
            self.server_url + url,
            headers=self._headers(),
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            logger.error(f"Passbolt request to {url} failed: {_describe(response)}")
            raise
        return response.json()

    def _headers(self) -> dict:
        return {"X-CSRF-Token": self._session.cookies.get("csrfToken", "")}

    @staticmethod
    def _gpgauth_details(response) -> str:
        """Server-provided reason for a failed handshake, for error messages."""
        details = [f"HTTP {response.status_code}"]
        debug = response.headers.get("X-GPGAuth-Debug")
        if debug:
            details.append(debug)
        return ", ".join(details)

    def close(self):
        self._session.close()


def _unescape_token(header_value: str) -> str:
    """
    Turn the X-GPGAuth-User-Auth-Token header back into an armored message.

    Passbolt percent-encodes the armor and escapes its spaces as `\\+`.
    """
    return urllib.parse.unquote(header_value).replace(r"\+", " ")


def _mfa_required(response) -> bool:
    try:
        return response.json()["header"]["message"] == "MFA authentication is required."
    except (ValueError, TypeError, KeyError):
        return "MFA authentication is required" in response.text


def _describe(response) -> str:
    """Short HTTP failure description, body truncated to keep logs readable."""
    body = (response.text or "").strip()
    if len(body) > 500:
        body = body[:500] + "…"
    return f"HTTP {response.status_code}: {body}" if body else f"HTTP {response.status_code}"
