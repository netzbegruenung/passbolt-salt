"""Tests for the GPGAuth login flow, without touching a real Passbolt server."""
import urllib.parse

import pytest
import requests

from salt_passbolt.api import LOGIN_URL, PassboltAuthError, PassboltClient, _unescape_token
from salt_passbolt.pgp_backend import SequoiaBackend

SERVER = "https://passbolt.example.com"
FINGERPRINT = "B2011423418A5B26CF9C56A9905B7682340C3A7D"
TOKEN = "gpgauthv1.3.0|36|3ec2a739-8e51-4c67-89fb-4bbfe9147e17|gpgauthv1.3.0"
CONFIG = {"SERVER": SERVER, "USER_FINGERPRINT": FINGERPRINT}


class FakeResponse:
    def __init__(self, status_code=200, headers=None, json_body=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self._json_body = json_body
        self.text = text if text or json_body is None else str(json_body)

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Stands in for requests.Session, recording calls and replaying answers."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.cookies = {}
        self.verify = True
        self.closed = False

    def post(self, url, json=None, timeout=None, headers=None):
        self.calls.append(("POST", url, json, headers))
        return self.handler("POST", url, json)

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url, None, headers))
        return self.handler("GET", url, None)

    def close(self):
        self.closed = True


class FakeBackend:
    """SequoiaBackend stand-in returning a canned plaintext."""

    def __init__(self, plaintext=TOKEN, error=None, fingerprint=FINGERPRINT):
        self.plaintext = plaintext
        self.error = error
        self._fingerprint = fingerprint
        self.decrypted = []

    def decrypt(self, data, passphrase=None):
        self.decrypted.append(data)
        if self.error:
            raise self.error
        return self.plaintext

    def fingerprint(self):
        return self._fingerprint


def make_client(handler, backend=None, config=None):
    """Build a client whose HTTP layer is a FakeSession."""
    client = PassboltClient(config or CONFIG, backend or FakeBackend())
    client._session = FakeSession(handler)
    return client


def default_handler(csrf_token="csrf-abc", authenticated=True, me_response=None):
    """Handler for a server that plays the GPGAuth flow correctly."""
    state = {"logins": 0}

    def handler(method, url, body):
        if method == "POST" and url.endswith(LOGIN_URL):
            state["logins"] += 1
            if state["logins"] == 1:
                return FakeResponse(headers={"X-GPGAuth-User-Auth-Token": "ENCRYPTED"})
            headers = {"X-GPGAuth-Authenticated": "true"} if authenticated else {}
            return FakeResponse(headers=headers)
        if method == "GET" and url.endswith("/users/me.json"):
            return me_response or FakeResponse(json_body={"body": {"id": "me"}})
        if method == "GET":
            return FakeResponse(json_body={"body": []})
        raise AssertionError(f"unexpected request: {method} {url}")

    return handler


def test_login_posts_decrypted_token():
    backend = FakeBackend()
    client = make_client(default_handler(), backend=backend)
    client._session.cookies["csrfToken"] = "csrf-abc"

    client.login()

    posts = [call for call in client._session.calls if call[0] == "POST"]
    assert len(posts) == 2
    assert posts[0][2] == {"gpg_auth": {"keyid": FINGERPRINT}}
    assert posts[1][2] == {
        "gpg_auth": {"keyid": FINGERPRINT, "user_token_result": TOKEN}
    }
    assert backend.decrypted == ["ENCRYPTED"]


def test_login_strips_whitespace_from_token():
    client = make_client(default_handler(), backend=FakeBackend(plaintext=f"{TOKEN}\n"))
    client.login()
    posts = [call for call in client._session.calls if call[0] == "POST"]
    assert posts[1][2]["gpg_auth"]["user_token_result"] == TOKEN


def test_login_verifies_session_and_picks_up_csrf_token():
    client = make_client(default_handler())
    client._session.cookies["csrfToken"] = "csrf-abc"
    client.login()

    client.get("/resources.json")

    method, url, _, headers = client._session.calls[-1]
    assert (method, url) == ("GET", SERVER + "/resources.json")
    assert headers == {"X-CSRF-Token": "csrf-abc"}


def test_get_sends_empty_csrf_token_when_cookie_absent():
    client = make_client(default_handler())
    client.login()
    client.get("/resources.json")
    assert client._session.calls[-1][3] == {"X-CSRF-Token": ""}


def test_missing_challenge_header_raises_with_server_reason():
    def handler(method, url, body):
        return FakeResponse(
            status_code=400,
            headers={"X-GPGAuth-Error": "true", "X-GPGAuth-Debug": "The user does not exist."},
        )

    client = make_client(handler)
    with pytest.raises(PassboltAuthError, match="The user does not exist."):
        client.login()


def test_undecryptable_challenge_raises():
    backend = FakeBackend(error=RuntimeError("sq decrypt failed: bad passphrase"))
    client = make_client(default_handler(), backend=backend)
    with pytest.raises(PassboltAuthError, match="bad passphrase"):
        client.login()


def test_empty_decrypted_challenge_raises():
    client = make_client(default_handler(), backend=FakeBackend(plaintext="  \n"))
    with pytest.raises(PassboltAuthError, match="empty"):
        client.login()


def test_mfa_required_raises_actionable_error():
    me = FakeResponse(
        status_code=403,
        json_body={"header": {"message": "MFA authentication is required."}},
    )
    client = make_client(default_handler(me_response=me))
    with pytest.raises(PassboltAuthError, match="MFA"):
        client.login()


def test_mfa_detected_without_json_body():
    me = FakeResponse(status_code=403, text="MFA authentication is required.")
    client = make_client(default_handler(me_response=me))
    with pytest.raises(PassboltAuthError, match="MFA"):
        client.login()


def test_rejected_session_raises_auth_error():
    me = FakeResponse(status_code=401, text="Authentication is required to continue")
    client = make_client(default_handler(me_response=me))
    with pytest.raises(PassboltAuthError, match="rejected"):
        client.login()


def test_login_succeeds_without_authenticated_header(caplog):
    """The header is advisory; /users/me.json is what actually proves the session."""
    client = make_client(default_handler(authenticated=False))
    client.login()
    assert "did not confirm authentication" in caplog.text


def test_get_propagates_http_errors():
    def handler(method, url, body):
        if url.endswith("/resources.json"):
            return FakeResponse(status_code=500, text="boom")
        return default_handler()(method, url, body)

    client = make_client(handler)
    client.login()
    with pytest.raises(requests.exceptions.HTTPError):
        client.get("/resources.json")


def test_close_closes_session():
    client = make_client(default_handler())
    client.close()
    assert client._session.closed is True


def test_context_manager_logs_in_and_closes():
    client = PassboltClient(CONFIG, FakeBackend())
    client._session = FakeSession(default_handler())
    with client as entered:
        assert entered is client
        assert any(call[0] == "POST" for call in client._session.calls)
    assert client._session.closed is True


def test_missing_server_raises():
    with pytest.raises(ValueError, match="SERVER"):
        PassboltClient({}, FakeBackend())


def test_fingerprint_is_normalized_from_config():
    config = {"SERVER": SERVER, "USER_FINGERPRINT": "b201 1423 418a 5b26 cf9c 56a9 905b 7682 340c 3a7d"}
    client = PassboltClient(config, FakeBackend(fingerprint="OTHER"))
    assert client.fingerprint == FINGERPRINT


def test_fingerprint_falls_back_to_key_file():
    client = PassboltClient({"SERVER": SERVER}, FakeBackend(fingerprint=FINGERPRINT))
    assert client.fingerprint == FINGERPRINT


def test_server_url_trailing_slash_is_stripped():
    client = PassboltClient({"SERVER": SERVER + "/", "USER_FINGERPRINT": FINGERPRINT}, FakeBackend())
    assert client.server_url == SERVER


def test_unescape_token_restores_armor():
    armor = "-----BEGIN PGP MESSAGE-----\n\nhQIMA+w bar\n-----END PGP MESSAGE-----\n"
    header = urllib.parse.quote(armor).replace("%20", r"\+")
    assert _unescape_token(header) == armor


@pytest.mark.skipif(not SequoiaBackend.is_available(), reason="sq CLI not available")
def test_login_with_real_sq_decryption(keypair_no_pass, sq_encrypt):
    """End-to-end: a real sq-encrypted challenge, decrypted by the real backend."""
    ciphertext = sq_encrypt(keypair_no_pass, TOKEN)
    backend = SequoiaBackend(key_file=str(keypair_no_pass))

    def handler(method, url, body):
        if method == "POST" and url.endswith(LOGIN_URL):
            if body["gpg_auth"].get("user_token_result") is None:
                encoded = urllib.parse.quote(ciphertext).replace("%20", r"\+")
                return FakeResponse(headers={"X-GPGAuth-User-Auth-Token": encoded})
            assert body["gpg_auth"]["user_token_result"] == TOKEN
            return FakeResponse(headers={"X-GPGAuth-Authenticated": "true"})
        return FakeResponse(json_body={"body": {"id": "me"}})

    config = {"SERVER": SERVER}
    client = PassboltClient(config, backend)
    client._session = FakeSession(handler)

    client.login()

    assert client.fingerprint == backend.fingerprint()
    posts = [call for call in client._session.calls if call[0] == "POST"]
    assert posts[1][2]["gpg_auth"]["user_token_result"] == TOKEN
