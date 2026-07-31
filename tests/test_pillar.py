"""Tests for pillar generation and config loading."""
import pytest

import salt_passbolt
from salt_passbolt import PassboltError, decode_json, generate_pillar, load_config

GROUP_UUID = "27b9abd4-af9b-4c9e-9af1-cf8cb963680c"
RESOURCE_UUID = "3ec2a739-8e51-4c67-89fb-4bbfe9147e17"

CONFIG_FILE = """\
[PASSBOLT]
SERVER = https://passbolt.example.com
USER_FINGERPRINT = B2011423418A5B26CF9C56A9905B7682340C3A7D
USER_PRIVATE_KEY_FILE = /etc/salt/passbolt_private.asc
PASSPHRASE = s3cret
"""


class FakeBackend:
    def __init__(self, plaintexts=None):
        self.plaintexts = plaintexts or {}

    def decrypt(self, data, passphrase=None):
        if isinstance(self.plaintexts.get(data), Exception):
            raise self.plaintexts[data]
        return self.plaintexts.get(data, data)


class FakeClient:
    def __init__(self, resources, secrets):
        self.resources = resources
        self.secrets = secrets

    def get(self, url):
        if url.startswith("/resources.json"):
            if isinstance(self.resources, Exception):
                raise self.resources
            return {"body": self.resources}
        for resource_id, secret in self.secrets.items():
            if url.startswith(f"/secrets/resource/{resource_id}.json"):
                if isinstance(secret, Exception):
                    raise secret
                return {"body": {"data": secret}}
        raise AssertionError(f"unexpected URL: {url}")


def resource(resource_id=RESOURCE_UUID, name="db"):
    return {"id": resource_id, "name": name, "username": "u", "uri": "https://x"}


def test_load_config_upper_cases_option_names(tmp_path):
    """configparser lower-cases options; callers look them up in upper case."""
    config_file = tmp_path / "passbolt.ini"
    config_file.write_text(CONFIG_FILE)

    config = load_config(str(config_file))

    assert config["SERVER"] == "https://passbolt.example.com"
    assert config["USER_PRIVATE_KEY_FILE"] == "/etc/salt/passbolt_private.asc"
    assert config["PASSPHRASE"] == "s3cret"


def test_load_config_keeps_percent_in_passphrase_literal(tmp_path):
    """Interpolation is off, so % needs no escaping in passbolt.ini."""
    config_file = tmp_path / "passbolt.ini"
    config_file.write_text(CONFIG_FILE.replace("s3cret", "100%_s3cret"))

    assert load_config(str(config_file))["PASSPHRASE"] == "100%_s3cret"


def test_generate_pillar_decrypts_secrets():
    client = FakeClient(resources=[resource()], secrets={RESOURCE_UUID: "CIPHERTEXT"})
    backend = FakeBackend({"CIPHERTEXT": '{"password":"hunter2","description":""}'})

    pillar = generate_pillar(client, backend, GROUP_UUID)

    assert pillar == {"passbolt": {RESOURCE_UUID: "hunter2"}}


def test_generate_pillar_supports_legacy_string_secrets():
    client = FakeClient(resources=[resource()], secrets={RESOURCE_UUID: "CIPHERTEXT"})
    backend = FakeBackend({"CIPHERTEXT": "plain-legacy-password"})

    pillar = generate_pillar(client, backend, GROUP_UUID)

    assert pillar["passbolt"][RESOURCE_UUID] == "plain-legacy-password"


def test_generate_pillar_raises_on_listing_failure():
    client = FakeClient(resources=RuntimeError("no access"), secrets={})

    with pytest.raises(PassboltError, match=GROUP_UUID):
        generate_pillar(client, FakeBackend(), GROUP_UUID)


def test_generate_pillar_raises_when_a_secret_is_unreadable():
    """One unreadable secret fails the render; the readable ones do not mask it."""
    other = "8b3f1c2a-0000-4c67-89fb-4bbfe9147e17"
    client = FakeClient(
        resources=[resource(), resource(other, "web")],
        secrets={RESOURCE_UUID: RuntimeError("fetch failed"), other: "CIPHERTEXT"},
    )
    backend = FakeBackend({"CIPHERTEXT": '{"password":"kept"}'})

    with pytest.raises(PassboltError, match=RESOURCE_UUID):
        generate_pillar(client, backend, GROUP_UUID)


def test_generate_pillar_raises_when_a_secret_fails_to_decrypt():
    client = FakeClient(resources=[resource()], secrets={RESOURCE_UUID: "CIPHERTEXT"})
    backend = FakeBackend({"CIPHERTEXT": RuntimeError("sq decrypt failed")})

    with pytest.raises(PassboltError, match="Failed to decrypt"):
        generate_pillar(client, backend, GROUP_UUID)


def test_generate_pillar_raises_on_empty_password():
    """An empty secret must never reach the pillar as an empty value."""
    client = FakeClient(resources=[resource()], secrets={RESOURCE_UUID: "CIPHERTEXT"})
    backend = FakeBackend({"CIPHERTEXT": '{"password":"","description":""}'})

    with pytest.raises(PassboltError, match="Empty passwords are not allowed"):
        generate_pillar(client, backend, GROUP_UUID)


def test_decode_json_rejects_empty_password():
    with pytest.raises(ValueError):
        decode_json("")


def test_fetch_rejects_invalid_group_uuid():
    with pytest.raises(PassboltError, match="not a valid UUID"):
        salt_passbolt.fetch_passbolt_passwords("not-a-uuid")


def test_fetch_raises_when_private_key_file_missing(monkeypatch):
    monkeypatch.setattr(
        salt_passbolt, "load_config", lambda: {"SERVER": "https://passbolt.example.com"}
    )
    with pytest.raises(PassboltError, match="USER_PRIVATE_KEY_FILE"):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)


def test_fetch_raises_when_config_unreadable(monkeypatch):
    def raise_missing():
        raise FileNotFoundError("/etc/salt/passbolt.ini")

    monkeypatch.setattr(salt_passbolt, "load_config", raise_missing)
    with pytest.raises(PassboltError, match="Failed to load the Passbolt configuration"):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)


def test_fetch_reports_unreadable_key_file_not_a_server_error(monkeypatch):
    """An unusable key file must not be blamed on the Passbolt server."""
    monkeypatch.setattr(
        salt_passbolt,
        "load_config",
        lambda: {
            "SERVER": "https://passbolt.example.com",
            "USER_PRIVATE_KEY_FILE": "/etc/salt/broken.asc",
        },
    )

    class BrokenKeyBackend:
        def __init__(self, key_file=None, passphrase=None):
            pass

        def fingerprint(self):
            raise RuntimeError("sq keyring list failed: no such file")

    monkeypatch.setattr(salt_passbolt, "SequoiaBackend", BrokenKeyBackend)

    with pytest.raises(PassboltError, match="/etc/salt/broken.asc"):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
