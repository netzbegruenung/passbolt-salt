"""Tests for pillar generation, caching and config loading."""
import os
import threading

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


CONFIG = {
    "SERVER": "https://passbolt.example.com",
    "USER_PRIVATE_KEY_FILE": "/etc/salt/passbolt_private.asc",
}
OTHER_GROUP_UUID = "5c1e6f0a-3b2d-4e8f-9a7c-1d2e3f4a5b6c"


class CountingClient(FakeClient):
    """FakeClient that also counts logins, requests and closes."""

    def __init__(self, resources, secrets):
        super().__init__(resources, secrets)
        self.backend = FakeBackend({"CIPHERTEXT": '{"password":"hunter2"}'})
        self.logins = 0
        self.requests = 0
        self.closed = False

    def login(self):
        self.logins += 1

    def get(self, url):
        self.requests += 1
        return super().get(url)

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fresh_state():
    """Module state survives between calls by design, so isolate every test."""
    salt_passbolt._reset_state()
    yield
    salt_passbolt._reset_state()


@pytest.fixture
def passbolt(monkeypatch):
    """
    Route fetch_passbolt_passwords to fake clients. Returns a namespace whose
    `config` is what load_config hands out and `clients` lists every client
    built, so tests can count logins.
    """
    class State:
        config = dict(CONFIG)
        clients = []
        now = 1000.0

    def new_client(config):
        client = CountingClient(
            resources=[resource()], secrets={RESOURCE_UUID: "CIPHERTEXT"}
        )
        State.clients.append(client)
        return client, client.backend

    monkeypatch.setattr(salt_passbolt, "load_config", lambda: dict(State.config))
    monkeypatch.setattr(salt_passbolt, "_new_client", new_client)
    monkeypatch.setattr(salt_passbolt.time, "monotonic", lambda: State.now)
    return State


def test_fetch_serves_repeated_calls_from_cache(passbolt):
    first = salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    second = salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)

    assert first == second == {"passbolt": {RESOURCE_UUID: "hunter2"}}
    assert len(passbolt.clients) == 1
    assert passbolt.clients[0].logins == 1
    # One listing plus one secret: the second call did not reach Passbolt.
    assert passbolt.clients[0].requests == 2


def test_fetch_refreshes_after_ttl_without_logging_in_again(passbolt):
    passbolt.config["CACHE_TTL"] = "60"
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)

    passbolt.now += 59
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert passbolt.clients[0].requests == 2

    passbolt.now += 1
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert passbolt.clients[0].requests == 4
    assert len(passbolt.clients) == 1
    assert passbolt.clients[0].logins == 1


def test_fetch_default_ttl_is_ten_minutes(passbolt):
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    passbolt.now += 599
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert passbolt.clients[0].requests == 2
    passbolt.now += 1
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert passbolt.clients[0].requests == 4


def test_fetch_ttl_zero_disables_cache_but_keeps_session(passbolt):
    passbolt.config["CACHE_TTL"] = "0"
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)

    assert passbolt.clients[0].requests == 4
    assert passbolt.clients[0].logins == 1


def test_fetch_caches_each_group_separately(passbolt):
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    salt_passbolt.fetch_passbolt_passwords(OTHER_GROUP_UUID)
    salt_passbolt.fetch_passbolt_passwords(OTHER_GROUP_UUID)

    assert passbolt.clients[0].requests == 4
    assert passbolt.clients[0].logins == 1


def test_fetch_returns_a_copy_of_the_cached_pillar(passbolt):
    pillar = salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    pillar["passbolt"][RESOURCE_UUID] = "changed by the caller"

    assert salt_passbolt.fetch_passbolt_passwords(GROUP_UUID) == {
        "passbolt": {RESOURCE_UUID: "hunter2"}
    }


def test_fetch_changed_config_drops_session_and_cache(passbolt):
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    passbolt.config["SERVER"] = "https://other.example.com"
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)

    assert len(passbolt.clients) == 2
    assert passbolt.clients[0].closed is True
    assert passbolt.clients[1].logins == 1
    assert passbolt.clients[1].requests == 2


def test_fetch_failure_is_not_cached_and_forces_new_login(passbolt):
    salt_passbolt.fetch_passbolt_passwords(OTHER_GROUP_UUID)
    passbolt.clients[0].resources = RuntimeError("server down")

    with pytest.raises(PassboltError):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert passbolt.clients[0].closed is True

    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert len(passbolt.clients) == 2
    assert passbolt.clients[1].logins == 1
    # A failing group does not evict the others.
    salt_passbolt.fetch_passbolt_passwords(OTHER_GROUP_UUID)
    assert passbolt.clients[1].requests == 2


def test_fetch_does_not_serve_stale_pillar_when_refresh_fails(passbolt):
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    passbolt.now += 600
    passbolt.clients[0].secrets[RESOURCE_UUID] = RuntimeError("fetch failed")

    with pytest.raises(PassboltError, match=RESOURCE_UUID):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)


def test_fetch_wraps_login_connection_errors(passbolt, monkeypatch):
    def unreachable(self):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(CountingClient, "login", unreachable)
    with pytest.raises(PassboltError, match="Failed to reach the Passbolt server"):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    assert passbolt.clients[0].closed is True


def test_concurrent_renders_share_one_fetch(passbolt):
    threads = [
        threading.Thread(target=salt_passbolt.fetch_passbolt_passwords, args=(GROUP_UUID,))
        for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(passbolt.clients) == 1
    assert passbolt.clients[0].logins == 1
    assert passbolt.clients[0].requests == 2


def test_forked_child_starts_without_session_or_cache(passbolt):
    salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        clean = salt_passbolt._client is None and not salt_passbolt._cache
        os.write(write_end, b"1" if clean else b"0")
        os._exit(0)
    os.waitpid(pid, 0)
    assert os.read(read_end, 1) == b"1"
    assert salt_passbolt._client is passbolt.clients[0]


@pytest.mark.parametrize("value", ["-1", "ten", "1.5"])
def test_invalid_cache_ttl_raises(passbolt, value):
    passbolt.config["CACHE_TTL"] = value
    with pytest.raises(PassboltError, match="CACHE_TTL"):
        salt_passbolt.fetch_passbolt_passwords(GROUP_UUID)


def test_load_config_reads_cache_ttl(tmp_path):
    config_file = tmp_path / "passbolt.ini"
    config_file.write_text(CONFIG_FILE + "CACHE_TTL = 120\n")

    assert salt_passbolt.get_cache_ttl(load_config(str(config_file))) == 120
