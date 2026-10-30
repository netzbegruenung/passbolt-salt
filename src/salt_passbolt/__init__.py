"""
Provides functions to fetch passwords from passbolt api
"""
import configparser
import copy
import json
import logging
import os
import threading
import time
import uuid

from .api import PassboltClient, PassboltError
from .pgp_backend import SequoiaBackend

logger = logging.getLogger(__name__)

_CONFIG_PATH = "/etc/salt/passbolt.ini"
_DEFAULT_CACHE_TTL = 600

# Per-process state, kept between pillar renders. Salt imports this module once
# per master worker process, so every worker logs in once and caches on its own.
# Nothing here is ever written to disk.
_lock = threading.Lock()
_config = None
_client = None
_cache = {}


def _reset_state():
    """
    Forget the session and all cached pillars.

    Also registered as fork handler: a child must not share the parent's HTTP
    connection, nor inherit a lock some other thread of the parent held.
    """
    global _lock, _config, _client, _cache
    _lock = threading.Lock()
    _config = None
    _client = None
    _cache = {}


# Not available on Windows, where there is no fork either.
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_state)


def get_password_list(client: PassboltClient, group_uuid: str) -> list[dict]:
    """
    Get list of passwords for group UUID
    """
    result = list()
    url = ("/resources.json?filter[is-shared-with-group]" +
           "={}&api-version=v2".format(group_uuid))
    passwords = client.get(url)["body"]
    if not passwords:
        raise ValueError("Got empty password list from Passbolt server.")
    for i in passwords:
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
    return result


def generate_pillar(
    client: PassboltClient, backend: SequoiaBackend, group_uuid: str
) -> dict:
    """
    Generate dictionary that is added to the Pillar

    Every failure raises PassboltError. A secret that cannot be fetched,
    decrypted or is empty must never be silently omitted: states would then
    render with an empty password instead of failing.
    """
    try:
        result = get_password_list(client, group_uuid)
    except Exception as e:
        raise PassboltError(
            f"Failed to obtain the Passbolt object list for group {group_uuid}. Verify that "
            "the Salt master's Passbolt user has access to this group."
        ) from e
    salt = {'passbolt': {}}

    for i in result:
        try:
            resource = client.get("/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        except Exception as e:
            raise PassboltError(f"Failed to fetch secret {i['id']} ({i['name']}).") from e

        try:
            password = decode_json(backend.decrypt(resource["body"]["data"]))
        except ValueError as e:
            raise PassboltError(
                f"Passbolt returned an empty secret for {i['id']} ({i['name']}). "
                "Empty passwords are not allowed."
            ) from e
        except Exception as e:
            raise PassboltError(f"Failed to decrypt secret {i['id']} ({i['name']}).") from e
        salt['passbolt'][i["id"]] = password
    return salt


def decode_json(data: str) -> str:
    """
    The passbolt API returns legacy strings or JSON objects.
    Try to decode JSON. Raise exceptions if the password is empty
    or decoding fails.

    For (obvious) security reasons empty passwords are never allowed.
    """
    try:
        password = json.loads(data)["password"]
    except (ValueError, TypeError, KeyError):
        password = data
    if not password:
        raise ValueError("Empty passwords are not allowed.")
    return password


def load_config(config_path: str = _CONFIG_PATH) -> dict:
    """
    Load configuration from passbolt.ini file.

    Option names are upper-cased, because configparser lower-cases them while
    the documented config file spells them in upper case.

    Interpolation is disabled so that a `%` in the passphrase is taken
    literally instead of raising an interpolation error.

    Returns:
        Configuration dictionary
    """
    config = configparser.ConfigParser(interpolation=None)
    with open(config_path) as f:
        config.read_file(f)
    return {key.upper(): value for key, value in config["PASSBOLT"].items()}


def get_cache_ttl(config: dict) -> int:
    """
    Seconds a group's pillar is served from memory, from CACHE_TTL in
    passbolt.ini. 0 disables the cache.
    """
    value = config.get("CACHE_TTL", "").strip()
    if not value:
        return _DEFAULT_CACHE_TTL
    try:
        ttl = int(value)
    except ValueError:
        ttl = -1
    if ttl < 0:
        raise PassboltError(
            f"Invalid value for CACHE_TTL in {_CONFIG_PATH}: {value!r}. "
            "Use a number of seconds, or 0 to disable the cache."
        )
    return ttl


def fetch_passbolt_passwords(group_uuid: str) -> dict:
    """
    Generate Passbolt API object and call API fetch function

    Raises PassboltError on any failure, which aborts the pillar render. This
    is deliberate: returning a partial or empty pillar would let states deploy
    empty secrets whenever Passbolt is unreachable or the key is unusable.

    Results are cached in memory per group for CACHE_TTL seconds, and the
    Passbolt session is reused across calls. Failures are never cached, and an
    expired entry is never served when refreshing it fails.
    """
    global _config
    try:
        uuid.UUID(group_uuid, version=4)
    except ValueError as e:
        raise PassboltError(f"{group_uuid} is not a valid UUID.") from e

    try:
        config = load_config()
    except Exception as e:
        raise PassboltError(
            f"Failed to load the Passbolt configuration from {_CONFIG_PATH}."
        ) from e
    ttl = get_cache_ttl(config)

    # One render at a time per process: the requests session is not
    # thread-safe, and concurrent renders of the same group should share one
    # fetch instead of each logging in.
    with _lock:
        if config != _config:
            # First call, or passbolt.ini changed (other server, key or
            # passphrase): nothing from the old settings may be reused.
            _discard_client()
            _cache.clear()
            _config = config

        cached = _cache.get(group_uuid)
        if ttl and cached and cached[0] > time.monotonic():
            logger.debug(f"Serving cached passwords for group {group_uuid}")
            return copy.deepcopy(cached[1])

        logger.debug(f"Fetching passwords for group {group_uuid}")
        _cache.pop(group_uuid, None)
        pillar = _fetch(config, group_uuid)
        if ttl:
            _cache[group_uuid] = (time.monotonic() + ttl, pillar)
        # Hand out a copy, so Salt merging pillars cannot alter the cached one.
        return copy.deepcopy(pillar)


def _fetch(config: dict, group_uuid: str) -> dict:
    """
    Fetch a group's pillar with the process-wide client, logging in first if
    there is none yet. On any failure the client is dropped, so the next call
    starts with a fresh login.
    """
    global _client
    if _client is None:
        _client, backend = _new_client(config)
        login = True
    else:
        backend = _client.backend
        login = False

    try:
        if login:
            _client.login()
        return generate_pillar(_client, backend, group_uuid)
    except PassboltError:
        _discard_client()
        raise
    except Exception as e:
        _discard_client()
        raise PassboltError(
            f"Failed to reach the Passbolt server at {config.get('SERVER')}."
        ) from e


def _new_client(config: dict):
    key_file = config.get("USER_PRIVATE_KEY_FILE")
    if not key_file:
        raise PassboltError(f"Missing value for USER_PRIVATE_KEY_FILE in {_CONFIG_PATH}.")

    try:
        backend = SequoiaBackend(key_file=key_file, passphrase=config.get("PASSPHRASE"))
    except Exception as e:
        raise PassboltError(
            "Sequoia (sq) is required to decrypt Passbolt secrets. Install the sq CLI on "
            "the Salt master."
        ) from e

    # Constructed outside the request handling in _fetch, because reading the
    # key file happens here: those failures must not be reported as the server
    # being unreachable.
    try:
        client = PassboltClient(config, backend)
    except RuntimeError as e:
        raise PassboltError(f"Failed to read the PGP key from {key_file}: {e}") from e
    except Exception as e:
        raise PassboltError(f"Invalid Passbolt configuration in {_CONFIG_PATH}: {e}") from e
    return client, backend


def _discard_client():
    global _client
    if _client is not None:
        _client.close()
    _client = None
