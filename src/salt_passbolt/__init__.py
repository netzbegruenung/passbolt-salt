"""
Provides functions to fetch passwords from passbolt api
"""
import configparser
import json
import logging
import uuid

from .api import PassboltClient, PassboltError
from .pgp_backend import SequoiaBackend

logger = logging.getLogger(__name__)

_CONFIG_PATH = "/etc/salt/passbolt.ini"


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


def fetch_passbolt_passwords(group_uuid: str) -> dict:
    """
    Generate Passbolt API object and call API fetch function

    Raises PassboltError on any failure, which aborts the pillar render. This
    is deliberate: returning a partial or empty pillar would let states deploy
    empty secrets whenever Passbolt is unreachable or the key is unusable.
    """
    try:
        uuid.UUID(group_uuid, version=4)
    except ValueError as e:
        raise PassboltError(f"{group_uuid} is not a valid UUID.") from e
    logger.debug(f"Fetching passwords for group {group_uuid}")

    try:
        config = load_config()
    except Exception as e:
        raise PassboltError(
            f"Failed to load the Passbolt configuration from {_CONFIG_PATH}."
        ) from e

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

    # Constructed outside the request handling below, because reading the key
    # file happens here: those failures must not be reported as the server
    # being unreachable.
    try:
        client = PassboltClient(config, backend)
    except RuntimeError as e:
        raise PassboltError(f"Failed to read the PGP key from {key_file}: {e}") from e
    except Exception as e:
        raise PassboltError(f"Invalid Passbolt configuration in {_CONFIG_PATH}: {e}") from e

    try:
        client.login()
        return generate_pillar(client, backend, group_uuid)
    except PassboltError:
        raise
    except Exception as e:
        raise PassboltError(
            f"Failed to reach the Passbolt server at {config.get('SERVER')}."
        ) from e
    finally:
        client.close()
