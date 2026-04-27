"""
Provides functions to fetch passwords from passbolt api
"""
import configparser
import json
import logging
import uuid

import passboltapi  # pylint: disable=E0401

from .pgp_backend import SequoiaBackend

logger = logging.getLogger(__name__)

_CONFIG_PATH = "/etc/salt/passbolt.ini"
_backend_cache = None
_backend_probed = False


def _get_backend():
    """
    Return the cached SequoiaBackend, probing once per process.

    Returns None if sq is unavailable or the config cannot be loaded; callers
    must fall back to passbolt-python-api's GnuPG decryption.
    """
    global _backend_cache, _backend_probed
    if _backend_probed:
        return _backend_cache
    _backend_probed = True
    try:
        config = load_config()
        _backend_cache = SequoiaBackend(
            key_file=config.get("USER_PRIVATE_KEY_FILE"),
            passphrase=config.get("PASSPHRASE"),
        )
        logger.info("Using Sequoia (sq) for decryption.")
    except Exception as e:
        logger.info(f"Sequoia backend unavailable, using GnuPG fallback: {e}")
    return _backend_cache

def get_password_list(passbolt_obj: passboltapi.PassboltAPI, group_uuid: str) -> list[dict]:
    """
    Get list of passwords for group UUID
    """
    result = list()
    url = ("/resources.json?filter[is-shared-with-group]" +
           "={}&api-version=v2".format(group_uuid))
    passwords = passbolt_obj.get(url)["body"]
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


def generate_pillar(passbolt_obj: passboltapi.PassboltAPI, group_uuid: str) -> dict:
    """
    Generate dictionary that is added to the Pillar

    Uses Sequoia backend (sq CLI) if available for better parallelism,
    falls back to GnuPG (gpg-agent) if Sequoia is not available.
    """
    try:
        result = get_password_list(passbolt_obj, group_uuid)
    except Exception as e:
        logger.error(f"Failed to obtain Passbolt object list for group {group_uuid}. Verify that the Salt Master Passbolt user has access to this group.")
        logger.exception(e)
        return {}
    salt = {'passbolt': {}}
    backend = _get_backend()

    for i in result:
        try:
            resource = passbolt_obj.get("/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        except Exception as e:
            logger.error(f"Failed to fetch password {i['id']}.")
            logger.exception(e)
            continue

        try:
            encrypted_data = resource["body"]["data"]
            if backend is not None:
                try:
                    decrypted = backend.decrypt(encrypted_data)
                except Exception as e:
                    logger.warning(f"Sequoia decryption failed for {i['id']}, falling back to GnuPG: {e}")
                    decrypted = passbolt_obj.decrypt(encrypted_data)
            else:
                decrypted = passbolt_obj.decrypt(encrypted_data)
            password = decode_json(decrypted)
        except ValueError as e:
            logger.warning(f"Passbolt returned an empty secret for {i['id']}. This secret is not added to the passbolt pillar.")
            continue
        except Exception as e:
            logger.error(f"Failed to decode password {i['id']}. It will not be added to the Pillar.")
            logger.exception(e)
            continue
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
        data = json.loads(data)
        password = data["password"]
    except Exception as e:
        logger.exception(e)
        raise e
    if not password:
        raise ValueError("Empty passwords are not allowed.")
    return password


def load_config(config_path: str = _CONFIG_PATH) -> dict:
    """
    Load configuration from passbolt.ini file.

    Returns:
        Configuration dictionary
    """
    config = configparser.ConfigParser()
    with open(config_path) as f:
        config.read_file(f)
    return dict(config["PASSBOLT"])


def fetch_passbolt_passwords(group_uuid: str) -> dict:
    """
    Generate Passbolt API object and call API fetch function
    """
    try:
        uuid_obj = uuid.UUID(group_uuid, version=4)
    except ValueError:
        logger.error(f"{group_uuid} is not a valid UUID.")
        return {}
    logger.debug(f"Fetching passwords for group {group_uuid}")
    with passboltapi.PassboltAPI(config_path=_CONFIG_PATH) as passbolt:
        salt = generate_pillar(passbolt, group_uuid)
    return salt
