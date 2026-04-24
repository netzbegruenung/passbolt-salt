"""
Provides functions to fetch passwords from passbolt api
"""
import json
import logging
import uuid

import passboltapi  # pylint: disable=E0401

logger = logging.getLogger(__name__)

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
    """
    try:
        result = get_password_list(passbolt_obj, group_uuid)
    except Exception as e:
        logger.error(f"Failed to obtain Passbolt object list for group {group_uuid}. Verify that the Salt Master Passbolt user has access to this group.")
        logger.exception(e)
        return {}
    salt = {'passbolt': {}}
    for i in result:
        try:
            resource = passbolt_obj.get("/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        except Exception as e:
            logger.error(f"Failed to fetch password {i['id']}.")
            logger.exception(e)
            continue
        try:
            password = decode_json(passbolt_obj.decrypt(resource["body"]["data"]))
        except ValueError as e:
            logger.warning(f"Passbolt returned an empty secret for {i['id']}. This secret is not added to the passbolt pillar.")
            continue
        except Exception as e:
            logger.error(f"Failed to decode password {i['id']}. It will not be added to the Pillar.")
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
    path = "/etc/salt/passbolt.ini"
    with passboltapi.PassboltAPI(config_path=path) as passbolt:
        salt = generate_pillar(passbolt, group_uuid)
    return salt
