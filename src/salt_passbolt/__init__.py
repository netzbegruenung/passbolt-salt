"""
Provides functions to fetch passwords from passbolt api
"""
import passboltapi  # pylint: disable=E0401


def get_password_list(passbolt_obj, group_uuid):
    """
    Get list of passwords for group UUID
    """
    result = list()
    url = ("/resources.json?filter[is-shared-with-group]" +
           "={}&api-version=v2".format(group_uuid))
    for i in passbolt_obj.get(url)["body"]:  # pylint: disable=C0301
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
    return result


def generate_pillar(passbolt_obj, group_uuid):
    """
    Generate dictionary that is added to the Pillar
    """
    result = get_password_list(passbolt_obj, group_uuid)
    salt = {'passbolt': {}}
    for i in result:
        resource = passbolt_obj.get("/secrets/resource/{}.json?api-version=v2".
                                    format(i["id"]))
        data = decode_json(passbolt_obj.decrypt(resource["body"]["data"]))
        assert data, "Passbolt returned an empty secret."
        salt['passbolt'][i["id"]] = data
    return salt


def decode_json(data):
    """
    The passbolt API returns legacy strings or JSON objects.
    Try to decode JSON, and if invalid return string.
    """
    import json
    try:
        data = json.loads(data)
    except json.decoder.JSONDecodeError:
        return data
    return data["password"]


def fetch_passbolt_passwords(group_uuid):
    """
    Generate Passbolt API object and call API fetch function
    """
    path = "/etc/salt/passbolt.ini"
    with passboltapi.PassboltAPI(config_path=path) as passbolt:
        salt = generate_pillar(passbolt, group_uuid)
    return salt
