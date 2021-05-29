#!py
def run():
    passbolt_group = "27b9abd4-af9b-4c9e-9af1-cf8cb963680c"

    from os import path
    file_path = path.join(path.dirname(path.realpath(__file__)), passbolt_group + ".txt")
    if path.isfile(file_path):
        with open(file_path) as f:
            data = {"passbolt": {}}
            for line in f.readlines():
                data["passbolt"][line.split(':')[0]] = line.split(':')[1]
        return data
    else:
        from salt_passbolt import fetch_passbolt_passwords
        return fetch_passbolt_passwords(passbolt_group)
