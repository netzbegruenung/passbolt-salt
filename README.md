# About
This Python module retrieves passwords for Passbolt groups to make them available in Saltstack Pillar.

# License
[MIT](LICENSE)

# Setup

1. Clone this repo 

2. Go to directory, run (requires `python3-setuptools`)
    ```shell
    python3 setup.py install
    ```
    This will install this module and its dependencies.

3. Create an Passbolt account for the Salt master.

4. Copy the private and public PGP key files to `/etc/salt`.

5. Import the private key with
    ```shell
    gpg --import /etc/salt/passbolt_private.asc
    ```

6. Create a `/etc/salt/passbolt.ini` file with the following content:
    ```ini
    [PASSBOLT]
    SERVER = https://passbolt.example.com
    #SERVER_PUBLIC_KEY_FILE = <optional: server_public.asc>
    USER_FINGERPRINT = [REPLACE WITH GPG KEY FINGERPRINT]
    USER_PUBLIC_KEY_FILE = /etc/salt/passbolt_public.asc
    USER_PRIVATE_KEY_FILE = /etc/salt/passbolt_private.asc
    PASSPHRASE = [REPLACE WITH PASSBOLT USER PASSWORD]
    ```

7. Change file permissions:
    ```shell
    chown salt /etc/salt/passbolt*
    chmod 600 /etc/salt/passbolt*
    ```

8. Create Pillar sls files for the different Salt minions. Use the example below as content for the sls files and replace the group UUID. Hint: you can find the group UUID in the URL of the Passbolt admin interface when editing a group.
    ```python
    #!py
    def run():
        from salt_passbolt import fetch_passbolt_passwords
        return fetch_passbolt_passwords("27b9abd4-af9b-4c9e-9af1-cf8cb963680c")
    ```
    You can also look into the [example](example) directory.
9. In state, reference secrets with their UUID. See the `example/salt/important_secrets/files/secret.conf`. Hint: you can find the secret UUID in the URL of your browser by clicking on the checkbox of a secret.
    ```
    password={{ pillar['passbolt']['3ec2a739-8e51-4c67-89fb-4bbfe9147e17'] }}
    ```

# YAML Replacement Structure

If the Passbolt server is not available, for example during local development, a file with the following format can replace the Python code mentioned in step 8:
```yaml
passbolt:
  3ec2a739-8e51-4c67-89fb-4bbfe9147e17: MY_SECRET
```
