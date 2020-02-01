# passbolt-salt
Script to retrieve Passbolt passwords for Saltstack Pillars

# Installation

1. Clone this repo 

2. Go to directory, run
    ```
    python3 setup.py
    ```

3. Create an Passbolt account for the Salt master.

4. Copy the private and public PGP key files to `/etc/salt`.

5. Create a `/etc/salt/passbolt.ini` file with the following content:
    ```
    [PASSBOLT]
    SERVER = https://pass.netzbegruenung.de
    #SERVER_PUBLIC_KEY_FILE = <optional: server_public.asc>
    USER_FINGERPRINT = [REPLACE WITH GPG KEY FINGERPRINT]
    USER_PUBLIC_KEY_FILE = /etc/salt/passbolt_public.asc
    USER_PRIVATE_KEY_FILE = /etc/salt/passbolt_private.asc
    PASSPHRASE = [REPLACE WITH PASSBOLT USER PASSWORD]
    ```

6. Change file permissions:
    ```
    chown salt /etc/salt/passbolt*
    chmod 600 /etc/salt/passbolt*
    ```

7. Create Pillar sls files where required with the content, replace the group UUID. Look into the example directory. Hint: you can find the Group UUID with the network tool of the browser by clicking on a group.
    ```
    #!py
    fetch_passbolt_passwords("27b9abd4-af9b-4c9e-9af1-cf8cb963680c")
    ```

8. In state, reference secrets with their UUID. See the `example/salt/important_secrets/files/secret.conf`. Hint: you can find the secret UUID in the URL of your browser by clicking on the checkbox of a secret.
    ```
    password={{ pillar['passbolt']['3ec2a739-8e51-4c67-89fb-4bbfe9147e17'] }}
    ```

