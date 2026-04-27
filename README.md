# About
This Python module allows you to manage secrets for Saltstack via Passbolt. This makes managing secrets easier than manually encrypting them and storing the encrpyted password in the Saltstack repository.

Additionally, it is possible to only have one source of truth for passwords for users and IT infrastructure while being able to manage access for each password. That means that all users can contribute to the Saltack configuration and manage (view/add/change) secrets within their responsibility.

# License
[MIT](LICENSE)

# Production Setup

1. Go to your Salt master and install the module with `salt-pip`

    ```shell
    salt-pip install passbolt-salt
    ```

    This will install this module and its dependencies.

3. Create a Passbolt account for the Salt master.

4. Copy the private and public PGP key files to `/etc/salt`.

5. Import the new Passbolt private key on the Salt master:
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

# Use Passwords of Passbolt Group in Pillar
Look into the [example](example) directory to see how the integration is done.

1. Create Pillar sls files for the different Salt minions, insert the content below and replace the group UUID.
   ```python
   #!py
   def run():
       from salt_passbolt import fetch_passbolt_passwords
       return fetch_passbolt_passwords("27b9abd4-af9b-4c9e-9af1-cf8cb963680c")
   ```
   Hint: you can find the group UUID in the URL of the Passbolt admin interface when editing a group.

2. In a state, reference secrets with their UUID. See the `example/salt/important_secrets/files/secret.conf`.
   ```
   password={{ pillar['passbolt']['3ec2a739-8e51-4c67-89fb-4bbfe9147e17'] }}
   ```
   Hint: you can find the secret UUID in the URL of your browser by clicking on the checkbox of a secret.

# Performance

## Using Sequoia PGP (Recommended)

If the `sq` CLI from [Sequoia PGP](https://sequoia-pgp.org/) is available on your system, it will be used automatically for decryption. Sequoia is a modern, memory-safe reimplementation of OpenPGP that provides better parallelism than GnuPG.

**Benefits:**
- No gpg-agent bottleneck - each decryption runs in its own process
- Better performance when rendering pillars for many minions simultaneously
- Automatic fallback to GnuPG if Sequoia is not available

**Requirements:**
- Install the `sq` CLI (Sequoia command-line tool). The package name and availability vary by distribution:
  - Debian 13 (trixie) and newer / Ubuntu 24.04 and newer: `apt install sq`
  - Older Debian/Ubuntu: install `sequoia-sq` from `contrib`/backports, or build from source
  - Arch Linux: `pacman -S sequoia-sq`
  - Other distros: build from source: https://gitlab.com/sequoia-pgp/sq

## Using GnuPG (Fallback)

If Sequoia is not available, this module automatically falls back to GnuPG (`gpg-agent`).

**Known limitation:** When rendering pillars for many minions simultaneously, the single `gpg-agent` process can become a CPU bottleneck.

**Workaround:** Enable Pillar cache on the Salt master with `pillar_cache: True` and periodically update it:
```
0 */12 * * * rm -rf /var/cache/salt/master/pillar_cache/* && salt '*' -b1 pillar.items
```

# YAML Replacement Structure
If the Passbolt server is not available, for example during local development, a file with the following format can replace the Python code mentioned in step 8:
```yaml
passbolt:
  3ec2a739-8e51-4c67-89fb-4bbfe9147e17: MY_SECRET
```
