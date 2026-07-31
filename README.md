# About
This Python module allows you to manage secrets for Saltstack via Passbolt. This makes managing secrets easier than manually encrypting them and storing the encrpyted password in the Saltstack repository.

Additionally, it is possible to only have one source of truth for passwords for users and IT infrastructure while being able to manage access for each password. That means that all users can contribute to the Saltack configuration and manage (view/add/change) secrets within their responsibility.

# License
[MIT](LICENSE)

# Production Setup

1. Install the `sq` CLI from [Sequoia PGP](https://sequoia-pgp.org/) on the Salt master. It performs
   all OpenPGP operations, both the Passbolt login and the decryption of secrets. The package name
   varies by distribution:
    - Debian 13 (trixie) and newer / Ubuntu 24.04 and newer: `apt install sq`
    - Older Debian/Ubuntu: install `sequoia-sq` from `contrib`/backports, or build from source
    - Arch Linux: `pacman -S sequoia-sq`
    - Other distros: build from source: https://gitlab.com/sequoia-pgp/sq

2. Install the module with `salt-pip`

    ```shell
    salt-pip install passbolt-salt
    ```

    This will install this module and its dependencies.

3. Create a Passbolt account for the Salt master.

4. Copy the private PGP key file to `/etc/salt`. No keyring import is needed; the key file is read
   directly.

5. Create a `/etc/salt/passbolt.ini` file with the following content:
    ```ini
    [PASSBOLT]
    SERVER = https://passbolt.example.com
    USER_PRIVATE_KEY_FILE = /etc/salt/passbolt_private.asc
    PASSPHRASE = [REPLACE WITH PASSBOLT USER PASSWORD]
    #USER_FINGERPRINT = [optional, derived from USER_PRIVATE_KEY_FILE if omitted]
    ```

6. Change file permissions:
    ```shell
    chown salt /etc/salt/passbolt*
    chmod 600 /etc/salt/passbolt*
    ```

Note that multi-factor authentication is not supported for the Salt master's Passbolt account.

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

# Failure Behaviour

Any failure aborts the pillar render for the affected minion with a `PassboltError`: an unreadable
`passbolt.ini`, a key file that `sq` cannot read, a rejected login, an unreachable server, a secret
that cannot be fetched or decrypted, and a secret whose password is empty.

This is deliberate. Skipping a secret would leave the pillar key absent, and states written as
`{{ pillar.get('passbolt', {}).get(uuid, '') }}` would then deploy an empty password instead of
failing. A failed render keeps the minion on its previous pillar and reports the reason in the
Salt master log.

A consequence worth knowing: a group whose secrets are all inaccessible to the Salt master's
Passbolt user fails the render rather than yielding an empty `passbolt` pillar.

# Performance

All OpenPGP operations are performed by the `sq` CLI, which runs in its own process per call. Unlike
GnuPG, there is no single `gpg-agent` to serialise on, so rendering pillars for many minions in
parallel is not bottlenecked on one process.

If pillar rendering is still too slow for your setup, enable the Pillar cache on the Salt master with
`pillar_cache: True` and refresh it periodically:
```
0 */12 * * * rm -rf /var/cache/salt/master/pillar_cache/* && salt '*' -b1 pillar.items
```

# Upgrading from 1.x

Version 2.0.0 replaced the `passbolt-python-api` dependency with a built-in Passbolt client and
dropped GnuPG support entirely:

- The `sq` CLI is now **required** on the Salt master.
- The private key no longer needs to be imported into a GnuPG keyring.
- `USER_FINGERPRINT` is now optional, and `USER_PUBLIC_KEY_FILE` / `SERVER_PUBLIC_KEY_FILE` are no
  longer used. Leaving them in `passbolt.ini` does no harm.
- MFA accounts are no longer supported (the previous static-OTP handling was not a real second
  factor).
- Failures now abort the pillar render instead of logging and continuing. In 1.x an unreachable
  server or an undecryptable secret could produce a pillar with the secret missing; see
  [Failure Behaviour](#failure-behaviour).
- `Python 3.9` or newer is required.

# YAML Replacement Structure
If the Passbolt server is not available, for example during local development, a file with the following format can replace the Python code from [Use Passwords of Passbolt Group in Pillar](#use-passwords-of-passbolt-group-in-pillar):
```yaml
passbolt:
  3ec2a739-8e51-4c67-89fb-4bbfe9147e17: MY_SECRET
```
