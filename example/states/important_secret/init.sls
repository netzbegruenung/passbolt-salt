important_secrets:
  file.managed:
    - name: /etc/secret.conf
    - source: salt://important_secrets/files/secret.conf
    - template: jinja

