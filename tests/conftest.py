import pathlib
import sys

# Make pgp_backend.py importable in isolation, without triggering
# salt_passbolt/__init__.py (which would pull in passboltapi).
sys.path.insert(
    0,
    str(pathlib.Path(__file__).resolve().parent.parent / "src" / "salt_passbolt"),
)
