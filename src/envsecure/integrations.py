"""Load an encrypted .env file's contents directly into ``os.environ``."""

from __future__ import annotations

import io

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from .core import EncryptionCore


def load_encrypted_env(filename: str, password: str) -> None:
    """Decrypt ``filename`` and load its contents into the process environment.

    Fixes two bugs in the original implementation:

    1. It referenced ``Fernet`` without importing it -- a guaranteed
       ``NameError`` on the very first call.
    2. It read only the first 1MB chunk of the encrypted file
       (``enc_file.read(1024 * 1024)``), silently truncating anything
       larger and relying on the same broken chunked-encryption scheme
       fixed in :mod:`envsecure.core`.

    It also avoids ever writing the decrypted secrets to a temporary file
    on disk (the original wrote ``<filename>.temp`` and deleted it
    afterwards) by decrypting into memory and handing python-dotenv an
    in-memory stream instead.
    """
    core = EncryptionCore()
    key = core.generate_key(password, filename, load_existing_salt=True)
    fernet = Fernet(key)

    with open(filename, "rb") as enc_file:
        token = enc_file.read()

    plaintext = fernet.decrypt(token).decode()
    load_dotenv(stream=io.StringIO(plaintext))


__all__ = ["load_encrypted_env"]
