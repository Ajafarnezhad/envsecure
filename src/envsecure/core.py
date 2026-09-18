"""Core encryption/decryption logic.

Uses Argon2id (via ``argon2-cffi``'s low-level API) to derive a Fernet key
from a password and a random per-file salt, following the OWASP Password
Storage Cheat Sheet's recommendation of Argon2id as the preferred key
derivation function. Fernet (AES-128-CBC + HMAC-SHA256) then provides
authenticated encryption of the file contents.
"""

from __future__ import annotations

import base64
import json
import os
import secrets

from argon2 import PasswordHasher, low_level
from argon2.exceptions import HashingError
from cryptography.fernet import Fernet, InvalidToken
from zxcvbn import zxcvbn

from .utils import get_logger

logger = get_logger(__name__)

ENCRYPTED_SUFFIX = ".envs"
SALT_SUFFIX = ".salt"


class EncryptionCore:
    """Encrypt and decrypt small files (``.env`` files) with a password-derived key."""

    def __init__(self, time_cost: int = 2, memory_cost: int = 102_400, parallelism: int = 8):
        self.ph = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)

    def validate_password(self, password: str, min_score: int = 3) -> bool:
        """Validate password strength using zxcvbn (score 0-4, 4 is strongest)."""
        result = zxcvbn(password)
        if result["score"] < min_score:
            logger.warning(
                "Weak password (score: %s). Suggestions: %s",
                result["score"],
                result["feedback"]["suggestions"],
            )
            return False
        return True

    @staticmethod
    def generate_salt(size: int = 16) -> bytes:
        return secrets.token_bytes(size)

    @staticmethod
    def _salt_path(filename: str) -> str:
        base = filename.removesuffix(ENCRYPTED_SUFFIX)
        return f"{base}{SALT_SUFFIX}"

    def _save_salt(self, filename: str, salt: bytes) -> str:
        # The salt file also records the exact Argon2 parameters used, not
        # just the salt bytes. Without this, decrypting with any
        # `EncryptionCore` constructed with different (e.g. updated default)
        # time_cost/memory_cost/parallelism silently derives the wrong key
        # and fails with `InvalidToken` -- indistinguishable from a wrong
        # password. Pinning the parameters alongside the salt makes
        # decryption independent of whatever the *current* defaults are.
        salt_path = self._salt_path(filename)
        payload = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "time_cost": self.ph.time_cost,
            "memory_cost": self.ph.memory_cost,
            "parallelism": self.ph.parallelism,
        }
        with open(salt_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        return salt_path

    def load_salt(self, filename: str) -> tuple[bytes, dict]:
        salt_file = self._salt_path(filename)
        if not os.path.exists(salt_file):
            raise FileNotFoundError(f"Salt file not found: {salt_file}")
        with open(salt_file, encoding="utf-8") as f:
            payload = json.load(f)
        salt = base64.b64decode(payload["salt"])
        params = {
            "time_cost": payload["time_cost"],
            "memory_cost": payload["memory_cost"],
            "parallelism": payload["parallelism"],
        }
        return salt, params

    def derive_key(self, password: str, salt: bytes, **kdf_params: int) -> bytes:
        time_cost = kdf_params.get("time_cost", self.ph.time_cost)
        memory_cost = kdf_params.get("memory_cost", self.ph.memory_cost)
        parallelism = kdf_params.get("parallelism", self.ph.parallelism)
        try:
            # `hash_secret_raw` (not `hash_secret`) is required here:
            # `hash_secret` returns Argon2's standard *encoded* hash string
            # (params + salt + hash all bundled together, e.g.
            # b"$argon2id$v=19$m=102400,t=2,p=8$...$..."), which is far
            # longer than 32 bytes and is not valid Fernet key material --
            # base64-encoding it and handing it to `Fernet()` raises
            # immediately. `hash_secret_raw` returns exactly the
            # `hash_len`-byte raw key we actually want.
            key = low_level.hash_secret_raw(
                password.encode(),
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=32,
                type=low_level.Type.ID,
            )
            return base64.urlsafe_b64encode(key)
        except HashingError:
            logger.exception("Key derivation failed")
            raise

    def generate_key(
        self,
        password: str,
        filename: str,
        load_existing_salt: bool = False,
        save_salt: bool = False,
    ) -> bytes:
        if load_existing_salt:
            salt, params = self.load_salt(filename)
            return self.derive_key(password, salt, **params)

        salt = self.generate_salt()
        if save_salt:
            salt_path = self._save_salt(filename, salt)
            logger.info("Salt saved to %s", salt_path)
        return self.derive_key(password, salt)

    def encrypt(self, filename: str, key: bytes, audit_log: bool = False) -> str:
        """Encrypt ``filename`` in place, writing ``<filename>.envs``.

        The original implementation processed the file in fixed-size 1MB
        chunks, calling ``Fernet.encrypt()`` on each chunk separately and
        concatenating the (variable-length, base64-encoded) tokens with no
        delimiters. ``decrypt()`` then tried to read back fixed-size slices,
        which only happens to work by coincidence for a file no bigger than
        one chunk -- for anything larger it reads misaligned byte ranges and
        raises ``InvalidToken``. Since this tool targets ``.env`` files
        (typically a few KB), we simply encrypt the whole file as one Fernet
        token; chunking a multi-megabyte secrets file was never a real
        requirement here.
        """
        fernet = Fernet(key)
        encrypted_file = f"{filename}{ENCRYPTED_SUFFIX}"
        try:
            with open(filename, "rb") as infile:
                data = infile.read()
            token = fernet.encrypt(data)
            with open(encrypted_file, "wb") as outfile:
                outfile.write(token)
            if audit_log:
                logger.info("Encrypted %s to %s", filename, encrypted_file)
            return "File encrypted successfully."
        except OSError:
            logger.exception("Encryption failed for %s", filename)
            raise

    def decrypt(
        self,
        filename: str,
        key: bytes,
        audit_log: bool = False,
        delete_source: bool = False,
    ) -> str:
        """Decrypt ``filename`` (a ``.envs`` file), writing the plaintext alongside it.

        ``delete_source`` defaults to ``False``. The original implementation
        *always* deleted the encrypted file and its salt immediately after a
        successful decrypt -- meaning the moment you decrypted your secrets
        to check them, you lost your only encrypted copy and the salt needed
        to ever re-derive its key. Pass ``delete_source=True`` explicitly if
        you really want that (e.g. a one-time "unwrap" workflow).
        """
        fernet = Fernet(key)
        decrypted_file = (
            filename[: -len(ENCRYPTED_SUFFIX)] if filename.endswith(ENCRYPTED_SUFFIX) else f"{filename}.decrypted"
        )
        try:
            with open(filename, "rb") as infile:
                token = infile.read()
            data = fernet.decrypt(token)
            with open(decrypted_file, "wb") as outfile:
                outfile.write(data)

            if delete_source:
                os.remove(filename)
                salt_file = self._salt_path(filename)
                if os.path.exists(salt_file):
                    os.remove(salt_file)

            if audit_log:
                logger.info("Decrypted %s to %s", filename, decrypted_file)
            return "File decrypted successfully."
        except InvalidToken:
            logger.error("Invalid password or corrupted file: %s", filename)
            raise
        except OSError:
            logger.exception("Decryption failed for %s", filename)
            raise


__all__ = ["ENCRYPTED_SUFFIX", "SALT_SUFFIX", "EncryptionCore"]
