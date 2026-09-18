from __future__ import annotations

import os

import pytest
from cryptography.fernet import InvalidToken

from envsecure.core import EncryptionCore


def test_instance(core: EncryptionCore):
    assert isinstance(core, EncryptionCore)


def test_generate_key_is_valid_fernet_key(core: EncryptionCore, temp_env_file: str):
    key = core.generate_key("a-reasonable-password", temp_env_file, save_salt=True)
    assert isinstance(key, bytes)
    assert len(key) == 44  # base64-encoded 32 raw bytes, as Fernet requires


def test_encrypt_decrypt_roundtrip_preserves_content(core: EncryptionCore, temp_env_file: str):
    with open(temp_env_file) as f:
        original_content = f.read()
    password = "strongpassword123!"

    key = core.generate_key(password, temp_env_file, save_salt=True)
    core.encrypt(temp_env_file, key)

    encrypted_file = f"{temp_env_file}.envs"
    assert os.path.exists(encrypted_file)

    os.remove(temp_env_file)  # simulate a fresh checkout with only the encrypted file
    core.decrypt(encrypted_file, key)

    assert os.path.exists(temp_env_file)
    with open(temp_env_file) as f:
        assert f.read() == original_content


def test_decrypt_keeps_source_files_by_default(core: EncryptionCore, temp_env_file: str):
    password = "strongpassword123!"
    key = core.generate_key(password, temp_env_file, save_salt=True)
    core.encrypt(temp_env_file, key)
    encrypted_file = f"{temp_env_file}.envs"
    salt_file = f"{temp_env_file}.salt"

    core.decrypt(encrypted_file, key)

    # The original implementation deleted both of these unconditionally,
    # destroying your only encrypted backup the moment you decrypted it.
    assert os.path.exists(encrypted_file)
    assert os.path.exists(salt_file)


def test_decrypt_delete_source_removes_encrypted_and_salt(core: EncryptionCore, temp_env_file: str):
    password = "strongpassword123!"
    key = core.generate_key(password, temp_env_file, save_salt=True)
    core.encrypt(temp_env_file, key)
    encrypted_file = f"{temp_env_file}.envs"
    salt_file = f"{temp_env_file}.salt"

    core.decrypt(encrypted_file, key, delete_source=True)

    assert not os.path.exists(encrypted_file)
    assert not os.path.exists(salt_file)


def test_decrypt_with_wrong_password_raises(core: EncryptionCore, temp_env_file: str):
    password = "strongpassword123!"
    key = core.generate_key(password, temp_env_file, save_salt=True)
    core.encrypt(temp_env_file, key)

    wrong_key = core.generate_key("totally-different-password", temp_env_file, load_existing_salt=True)
    with pytest.raises(InvalidToken):
        core.decrypt(f"{temp_env_file}.envs", wrong_key)


def test_validate_password_strength(core: EncryptionCore):
    assert core.validate_password("weak", min_score=3) is False
    assert core.validate_password("Tr0ub4dor&3-xk9Q!mZp", min_score=3) is True


def test_large_file_roundtrips(core: EncryptionCore, tmp_path):
    # Regression test: the original chunked implementation only worked (by
    # coincidence) for files smaller than one 1MB chunk.
    big_file = tmp_path / "big.env"
    content = "SECRET=" + ("x" * (2 * 1024 * 1024)) + "\n"
    big_file.write_text(content)

    password = "strongpassword123!"
    key = core.generate_key(password, str(big_file), save_salt=True)
    core.encrypt(str(big_file), key)
    os.remove(big_file)

    core.decrypt(f"{big_file}.envs", key)
    assert big_file.read_text() == content
