from __future__ import annotations

import os

from envsecure.core import EncryptionCore
from envsecure.integrations import load_encrypted_env


def test_load_encrypted_env_sets_environment(temp_env_file, monkeypatch):
    core = EncryptionCore(time_cost=1, memory_cost=1024, parallelism=1)
    password = "strongpassword123!"
    key = core.generate_key(password, temp_env_file, save_salt=True)
    core.encrypt(temp_env_file, key)
    encrypted_file = f"{temp_env_file}.envs"

    monkeypatch.delenv("KEY", raising=False)
    load_encrypted_env(encrypted_file, password)

    assert os.environ["KEY"] == "VALUE"
    assert os.environ["ANOTHER_KEY"] == "another value"


def test_load_encrypted_env_does_not_write_plaintext_to_disk(temp_env_file, tmp_path):
    core = EncryptionCore(time_cost=1, memory_cost=1024, parallelism=1)
    password = "strongpassword123!"
    key = core.generate_key(password, temp_env_file, save_salt=True)
    core.encrypt(temp_env_file, key)
    encrypted_file = f"{temp_env_file}.envs"

    load_encrypted_env(encrypted_file, password)

    # The original implementation wrote `<filename>.temp` to disk; confirm
    # no such artifact is left behind.
    leftovers = [p for p in os.listdir(os.path.dirname(temp_env_file)) if p.endswith(".temp")]
    assert leftovers == []
