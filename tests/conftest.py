from __future__ import annotations

import pytest

from envsecure.core import EncryptionCore


@pytest.fixture
def core() -> EncryptionCore:
    # Low Argon2 costs so the test suite runs quickly.
    return EncryptionCore(time_cost=1, memory_cost=1024, parallelism=1)


@pytest.fixture
def temp_env_file(tmp_path) -> str:
    file = tmp_path / ".env"
    file.write_text("KEY=VALUE\nANOTHER_KEY=another value\n")
    return str(file)
