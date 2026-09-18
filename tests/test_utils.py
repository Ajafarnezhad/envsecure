from __future__ import annotations

from pathlib import Path

from envsecure.utils import get_logger, validate_file_extension


def test_get_logger_creates_log_file(tmp_path: Path):
    logger = get_logger("test_utils_creates_file", log_dir=str(tmp_path))
    logger.info("hello")
    assert (tmp_path / "envsecure.log").exists()


def test_get_logger_does_not_duplicate_handlers(tmp_path: Path):
    name = "test_utils_no_dupes"
    first = get_logger(name, log_dir=str(tmp_path))
    handler_count = len(first.handlers)

    second = get_logger(name, log_dir=str(tmp_path))

    assert second is first
    assert len(second.handlers) == handler_count


def test_validate_file_extension():
    assert validate_file_extension("secrets.env", ".env") is True
    assert validate_file_extension("secrets.txt", ".env") is False
