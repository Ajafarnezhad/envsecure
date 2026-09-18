"""Small shared helpers: logging, password prompting, and file-extension checks."""

from __future__ import annotations

import logging
import os

import typer


def get_logger(name: str, *, log_dir: str = ".", level: int = logging.INFO) -> logging.Logger:
    """Return a logger that writes to ``<log_dir>/envsecure.log`` and stderr.

    The original implementation called ``logging.FileHandler("envsecure.log")``
    and attached a fresh handler on *every* call to ``get_logger`` -- since
    every module in this package calls it once at import time, and pytest
    re-imports modules across test runs, this multiplied every log line by
    the number of times the logger had been requested. Handlers are now
    attached exactly once per logger name.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(os.path.join(log_dir, "envsecure.log"), encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def prompt_password(prompt: str, *, confirm: bool = True) -> str:
    return typer.prompt(prompt, hide_input=True, confirmation_prompt=confirm)


def validate_file_extension(filename: str, expected_ext: str) -> bool:
    return filename.endswith(expected_ext)


__all__ = ["get_logger", "prompt_password", "validate_file_extension"]
