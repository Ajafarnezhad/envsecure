from __future__ import annotations

import os

from typer.testing import CliRunner

from envsecure.cli import app

runner = CliRunner()


def test_encrypt_rejects_wrong_extension(tmp_path):
    bad_file = tmp_path / "secrets.txt"
    bad_file.write_text("KEY=VALUE")
    result = runner.invoke(app, ["encrypt", str(bad_file)])
    assert result.exit_code == 1
    assert "Invalid file extension" in result.output


def test_encrypt_rejects_weak_password(temp_env_file):
    result = runner.invoke(
        app,
        ["encrypt", temp_env_file, "--min-score", "3"],
        input="weak\nweak\n",
    )
    assert result.exit_code == 1
    assert "too weak" in result.output.lower()


def test_encrypt_then_decrypt_round_trip(temp_env_file):
    password = "Tr0ub4dor&3-xk9Q!mZp\n"
    encrypt_result = runner.invoke(app, ["encrypt", temp_env_file], input=password * 2)
    assert encrypt_result.exit_code == 0, encrypt_result.output

    os.remove(temp_env_file)
    encrypted_file = f"{temp_env_file}.envs"

    decrypt_result = runner.invoke(app, ["decrypt", encrypted_file], input=password)
    assert decrypt_result.exit_code == 0, decrypt_result.output
    assert os.path.exists(temp_env_file)
    # kept by default
    assert os.path.exists(encrypted_file)


def test_decrypt_wrong_password_reports_clean_error(temp_env_file):
    password = "Tr0ub4dor&3-xk9Q!mZp\n"
    runner.invoke(app, ["encrypt", temp_env_file], input=password * 2)
    encrypted_file = f"{temp_env_file}.envs"

    result = runner.invoke(app, ["decrypt", encrypted_file], input="wrong-password\n")
    assert result.exit_code == 1
    assert "Incorrect password" in result.output


def test_decrypt_rejects_wrong_extension(tmp_path):
    bad_file = tmp_path / "secrets.txt"
    bad_file.write_text("not encrypted")
    result = runner.invoke(app, ["decrypt", str(bad_file)])
    assert result.exit_code == 1
    assert "Invalid file extension" in result.output


def test_load_command_success(temp_env_file, monkeypatch):
    password = "Tr0ub4dor&3-xk9Q!mZp\n"
    runner.invoke(app, ["encrypt", temp_env_file], input=password * 2)
    encrypted_file = f"{temp_env_file}.envs"

    monkeypatch.delenv("KEY", raising=False)
    result = runner.invoke(app, ["load", encrypted_file], input=password)
    assert result.exit_code == 0
    assert "Loaded encrypted .env" in result.output


def test_load_command_wrong_password_reports_clean_error(temp_env_file):
    password = "Tr0ub4dor&3-xk9Q!mZp\n"
    runner.invoke(app, ["encrypt", temp_env_file], input=password * 2)
    encrypted_file = f"{temp_env_file}.envs"

    result = runner.invoke(app, ["load", encrypted_file], input="wrong-password\n")
    assert result.exit_code == 1
    assert "Incorrect password" in result.output
