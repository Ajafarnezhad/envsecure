"""Command-line interface."""

from __future__ import annotations

import typer
from cryptography.fernet import InvalidToken

from .core import ENCRYPTED_SUFFIX, EncryptionCore
from .integrations import load_encrypted_env
from .utils import prompt_password, validate_file_extension

app = typer.Typer(rich_markup_mode="rich", help="Encrypt and decrypt .env files at rest.")


@app.command()
def encrypt(
    filename: str = typer.Argument(..., help="The .env file to encrypt."),
    min_score: int = typer.Option(3, min=0, max=4, help="Minimum required password strength (0-4)."),
    audit_log: bool = typer.Option(False, help="Log this operation to envsecure.log."),
) -> None:
    """Encrypt a .env file, producing <filename>.envs and <filename>.salt."""
    if not validate_file_extension(filename, ".env"):
        typer.secho("Invalid file extension. Must be .env.", fg=typer.colors.RED)
        raise typer.Exit(1)

    password = prompt_password("Enter password for encryption: ")
    core = EncryptionCore()
    if not core.validate_password(password, min_score):
        typer.secho("Password too weak. Aborting.", fg=typer.colors.RED)
        raise typer.Exit(1)

    key = core.generate_key(password, filename, save_salt=True)
    result = core.encrypt(filename, key, audit_log)
    typer.secho(result, fg=typer.colors.GREEN)


@app.command()
def decrypt(
    filename: str = typer.Argument(..., help="The .envs file to decrypt."),
    audit_log: bool = typer.Option(False, help="Log this operation to envsecure.log."),
    delete_source: bool = typer.Option(
        False, help="Delete the .envs and .salt files after a successful decrypt."
    ),
) -> None:
    """Decrypt a .envs file back to its original filename."""
    if not validate_file_extension(filename, ENCRYPTED_SUFFIX):
        typer.secho(f"Invalid file extension. Must be {ENCRYPTED_SUFFIX}.", fg=typer.colors.RED)
        raise typer.Exit(1)

    password = prompt_password("Enter password for decryption: ", confirm=False)
    core = EncryptionCore()
    key = core.generate_key(password, filename, load_existing_salt=True)
    try:
        result = core.decrypt(filename, key, audit_log, delete_source=delete_source)
    except InvalidToken:
        typer.secho("Incorrect password or corrupted file.", fg=typer.colors.RED)
        raise typer.Exit(1) from None
    typer.secho(result, fg=typer.colors.GREEN)


@app.command()
def load(
    filename: str = typer.Argument(..., help="Encrypted .envs file to load."),
) -> None:
    """Decrypt an encrypted .env file and load it into the current environment."""
    password = prompt_password("Enter password to load .env: ", confirm=False)
    try:
        load_encrypted_env(filename, password)
    except InvalidToken:
        typer.secho("Incorrect password or corrupted file.", fg=typer.colors.RED)
        raise typer.Exit(1) from None
    typer.secho("Loaded encrypted .env into environment.", fg=typer.colors.GREEN)


if __name__ == "__main__":  # pragma: no cover
    app()
