# Changelog

## 1.1.0

Rewrite fixing real correctness and security bugs found in the 1.0.0
prototype:

- **Key derivation was silently broken.** `derive_key` called
  `argon2.low_level.hash_secret`, which returns Argon2's encoded hash
  *string* (params + salt + hash bundled together), not a raw key -- passing
  that (base64-encoded) to `Fernet()` raised immediately. Switched to
  `hash_secret_raw`.
- **Chunked encryption/decryption was broken for anything but trivially
  small files.** Encryption processed the file in fixed 1MB chunks and
  concatenated the resulting (variable-length) Fernet tokens with no
  delimiters; decryption then read back fixed-size slices that didn't align
  with token boundaries, raising `InvalidToken` for any file spanning more
  than one chunk. `.env` files are small, so encryption now simply
  processes the whole file as a single Fernet token.
- **`decrypt` destroyed its own inputs.** It unconditionally deleted the
  `.envs` file and its `.salt` file immediately after decrypting --
  checking your secrets once meant losing your only encrypted copy and the
  salt needed to ever re-derive its key. Deletion is now opt-in via
  `--delete-source`.
- **Argon2 parameters weren't persisted**, so decrypting with a differently
  configured `EncryptionCore` (e.g. after a future default change) derived
  the wrong key -- indistinguishable from a wrong password. The salt file
  now also records `time_cost`/`memory_cost`/`parallelism`.
- **`load_encrypted_env` referenced `Fernet` without importing it**
  (guaranteed `NameError`) and read only the first 1MB of the encrypted
  file. Fixed, and it no longer writes decrypted secrets to a temporary
  file on disk -- it decrypts into memory and hands python-dotenv an
  in-memory stream.
- **Logger duplicated handlers on every call**, multiplying every log line.
  Fixed to attach handlers once per logger name.
- Removed the `logging = "*"` line from dependencies (it's a standard
  library module, not a package to install) and switched packaging from
  Poetry (whose `docker/Dockerfile` referenced a `poetry.lock` that didn't
  exist in the repository) to a plain `pyproject.toml` + `pip`.
- Added a real pytest suite (core roundtrip, wrong-password handling, a
  >1MB file regression test, CLI end-to-end via Typer's `CliRunner`),
  `ruff` and `bandit` are clean, and CI runs both across Python 3.10-3.12.

Also dropped several stray files that had accumulated in the original
prototype's folder (a misnamed `.gitignore`, a debug log from a local
file-organizing script, and duplicate/misplaced config files) that had no
place in the published repository.
