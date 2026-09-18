# Security Policy

## Threat model

EnvSecure encrypts a `.env` file at rest using a password-derived key
(Argon2id + Fernet/AES). It protects secrets **stored on disk or committed
to a repository by mistake** from anyone who obtains the encrypted file
without the password. It does **not** protect secrets once they are
decrypted and loaded into a running process's environment, and it is not a
substitute for a dedicated secrets manager (Vault, AWS Secrets Manager,
etc.) in a production system with multiple services and rotation
requirements.

## Design notes

- Key derivation uses Argon2id (`argon2-cffi`'s `hash_secret_raw`), the
  function recommended by the OWASP Password Storage Cheat Sheet, with a
  random 16-byte salt per file.
- The Argon2 cost parameters (`time_cost`, `memory_cost`, `parallelism`)
  used at encryption time are stored alongside the salt (in `<file>.salt`,
  as JSON) so that decryption is not silently broken by a future change to
  this library's defaults.
- Encryption/decryption use `cryptography`'s `Fernet`, which provides
  authenticated encryption (AES-128-CBC + HMAC-SHA256) -- a corrupted or
  tampered ciphertext raises `InvalidToken` rather than silently decrypting
  to garbage.
- `envsecure decrypt` does **not** delete the encrypted file or its salt
  unless you pass `--delete-source` explicitly.
- Password strength is checked with `zxcvbn` before encryption (configurable
  via `--min-score`).

## Known limitations

- The password itself is never stored, but a weak or reused password
  remains the weakest link -- EnvSecure cannot detect password reuse across
  services.
- `envsecure load` decrypts into `os.environ` in the current process; any
  code running in that process (including other imported packages) can read
  those values, same as any other environment variable.
- The `<file>.salt` metadata file is not itself encrypted (it contains no
  secret material -- salt and cost parameters are not sensitive -- but it
  should still be kept alongside its corresponding `.envs` file).

## Reporting a vulnerability

Please open a private security advisory on this repository (GitHub →
Security → Report a vulnerability) rather than a public issue.
