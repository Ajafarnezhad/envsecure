# EnvSecure

[![CI](https://github.com/Ajafarnezhad/envsecure/actions/workflows/ci.yml/badge.svg)](https://github.com/Ajafarnezhad/envsecure/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

A small CLI that encrypts `.env` files at rest, so secrets never sit on disk
(or get committed to a repository) in plaintext. Keys are derived from a
password with Argon2id, per the OWASP Password Storage Cheat Sheet, and
files are encrypted with Fernet (authenticated AES-128-CBC + HMAC-SHA256).

## Why this project

A password-based file encryption tool is a good place to see whether the
cryptography is actually wired up correctly, because a bug here doesn't
just misbehave -- it either silently produces useless ciphertext, or
destroys the only copy of your secrets. Rewriting this from an earlier
prototype turned up exactly those two failure modes; see
[CHANGELOG.md](CHANGELOG.md) for the full list of what was fixed.

## What changed from the original prototype

- **Key derivation was silently broken**: it used the wrong argon2-cffi
  function (`hash_secret` instead of `hash_secret_raw`), producing key
  material `Fernet` rejects outright.
- **Chunked encryption broke on any file bigger than 1MB**: fixed-size
  chunks were encrypted independently and concatenated with no delimiters;
  decryption read misaligned byte ranges. Whole-file encryption replaces it
  (`.env` files are small; chunking added risk with no benefit).
- **`decrypt` used to delete your only encrypted backup and its salt**
  immediately after every successful decrypt. Now opt-in via
  `--delete-source`.
- **Argon2 cost parameters weren't persisted with the salt**, so decrypting
  with different parameters than at encryption time silently derived the
  wrong key. They're now stored alongside the salt.
- **`load_encrypted_env` referenced an unimported `Fernet`** (guaranteed
  crash) and wrote decrypted secrets to a temporary file on disk; it now
  decrypts in memory only.

## Installation

```bash
git clone https://github.com/Ajafarnezhad/envsecure.git
cd envsecure
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

Encrypt a `.env` file (prompts for a password, checked against `zxcvbn` for
strength):

```bash
envsecure encrypt .env
# -> writes .env.envs and .env.salt
```

Decrypt it back (source files are kept by default):

```bash
envsecure decrypt .env.envs
# -> writes .env; pass --delete-source to also remove .env.envs and .env.salt
```

Load an encrypted `.env` directly into the current process's environment,
without ever writing plaintext to disk:

```bash
envsecure load .env.envs
```

Run `envsecure --help` or `envsecure <command> --help` for all options.

### Programmatic use

```python
from envsecure.core import EncryptionCore

core = EncryptionCore()
key = core.generate_key("a strong password", ".env", save_salt=True)
core.encrypt(".env", key)
...
core.decrypt(".env.envs", key)  # writes .env; keeps .env.envs and .env.salt
```

## What gets committed to version control

Never commit `.env`, `.env.envs`, or `.env.salt` files with real secrets to
a public repository -- `.env.envs`/`.env.salt` are safe *in principle*
(they're encrypted, and the salt/params aren't secret), but treat committing
them as a deliberate, reviewed decision, not a default. The bundled
`.gitignore` excludes all three.

## Project layout

```
envsecure/
├── src/envsecure/
│   ├── core.py           # Argon2id key derivation + Fernet encrypt/decrypt
│   ├── integrations.py   # load an encrypted .env into os.environ
│   ├── cli.py            # Typer CLI: encrypt / decrypt / load
│   └── utils.py          # logging, password prompt, extension checks
├── tests/                # pytest suite (core, integrations, CLI)
├── docker/               # Dockerfile + docker-compose.yaml
├── .github/workflows/ci.yml
├── SECURITY.md           # threat model, design notes, known limitations
└── CHANGELOG.md
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
bandit -r src/ -ll
pytest --cov=envsecure --cov-report=term-missing
```

CI runs the same lint, Bandit, and test suite (100% line coverage enforced)
on every push and pull request across Python 3.10–3.12.

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Amirhossein Jafarnezhad** — [github.com/Ajafarnezhad](https://github.com/Ajafarnezhad)
