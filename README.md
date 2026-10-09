# Clipboard Vault

A local vault for things you copy and need again but should not leave in plain text: API keys, tokens, JSON credentials, URLs, notes and snippets. Content is classified, a masked preview is shown in the list, and the full text is encrypted with a passphrase you supply. It runs as a macOS desktop app (Tkinter) or a browser app on localhost.

> This is a local convenience tool, not a team secrets manager. Do not sync the SQLite file through cloud drives, do not commit it, and use a real password manager for critical production credentials.

System design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Problem it addresses

Copied secrets end up in notes apps, chat windows and shell history in plain text. This keeps them in one place, encrypted at rest, searchable by safe metadata (title, tags, type, summary, masked preview), and revealed only when you enter the vault passphrase.

## Setup and run

Python 3.10 or newer. The desktop app needs Tkinter (bundled with most Python installs; on Homebrew Python install `python-tk`).

```bash
pip install -r requirements.txt
python3 desktop_app.py        # desktop app
python3 app.py                # browser app at http://127.0.0.1:5057
```

On macOS you can also double-click `Clipboard Vault.app` (if macOS blocks the unsigned app, right-click it and choose Open) or `Clipboard Vault.command`. Both launch `desktop_app.py` from the project folder.

## Behavior

- The first save creates the vault: your passphrase (at least 8 characters) is turned into a verifier that is stored, and the passphrase itself is never stored.
- Each item is encrypted at rest in `clipboard_vault.sqlite3` with a key derived from your passphrase and a random per-item salt.
- Search uses only metadata: title, tags, type, summary and masked preview. For items classified as secrets, the summary and preview are masked.
- Reveal requires the passphrase and clears the dialog after 30 seconds.
- Items are classified as url, email, code, JSON, credential JSON, secret or note using the patterns in `core.py`.

## Tests

```bash
python3 -m unittest discover -s tests
```

Six unit tests cover classification, masking (including that a secret never appears in the stored summary or preview) and the encrypt/decrypt round trip. The Flask routes and the desktop UI have no automated tests.

## Limitations and next steps

- Only the item content is encrypted. Title and tags are stored in plain text, including any you type yourself, so do not put secrets in them.
- The passphrase cannot be changed: there is no re-encryption path. The first passphrase you save with becomes the vault passphrase, so a typo on the first save is permanent.
- List, update and delete endpoints need no passphrase, and there is no origin or CSRF check. The server only binds to 127.0.0.1, but any local process or page that can reach it can list metadata or delete items.
- No lockout or rate limit on passphrase attempts beyond the cost of the key derivation (390,000 PBKDF2-SHA256 iterations, run on every save and reveal).
- `app.py` starts Flask with `debug=True`. Keep it to local use.
- Revealing copies content to the system clipboard; only the dialog is cleared, not the clipboard, so a clipboard history tool may keep it.
- Database setup and vault logic are duplicated between `app.py` and `desktop_app.py`; a shared module would remove the drift risk.
- `requirements.txt` pins `Flask==2.3.0` without pinning Werkzeug, and a fresh install pulls a Werkzeug version that breaks Flask's test client. Pin a compatible Werkzeug or upgrade Flask before writing route tests.
- No export, backup or import. No LICENSE yet.
