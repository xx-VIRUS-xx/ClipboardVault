# Architecture

A small local application with two front ends over one shared core and one SQLite file. There is no server beyond localhost and no network dependency.

## System context

```
 macOS launchers                  Front ends                       Shared core            Storage
 Clipboard Vault.app  ----+
 Clipboard Vault.command -+--->  desktop_app.py (Tkinter)  --+
 python3 desktop_app.py         |  paste from system clipboard |
                                |  reveal dialog, copy         +--> core.py -------+
                                                                |    classify_content|--> clipboard_vault.sqlite3
 browser (127.0.0.1:5057) --->  app.py (Flask JSON API)  ------+    mask_secret      |    settings (vault salt + verifier)
   templates/index.html         static/app.js, styles.css            derive_key,      |    items (metadata + ciphertext)
                                                                     encrypt/decrypt  |
```

## Components

| Module | Responsibility |
|---|---|
| `core.py` | Pure logic. `classify_content` assigns a kind (empty, url, email, code, json, json-list, credential-json, secret, note), a sensitivity, tags, a summary and a masked preview. `mask_secret` hides the middle of a value. `derive_key`, `encrypt_text`, `decrypt_text` implement passphrase-based encryption. `hash_passphrase` produces the stored verifier |
| `app.py` | Flask app: `GET /api/status`, `POST /api/classify`, `GET/POST /api/items`, `POST /api/items/<id>/reveal`, `PATCH/DELETE /api/items/<id>`; serves the single page. Opens a SQLite connection per request |
| `static/app.js`, `templates/index.html` | Single-page UI: live classification while typing (debounced), search and kind filter, reveal dialog that auto-closes after 30 seconds, copy |
| `desktop_app.py` | Tkinter UI with the same features, plus reading the system clipboard directly. Contains its own copy of the schema, vault verification and item queries |
| `Clipboard Vault.app`, `.command` | Thin shell launchers that `cd` to the project folder and run `desktop_app.py` |
| `tests/test_core.py` | Unit tests for `core.py` |

## Data model

- `settings(key, value)`: holds `vault_salt` and `vault_verifier`.
- `items(id, title, kind, sensitivity, tags, summary, masked_preview, ciphertext, salt, favorite, created_at, updated_at, last_used_at)` with indexes on `kind` and `created_at`.

Only `ciphertext` holds the real content. Everything else is metadata the list and search use.

## Key flows

**Save.** Classify the content -> verify the passphrase against the stored verifier (or create the vault on first use) -> derive a key from the passphrase and a fresh random salt -> encrypt with Fernet -> insert metadata, ciphertext and salt.

**Search and list.** Query only metadata columns (`title`, `summary`, `tags`, `kind`) with LIKE; results show the masked preview, never the content.

**Reveal.** Verify the passphrase -> derive the key from the item's salt -> decrypt -> update `last_used_at` -> return content; the UI clears the dialog after 30 seconds. A wrong passphrase yields a generic error.

## Key design decisions

- **Passphrase is never stored.** The server keeps a PBKDF2-SHA256 verifier (390,000 iterations) with its own salt, and the request carries the passphrase every time it is needed. The process holds no unlocked state, so there is no session to steal.
- **Per-item salt.** Every item is encrypted under its own derived key, so identical content or a shared passphrase does not produce related ciphertexts.
- **Fernet for encryption.** Authenticated encryption from the `cryptography` package; tampering or a wrong key raises an error rather than returning garbage.
- **Metadata search only.** The list is searchable without decrypting anything, and secrets are masked in both preview and summary.
- **Classification by simple patterns.** Provider key prefixes, key-value assignments and any long token-like string are treated as secrets; false positives are preferred over leaks.
- **Local-only by default.** The Flask server binds to 127.0.0.1 and the database is a file next to the code (git-ignored).
- **Shared core, two thin front ends.** All security-relevant logic that is shared (classification, masking, encryption) lives in `core.py` and is unit tested.

## Known limitations

- Title and tags are plain text and are whatever the user types. Before the fix in commit "Fix: mask summary for secrets", a secret's first line was also stored unmasked in `summary` and used as the default title; databases created with earlier versions may still contain such rows.
- No passphrase change or re-encryption, and no recovery if the passphrase is lost.
- List, update and delete endpoints require no passphrase and there is no CSRF or origin check.
- Every save and reveal runs two key derivations (verify and derive), which is deliberately slow and also the only throttle on guessing.
- `app.py` runs with `debug=True` when started directly.
- Schema and vault code are duplicated between `app.py` and `desktop_app.py`.
- Revealed content is copied to the system clipboard and not cleared from it.
