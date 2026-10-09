import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from core import (
    classify_content,
    decrypt_text,
    encrypt_text,
    hash_passphrase,
    random_token,
)


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "clipboard_vault.sqlite3"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("CLIPBOARD_APP_SECRET", random_token())


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    with db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                kind TEXT NOT NULL,
                sensitivity TEXT NOT NULL,
                tags TEXT NOT NULL,
                summary TEXT NOT NULL,
                masked_preview TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                salt TEXT NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_used_at INTEGER
            )
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_items_kind ON items(kind)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_items_created ON items(created_at)")


def get_setting(con: sqlite3.Connection, key: str) -> str | None:
    row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(con: sqlite3.Connection, key: str, value: str) -> None:
    con.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
        (key, value),
    )


def verify_or_create_vault(con: sqlite3.Connection, passphrase: str) -> None:
    if not passphrase or len(passphrase) < 8:
        raise ValueError("Use a vault passphrase with at least 8 characters.")

    salt = get_setting(con, "vault_salt")
    verifier = get_setting(con, "vault_verifier")
    if not salt or not verifier:
        salt = random_token(16)
        verifier = hash_passphrase(passphrase, salt.encode("utf-8"))
        set_setting(con, "vault_salt", salt)
        set_setting(con, "vault_verifier", verifier)
        return

    if hash_passphrase(passphrase, salt.encode("utf-8")) != verifier:
        raise ValueError("Wrong vault passphrase.")


def item_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "kind": row["kind"],
        "sensitivity": row["sensitivity"],
        "tags": [x for x in row["tags"].split(",") if x],
        "summary": row["summary"],
        "masked_preview": row["masked_preview"],
        "favorite": bool(row["favorite"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_used_at": row["last_used_at"],
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    with db() as con:
        return jsonify(
            {
                "vault_exists": bool(get_setting(con, "vault_verifier")),
                "count": con.execute("SELECT COUNT(*) AS n FROM items").fetchone()["n"],
            }
        )


@app.post("/api/classify")
def classify():
    content = str(request.json.get("content", ""))
    result = classify_content(content)
    return jsonify(result.__dict__)


@app.get("/api/items")
def list_items():
    query = request.args.get("q", "").strip().lower()
    kind = request.args.get("kind", "").strip()
    params: list[object] = []
    clauses: list[str] = []

    if query:
        like = f"%{query}%"
        clauses.append(
            "(LOWER(title) LIKE ? OR LOWER(summary) LIKE ? OR LOWER(tags) LIKE ? OR LOWER(kind) LIKE ?)"
        )
        params.extend([like, like, like, like])
    if kind:
        clauses.append("kind = ?")
        params.append(kind)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT * FROM items
        {where}
        ORDER BY favorite DESC, updated_at DESC, id DESC
        LIMIT 250
    """
    with db() as con:
        rows = con.execute(sql, params).fetchall()
    return jsonify([item_to_dict(row) for row in rows])


@app.post("/api/items")
def create_item():
    payload = request.json or {}
    content = str(payload.get("content", "")).strip()
    passphrase = str(payload.get("passphrase", ""))
    if not content:
        return jsonify({"error": "Nothing to save."}), 400

    classification = classify_content(content)
    title = str(payload.get("title") or classification.summary or classification.kind).strip()
    raw_tags = payload.get("tags") or []
    user_tags = [str(tag).strip().lower() for tag in raw_tags if str(tag).strip()]
    tags = ",".join(list(dict.fromkeys(classification.tags + user_tags)))
    now = int(time.time())

    with db() as con:
        try:
            verify_or_create_vault(con, passphrase)
            salt, ciphertext = encrypt_text(content, passphrase)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 403

        cur = con.execute(
            """
            INSERT INTO items (
                title, kind, sensitivity, tags, summary, masked_preview,
                ciphertext, salt, favorite, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title[:120],
                classification.kind,
                classification.sensitivity,
                tags,
                classification.summary,
                classification.masked_preview,
                ciphertext,
                salt,
                1 if payload.get("favorite") else 0,
                now,
                now,
            ),
        )
        row = con.execute("SELECT * FROM items WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify(item_to_dict(row)), 201


@app.post("/api/items/<int:item_id>/reveal")
def reveal_item(item_id: int):
    passphrase = str((request.json or {}).get("passphrase", ""))
    with db() as con:
        row = con.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            return jsonify({"error": "Item not found."}), 404
        try:
            verify_or_create_vault(con, passphrase)
            content = decrypt_text(row["ciphertext"], row["salt"], passphrase)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 403
        now = int(time.time())
        con.execute("UPDATE items SET last_used_at = ? WHERE id = ?", (now, item_id))
    data = item_to_dict(row)
    data["content"] = content
    data["last_used_at"] = now
    return jsonify(data)


@app.patch("/api/items/<int:item_id>")
def update_item(item_id: int):
    payload = request.json or {}
    allowed = {}
    if "title" in payload:
        allowed["title"] = str(payload["title"]).strip()[:120]
    if "favorite" in payload:
        allowed["favorite"] = 1 if payload["favorite"] else 0
    if "tags" in payload:
        tags = [str(tag).strip().lower() for tag in payload["tags"] if str(tag).strip()]
        allowed["tags"] = ",".join(list(dict.fromkeys(tags)))

    if not allowed:
        return jsonify({"error": "No supported fields to update."}), 400

    allowed["updated_at"] = int(time.time())
    assignments = ", ".join(f"{key} = ?" for key in allowed.keys())
    values = list(allowed.values()) + [item_id]
    with db() as con:
        con.execute(f"UPDATE items SET {assignments} WHERE id = ?", values)
        row = con.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        return jsonify({"error": "Item not found."}), 404
    return jsonify(item_to_dict(row))


@app.delete("/api/items/<int:item_id>")
def delete_item(item_id: int):
    with db() as con:
        cur = con.execute("DELETE FROM items WHERE id = ?", (item_id,))
    if cur.rowcount == 0:
        return jsonify({"error": "Item not found."}), 404
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5057, debug=True)
