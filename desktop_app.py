import sqlite3
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from core import (
    classify_content,
    decrypt_text,
    encrypt_text,
    hash_passphrase,
    random_token,
)


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "clipboard_vault.sqlite3"


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
    con.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, value))


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


def row_to_item(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "kind": row["kind"],
        "sensitivity": row["sensitivity"],
        "tags": row["tags"],
        "summary": row["summary"],
        "masked_preview": row["masked_preview"],
        "favorite": bool(row["favorite"]),
        "updated_at": row["updated_at"],
        "last_used_at": row["last_used_at"],
    }


def save_item(content: str, passphrase: str, title: str, tags: list[str], favorite: bool) -> dict:
    classification = classify_content(content)
    title = (title or classification.summary or classification.kind).strip()[:120]
    merged_tags = list(dict.fromkeys(classification.tags + tags))
    salt, ciphertext = encrypt_text(content, passphrase)
    now = int(time.time())

    with db() as con:
        verify_or_create_vault(con, passphrase)
        cur = con.execute(
            """
            INSERT INTO items (
                title, kind, sensitivity, tags, summary, masked_preview,
                ciphertext, salt, favorite, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                classification.kind,
                classification.sensitivity,
                ",".join(merged_tags),
                classification.summary,
                classification.masked_preview,
                ciphertext,
                salt,
                1 if favorite else 0,
                now,
                now,
            ),
        )
        row = con.execute("SELECT * FROM items WHERE id = ?", (cur.lastrowid,)).fetchone()
    return row_to_item(row)


def list_items(query: str = "") -> list[dict]:
    query = query.strip().lower()
    params: list[object] = []
    where = ""
    if query:
        like = f"%{query}%"
        where = """
            WHERE LOWER(title) LIKE ?
               OR LOWER(summary) LIKE ?
               OR LOWER(tags) LIKE ?
               OR LOWER(kind) LIKE ?
        """
        params = [like, like, like, like]

    with db() as con:
        rows = con.execute(
            f"""
            SELECT * FROM items
            {where}
            ORDER BY favorite DESC, updated_at DESC, id DESC
            LIMIT 500
            """,
            params,
        ).fetchall()
    return [row_to_item(row) for row in rows]


def reveal_item(item_id: int, passphrase: str) -> str:
    with db() as con:
        row = con.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not row:
            raise ValueError("Item not found.")
        verify_or_create_vault(con, passphrase)
        content = decrypt_text(row["ciphertext"], row["salt"], passphrase)
        con.execute(
            "UPDATE items SET last_used_at = ? WHERE id = ?",
            (int(time.time()), item_id),
        )
        return content


def update_favorite(item_id: int, favorite: bool) -> None:
    with db() as con:
        con.execute(
            "UPDATE items SET favorite = ?, updated_at = ? WHERE id = ?",
            (1 if favorite else 0, int(time.time()), item_id),
        )


def delete_item(item_id: int) -> None:
    with db() as con:
        con.execute("DELETE FROM items WHERE id = ?", (item_id,))


class ClipboardVaultApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Clipboard Vault")
        self.geometry("1120x720")
        self.minsize(920, 620)
        self.items_by_tree_id: dict[str, dict] = {}
        self.revealed_content = ""
        self.reveal_window: tk.Toplevel | None = None

        self._configure_style()
        self._build()
        self.refresh_items()

    def _configure_style(self) -> None:
        self.configure(bg="#f5f7f4")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f5f7f4")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f5f7f4", foreground="#1c2420")
        style.configure("Panel.TLabel", background="#ffffff", foreground="#1c2420")
        style.configure("Muted.TLabel", background="#ffffff", foreground="#647067")
        style.configure("TButton", padding=(10, 7))
        style.configure("Treeview", rowheight=32, font=("Helvetica", 12))
        style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"))

    def _build(self) -> None:
        self.columnconfigure(0, weight=0, minsize=420)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        left = ttk.Frame(self, style="Panel.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(14, 7), pady=14)
        left.columnconfigure(0, weight=1)

        right = ttk.Frame(self, style="Panel.TFrame", padding=16)
        right.grid(row=0, column=1, sticky="nsew", padx=(7, 14), pady=14)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(3, weight=1)

        ttk.Label(left, text="Clipboard Vault", style="Panel.TLabel", font=("Helvetica", 26, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            left,
            text="Local encrypted storage for copied API keys, tokens, notes, URLs, and snippets.",
            style="Muted.TLabel",
            wraplength=360,
        ).grid(row=1, column=0, sticky="w", pady=(4, 12))

        self.passphrase_var = tk.StringVar()
        self._label(left, "Vault passphrase", 2)
        ttk.Entry(left, textvariable=self.passphrase_var, show="*").grid(row=3, column=0, sticky="ew")

        button_row = ttk.Frame(left, style="Panel.TFrame")
        button_row.grid(row=4, column=0, sticky="ew", pady=12)
        ttk.Button(button_row, text="Read Mac Clipboard", command=self.read_clipboard).pack(side="left")
        ttk.Button(button_row, text="Classify", command=self.classify_current).pack(side="left", padx=8)

        self.content = tk.Text(left, height=14, wrap="word", undo=True, font=("Menlo", 12))
        self.content.grid(row=5, column=0, sticky="nsew")
        left.rowconfigure(5, weight=1)

        self.pipeline_var = tk.StringVar(value="Waiting for content")
        ttk.Label(left, textvariable=self.pipeline_var, style="Muted.TLabel", wraplength=380).grid(
            row=6, column=0, sticky="ew", pady=(10, 0)
        )

        self.title_var = tk.StringVar()
        self.tags_var = tk.StringVar()
        self.favorite_var = tk.BooleanVar()
        self._label(left, "Title", 7)
        ttk.Entry(left, textvariable=self.title_var).grid(row=8, column=0, sticky="ew")
        self._label(left, "Tags", 9)
        ttk.Entry(left, textvariable=self.tags_var).grid(row=10, column=0, sticky="ew")
        ttk.Checkbutton(left, text="Favorite", variable=self.favorite_var).grid(row=11, column=0, sticky="w", pady=(8, 0))
        ttk.Button(left, text="Save Encrypted Item", command=self.save_current).grid(
            row=12, column=0, sticky="ew", pady=(12, 0)
        )

        ttk.Label(right, text="Saved Items", style="Panel.TLabel", font=("Helvetica", 22, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        self.search_var = tk.StringVar()
        search = ttk.Entry(right, textvariable=self.search_var)
        search.grid(row=1, column=0, sticky="ew", pady=(10, 10))
        search.bind("<KeyRelease>", lambda _event: self.refresh_items())

        actions = ttk.Frame(right, style="Panel.TFrame")
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(actions, text="Reveal", command=self.reveal_selected).pack(side="left")
        ttk.Button(actions, text="Copy", command=self.copy_selected).pack(side="left", padx=8)
        ttk.Button(actions, text="Favorite", command=self.toggle_favorite_selected).pack(side="left")
        ttk.Button(actions, text="Delete", command=self.delete_selected).pack(side="left", padx=8)

        columns = ("title", "kind", "sensitivity", "preview", "updated")
        self.tree = ttk.Treeview(right, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("title", text="Title")
        self.tree.heading("kind", text="Type")
        self.tree.heading("sensitivity", text="Risk")
        self.tree.heading("preview", text="Masked Preview")
        self.tree.heading("updated", text="Updated")
        self.tree.column("title", width=220, anchor="w")
        self.tree.column("kind", width=120, anchor="w")
        self.tree.column("sensitivity", width=80, anchor="w")
        self.tree.column("preview", width=260, anchor="w")
        self.tree.column("updated", width=145, anchor="w")
        self.tree.grid(row=3, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", lambda _event: self.reveal_selected())

        yscroll = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=3, column=1, sticky="ns")

    def _label(self, parent: ttk.Frame, text: str, row: int) -> None:
        ttk.Label(parent, text=text, style="Muted.TLabel").grid(row=row, column=0, sticky="w", pady=(10, 4))

    def selected_item(self) -> dict | None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Clipboard Vault", "Select a saved item first.")
            return None
        return self.items_by_tree_id[selected[0]]

    def read_clipboard(self) -> None:
        try:
            value = self.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Clipboard Vault", "The Mac clipboard does not contain readable text.")
            return
        self.content.delete("1.0", "end")
        self.content.insert("1.0", value)
        self.classify_current()

    def classify_current(self) -> None:
        value = self.content.get("1.0", "end").strip()
        if not value:
            self.pipeline_var.set("Waiting for content")
            return
        result = classify_content(value)
        tags = ", ".join(result.tags) if result.tags else "none"
        self.pipeline_var.set(
            f"Type: {result.kind} | Sensitivity: {result.sensitivity} | Tags: {tags} | Preview: {result.masked_preview}"
        )
        if not self.title_var.get().strip():
            self.title_var.set(result.summary)
        if not self.tags_var.get().strip() and result.tags:
            self.tags_var.set(", ".join(result.tags))

    def save_current(self) -> None:
        content = self.content.get("1.0", "end").strip()
        passphrase = self.passphrase_var.get()
        tags = [tag.strip().lower() for tag in self.tags_var.get().split(",") if tag.strip()]
        try:
            save_item(content, passphrase, self.title_var.get(), tags, self.favorite_var.get())
        except ValueError as exc:
            messagebox.showerror("Clipboard Vault", str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Clipboard Vault", f"Could not save item: {exc}")
            return

        self.content.delete("1.0", "end")
        self.title_var.set("")
        self.tags_var.set("")
        self.favorite_var.set(False)
        self.pipeline_var.set("Saved encrypted item.")
        self.refresh_items()

    def refresh_items(self) -> None:
        self.items_by_tree_id.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in list_items(self.search_var.get()):
            label = f"* {item['title']}" if item["favorite"] else item["title"]
            tree_id = self.tree.insert(
                "",
                "end",
                values=(
                    label,
                    item["kind"],
                    item["sensitivity"],
                    item["masked_preview"],
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(item["updated_at"])),
                ),
            )
            self.items_by_tree_id[tree_id] = item

    def reveal_selected(self) -> None:
        item = self.selected_item()
        if not item:
            return
        try:
            content = reveal_item(item["id"], self.passphrase_var.get())
        except ValueError as exc:
            messagebox.showerror("Clipboard Vault", str(exc))
            return
        self.revealed_content = content
        self.refresh_items()
        self.show_reveal_window(item, content)

    def show_reveal_window(self, item: dict, content: str) -> None:
        if self.reveal_window and self.reveal_window.winfo_exists():
            self.reveal_window.destroy()

        win = tk.Toplevel(self)
        win.title(f"Reveal - {item['title']}")
        win.geometry("760x420")
        win.configure(bg="#ffffff")
        win.columnconfigure(0, weight=1)
        win.rowconfigure(1, weight=1)
        self.reveal_window = win

        ttk.Label(win, text=item["title"], font=("Helvetica", 18, "bold")).grid(
            row=0, column=0, sticky="w", padx=14, pady=(14, 8)
        )
        text = tk.Text(win, wrap="word", font=("Menlo", 12))
        text.grid(row=1, column=0, sticky="nsew", padx=14)
        text.insert("1.0", content)
        text.configure(state="disabled")

        buttons = ttk.Frame(win)
        buttons.grid(row=2, column=0, sticky="ew", padx=14, pady=14)
        ttk.Button(buttons, text="Copy to Mac Clipboard", command=self.copy_revealed).pack(side="left")
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="left", padx=8)

        win.after(30_000, self.clear_reveal_window)

    def clear_reveal_window(self) -> None:
        self.revealed_content = ""
        if self.reveal_window and self.reveal_window.winfo_exists():
            self.reveal_window.destroy()

    def copy_revealed(self) -> None:
        if not self.revealed_content:
            return
        self.clipboard_clear()
        self.clipboard_append(self.revealed_content)
        self.update()
        self.clear_reveal_window()
        messagebox.showinfo("Clipboard Vault", "Copied to Mac clipboard and cleared reveal window.")

    def copy_selected(self) -> None:
        item = self.selected_item()
        if not item:
            return
        try:
            content = reveal_item(item["id"], self.passphrase_var.get())
        except ValueError as exc:
            messagebox.showerror("Clipboard Vault", str(exc))
            return
        self.clipboard_clear()
        self.clipboard_append(content)
        self.update()
        self.refresh_items()
        messagebox.showinfo("Clipboard Vault", "Copied to Mac clipboard.")

    def toggle_favorite_selected(self) -> None:
        item = self.selected_item()
        if not item:
            return
        update_favorite(item["id"], not item["favorite"])
        self.refresh_items()

    def delete_selected(self) -> None:
        item = self.selected_item()
        if not item:
            return
        if not messagebox.askyesno("Clipboard Vault", f"Delete '{item['title']}'?"):
            return
        delete_item(item["id"])
        self.refresh_items()


def main() -> None:
    init_db()
    app = ClipboardVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
