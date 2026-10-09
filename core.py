import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KDF_ITERATIONS = 390_000


SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9_-]{32,}\b"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|bearer)\b\s*[:=]"),
]


@dataclass(frozen=True)
class Classification:
    kind: str
    sensitivity: str
    tags: list[str]
    summary: str
    masked_preview: str


def random_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def hash_passphrase(passphrase: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, KDF_ITERATIONS
    )
    return base64.urlsafe_b64encode(digest).decode("ascii")


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_text(text: str, passphrase: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    token = Fernet(derive_key(passphrase, salt)).encrypt(text.encode("utf-8"))
    return base64.urlsafe_b64encode(salt).decode("ascii"), token.decode("ascii")


def decrypt_text(ciphertext: str, salt_b64: str, passphrase: str) -> str:
    salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
    try:
        data = Fernet(derive_key(passphrase, salt)).decrypt(ciphertext.encode("ascii"))
    except InvalidToken as exc:
        raise ValueError("Bad passphrase or corrupted item") from exc
    return data.decode("utf-8")


def mask_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    if len(value) <= 18:
        return f"{value[:3]}...{value[-3:]}"
    return f"{value[:6]}...{value[-4:]}"


def _json_kind(content: str) -> str | None:
    try:
        parsed: Any = json.loads(content)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        keys = {str(k).lower() for k in parsed.keys()}
        if keys & {"api_key", "apikey", "token", "secret", "password"}:
            return "credential-json"
        return "json"
    if isinstance(parsed, list):
        return "json-list"
    return "json-value"


def classify_content(content: str) -> Classification:
    text = content.strip()
    lower = text.lower()
    tags: list[str] = []

    if not text:
        return Classification("empty", "low", [], "Empty clipboard item", "")

    json_kind = _json_kind(text)
    if json_kind:
        kind = json_kind
        tags.append("json")
    elif re.match(r"^https?://", text):
        kind = "url"
        tags.append("link")
    elif re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", text):
        kind = "email"
        tags.append("contact")
    elif "\n" in text and any(x in lower for x in ("def ", "class ", "function ", "const ", "import ")):
        kind = "code"
        tags.append("code")
    elif any(pattern.search(text) for pattern in SECRET_PATTERNS):
        kind = "secret"
    else:
        kind = "note"

    is_secret = kind in {"secret", "credential-json"} or any(
        pattern.search(text) for pattern in SECRET_PATTERNS
    )
    sensitivity = "high" if is_secret else "low"
    if is_secret:
        tags.append("secret")

    first_line = text.splitlines()[0] if text else ""
    summary = first_line[:90] or kind
    preview = mask_secret(first_line) if is_secret else first_line[:160]

    deduped_tags = list(dict.fromkeys(tags))
    return Classification(kind, sensitivity, deduped_tags, summary, preview)
