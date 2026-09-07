import hashlib
import hmac
import json
import os
import time

import bcrypt
from cryptography.fernet import Fernet
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from models import AuditLog, Device

JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-insecure-secret-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "30"))

_fernet_key = os.getenv("FIELD_ENCRYPTION_KEY")
_fernet = Fernet(_fernet_key.encode()) if _fernet_key else None


# --------------------------------------------------------------- Passwords
# Using the bcrypt library directly rather than passlib: passlib is
# effectively unmaintained and its version-detection breaks on current
# bcrypt releases. Direct bcrypt is simpler and has one less moving part.
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode()[:72], hashed.encode())


# -------------------------------------------------------------------- JWT
def create_access_token(subject: str, role: str) -> str:
    payload = {
        "sub": subject,
        "role": role,
        "exp": time.time() + JWT_EXPIRY_MINUTES * 60,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


# ------------------------------------------------------- Device / HMAC ---
def verify_hmac(payload: dict, signature: str, device_secret: str) -> bool:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(device_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ----------------------------------------------------- Field encryption --
def encrypt_field(plaintext: str) -> str:
    if not _fernet:
        raise RuntimeError("FIELD_ENCRYPTION_KEY not configured")
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_field(ciphertext: str) -> str:
    if not _fernet:
        raise RuntimeError("FIELD_ENCRYPTION_KEY not configured")
    return _fernet.decrypt(ciphertext.encode()).decode()


# ------------------------------------------------------- Audit chaining --
def append_audit_log(db: Session, actor: str, action: str, target: str | None = None):
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    ts = time.time()

    entry_body = json.dumps(
        {"ts": ts, "actor": actor, "action": action, "target": target, "prev": prev_hash},
        sort_keys=True,
    ).encode()
    entry_hash = hashlib.sha256(entry_body).hexdigest()

    row = AuditLog(
        timestamp=ts, actor=actor, action=action, target=target,
        prev_hash=prev_hash, entry_hash=entry_hash,
    )
    db.add(row)
    db.commit()


def verify_audit_chain(db: Session) -> bool:
    """Walk the whole audit log and confirm no entry has been altered or
    removed. Run this periodically -- it's how tampering with the audit
    trail itself gets caught."""
    rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    prev_hash = "genesis"
    for row in rows:
        entry_body = json.dumps(
            {"ts": row.timestamp, "actor": row.actor, "action": row.action,
             "target": row.target, "prev": prev_hash},
            sort_keys=True,
        ).encode()
        expected = hashlib.sha256(entry_body).hexdigest()
        if expected != row.entry_hash or row.prev_hash != prev_hash:
            return False
        prev_hash = row.entry_hash
    return True
