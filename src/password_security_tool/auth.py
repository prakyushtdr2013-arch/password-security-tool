import os
import re
import secrets
import smtplib
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterable, Optional

from .core import (
    ROLE_ADMIN,
    ROLE_USER,
    calculate_entropy,
    hash_password,
    is_common_password,
    verify_password,
)

DEFAULT_PASSWORD_POLICY = {
    "minimum_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_special_characters": True,
    "block_common_passwords": True,
    "minimum_entropy": 60,
    "lockout_threshold": 5,
    "lockout_duration_minutes": 15,
}

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"


@dataclass(frozen=True)
class AuthUser:
    id: int
    username: str
    email: str
    role: str
    password_hash: str
    status: str
    is_locked: bool
    failed_attempts: int
    locked_until: Optional[str]
    last_login: Optional[str]
    updated_at: Optional[str]
    created_at: str


@dataclass(frozen=True)
class SessionInfo:
    token: str
    user_id: int
    username: str
    role: str
    expires_at: str

DEFAULT_DB_PATH = Path(os.environ.get("PASSWORD_TOOL_DB", "password_tool.sqlite3"))
MAX_FAILED_ATTEMPTS = DEFAULT_PASSWORD_POLICY["lockout_threshold"]
LOCKOUT_MINUTES = DEFAULT_PASSWORD_POLICY["lockout_duration_minutes"]
OTP_TTL_MINUTES = 10
SESSION_TTL_HOURS = 1


class AuthError(Exception):
    """Raised for authentication and authorization failures."""


class EmailOTPService:
    def __init__(
        self,
        smtp_host: str = "smtp.gmail.com",
        smtp_port: int = 587,
        sender_email: str | None = None,
        app_password: str | None = None,
        dry_run: bool | None = None,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender_email = sender_email or os.environ.get("GMAIL_ADDRESS")
        self.app_password = app_password or os.environ.get("GMAIL_APP_PASSWORD")
        self.dry_run = dry_run if dry_run is not None else not (self.sender_email and self.app_password)
        self.last_otp: str | None = None

    def generate_otp(self) -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    def send_otp(self, recipient: str, otp: str, *, username: str, role: str) -> None:
        self.last_otp = otp
        if self.dry_run:
            return

        message = EmailMessage()
        message["Subject"] = "PassGuard login verification code"
        message["From"] = self.sender_email
        message["To"] = recipient
        message.set_content(
            f"Your PassGuard verification code is {otp}.\n\n"
            f"Account: {username}\nRole: {role}\nThis code expires in {OTP_TTL_MINUTES} minutes."
        )

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
            server.starttls()
            server.login(self.sender_email, self.app_password)
            server.send_message(message)


class AuthService:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH, otp_service: EmailOTPService | None = None) -> None:
        self.db_path = Path(db_path)
        self.otp_service = otp_service or EmailOTPService()
        self.initialize_schema()

    def initialize_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.executemany(
                "INSERT OR IGNORE INTO roles(name, description) VALUES (?, ?)",
                [
                    (ROLE_ADMIN, "Can manage users and access administrative routes."),
                    (ROLE_USER, "Can use password strength, breach, and generator tools."),
                ],
            )
            self._ensure_password_policy(conn)
            self._migrate_user_schema(conn)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        *,
        role: str = ROLE_USER,
        algorithm: str = "argon2",
    ) -> AuthUser:
        username = username.strip()
        email = email.strip().lower()
        if not username or not email or not password:
            raise AuthError("Username, email, and password are required.")
        if role not in {ROLE_ADMIN, ROLE_USER}:
            raise AuthError("Invalid role.")

        policy = self.get_password_policy()
        self._validate_password(password, policy)

        with self._connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users(username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (username, email, hash_password(password, algorithm), role, STATUS_ACTIVE),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthError("Username or email already exists.") from exc
        user = self.get_user(username)
        if not user:
            raise AuthError("User registration failed.")
        return user

    def start_login(self, username: str, password: str) -> AuthUser:
        user = self.get_user(username)
        if not user:
            raise AuthError("Invalid username or password.")
        if user.status == STATUS_DISABLED:
            raise AuthError("Account is disabled.")
        if self._is_locked(user):
            raise AuthError("Account is temporarily locked. Try again later.")
        if not verify_password(password, user.password_hash):
            self._record_failed_attempt(user.id)
            raise AuthError("Invalid username or password.")

        self._reset_failed_attempts(user.id)
        otp = self.otp_service.generate_otp()
        self._store_otp(user.id, otp)
        self.otp_service.send_otp(user.email, otp, username=user.username, role=user.role)
        return user

    def verify_login_otp(self, username: str, otp: str) -> SessionInfo:
        user = self.get_user(username)
        if not user:
            raise AuthError("Invalid verification request.")
        if user.status == STATUS_DISABLED:
            raise AuthError("Account is disabled.")
        if not self._consume_valid_otp(user.id, otp):
            raise AuthError("Invalid or expired verification code.")
        session = self.create_session(user.id)
        with self._connection() as conn:
            conn.execute(
                "UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?",
                (_to_iso(_utc_now()), _to_iso(_utc_now()), user.id),
            )
        self.record_audit_event("login_success", actor_user_id=user.id, subject_user_id=user.id)
        return session

    def authenticate_user(self, username: str, password: str, otp: str) -> SessionInfo:
        user = self.get_user(username)
        if not user:
            raise AuthError("Invalid username or password.")
        if user.status == STATUS_DISABLED:
            raise AuthError("Account is disabled.")
        if self._is_locked(user):
            raise AuthError("Account is temporarily locked. Try again later.")
        if not verify_password(password, user.password_hash):
            self._record_failed_attempt(user.id)
            raise AuthError("Invalid username or password.")
        if not self._consume_valid_otp(user.id, otp):
            raise AuthError("Invalid or expired verification code.")
        self._reset_failed_attempts(user.id)
        return self.create_session(user.id)

    def create_session(self, user_id: int) -> SessionInfo:
        user = self.get_user_by_id(user_id)
        if not user:
            raise AuthError("User not found.")
        token = secrets.token_urlsafe(32)
        expires_at = _utc_now() + timedelta(hours=SESSION_TTL_HOURS)
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, user.id, _to_iso(expires_at)),
            )
        return SessionInfo(token=token, user_id=user.id, username=user.username, role=user.role, expires_at=_to_iso(expires_at))

    def get_password_policy(self) -> dict[str, Any]:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM password_policies WHERE id = 1").fetchone()
        if not row:
            return DEFAULT_PASSWORD_POLICY.copy()
        return {
            "minimum_length": row["minimum_length"],
            "require_uppercase": bool(row["require_uppercase"]),
            "require_lowercase": bool(row["require_lowercase"]),
            "require_numbers": bool(row["require_numbers"]),
            "require_special_characters": bool(row["require_special_characters"]),
            "block_common_passwords": bool(row["block_common_passwords"]),
            "minimum_entropy": row["minimum_entropy"],
            "lockout_threshold": row["lockout_threshold"],
            "lockout_duration_minutes": row["lockout_duration_minutes"],
        }

    def set_password_policy(self, policy: dict[str, Any]) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO password_policies(id, minimum_length, require_uppercase, require_lowercase, require_numbers, require_special_characters, block_common_passwords, minimum_entropy, lockout_threshold, lockout_duration_minutes, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                , (
                    policy["minimum_length"],
                    int(policy["require_uppercase"]),
                    int(policy["require_lowercase"]),
                    int(policy["require_numbers"]),
                    int(policy["require_special_characters"]),
                    int(policy["block_common_passwords"]),
                    policy["minimum_entropy"],
                    policy["lockout_threshold"],
                    policy["lockout_duration_minutes"],
                    _to_iso(_utc_now()),
                ),
            )

    def _validate_password(self, password: str, policy: dict[str, Any]) -> None:
        if len(password) < policy["minimum_length"]:
            raise AuthError(f"Password must be at least {policy['minimum_length']} characters.")
        if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
            raise AuthError("Password must include at least one uppercase character.")
        if policy["require_lowercase"] and not re.search(r"[a-z]", password):
            raise AuthError("Password must include at least one lowercase character.")
        if policy["require_numbers"] and not re.search(r"[0-9]", password):
            raise AuthError("Password must include at least one number.")
        if policy["require_special_characters"] and not re.search(r"[^A-Za-z0-9]", password):
            raise AuthError("Password must include at least one special character.")
        if policy["block_common_passwords"] and is_common_password(password):
            raise AuthError("Password is too common. Choose a stronger password.")
        entropy = calculate_entropy(password)
        if entropy < policy["minimum_entropy"]:
            raise AuthError(
                f"Password entropy must be at least {policy['minimum_entropy']}. "
                f"Current entropy is {round(entropy, 2)}."
            )

    def list_users(self) -> list[AuthUser]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY username ASC").fetchall()
        return [_row_to_user(row) for row in rows if row]

    def change_user_role(self, username: str, role: str, actor_user_id: int | None = None) -> AuthUser:
        if role not in {ROLE_ADMIN, ROLE_USER}:
            raise AuthError("Invalid role.")
        user = self.get_user(username)
        if not user:
            raise AuthError("User not found.")
        with self._connection() as conn:
            conn.execute("UPDATE users SET role = ?, updated_at = ? WHERE id = ?", (role, _to_iso(_utc_now()), user.id))
        self.record_audit_event(
            "role_changed",
            actor_user_id=actor_user_id,
            subject_user_id=user.id,
            details=f"Role changed to {role}",
        )
        return self.get_user(username)

    def update_user_status(self, username: str, status: str, actor_user_id: int | None = None) -> AuthUser:
        if status not in {STATUS_ACTIVE, STATUS_DISABLED}:
            raise AuthError("Invalid user status.")
        user = self.get_user(username)
        if not user:
            raise AuthError("User not found.")
        with self._connection() as conn:
            conn.execute("UPDATE users SET status = ?, updated_at = ? WHERE id = ?", (status, _to_iso(_utc_now()), user.id))
        self.record_audit_event("user_status_changed", actor_user_id=user.id, subject_user_id=user.id, details=f"Status set to {status}")
        return self.get_user(username)

    def get_active_session_count(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM sessions").fetchone()
        return int(row["count"] if row else 0)

    def get_locked_user_count(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users WHERE locked_until IS NOT NULL AND locked_until > ?", (_to_iso(_utc_now()),)).fetchone()
        return int(row["count"] if row else 0)

    def get_recent_audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT l.id, l.event_type, l.details, l.source_ip, l.created_at,
                       a.username AS actor_username,
                       s.username AS subject_username
                FROM user_audit_logs l
                LEFT JOIN users a ON a.id = l.actor_user_id
                LEFT JOIN users s ON s.id = l.subject_user_id
                ORDER BY l.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_audit_event(
        self,
        event_type: str,
        subject_user_id: int | None = None,
        actor_user_id: int | None = None,
        details: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO user_audit_logs(event_type, actor_user_id, subject_user_id, details, source_ip) VALUES (?, ?, ?, ?, ?)",
                (event_type, actor_user_id, subject_user_id, details, source_ip),
            )

    def get_session(self, token: str | None) -> SessionInfo | None:
        if not token:
            return None
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT s.token, s.user_id, u.username, u.role, s.expires_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ?
                """,
                (token,),
            ).fetchone()
        if not row:
            return None
        if _from_iso(row["expires_at"]) <= _utc_now():
            self.logout(token)
            return None
        return SessionInfo(
            token=row["token"],
            user_id=row["user_id"],
            username=row["username"],
            role=row["role"],
            expires_at=row["expires_at"],
        )

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._connection() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))

    def require_role(self, session_token: str | None, allowed_roles: Iterable[str]) -> SessionInfo:
        session = self.get_session(session_token)
        if not session:
            raise AuthError("Authentication required.")
        if session.role not in set(allowed_roles):
            raise AuthError("You do not have permission to access this resource.")
        return session

    def get_user(self, username: str | None) -> AuthUser | None:
        if not username:
            return None
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
        return _row_to_user(row)

    def get_user_by_id(self, user_id: int) -> AuthUser | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(row)

    def _record_failed_attempt(self, user_id: int) -> None:
        user = self.get_user_by_id(user_id)
        attempts = (user.failed_attempts if user else 0) + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = _to_iso(_utc_now() + timedelta(minutes=LOCKOUT_MINUTES))
        with self._connection() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user_id),
            )
        self.record_audit_event(
            "login_failed",
            subject_user_id=user_id,
            details=f"Failed login attempt {attempts}",
        )

    def _reset_failed_attempts(self, user_id: int) -> None:
        with self._connection() as conn:
            conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))

    def _is_locked(self, user: AuthUser) -> bool:
        if not user.locked_until:
            return False
        return _from_iso(user.locked_until) > _utc_now()

    def _store_otp(self, user_id: int, otp: str) -> None:
        expires_at = _to_iso(_utc_now() + timedelta(minutes=OTP_TTL_MINUTES))
        otp_hash = hash_password(otp, "bcrypt")
        with self._connection() as conn:
            conn.execute("DELETE FROM user_otps WHERE user_id = ?", (user_id,))
            conn.execute(
                "INSERT INTO user_otps(user_id, otp_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, otp_hash, expires_at),
            )

    def _consume_valid_otp(self, user_id: int, otp: str) -> bool:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT id, otp_hash, expires_at FROM user_otps WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            if not row or _from_iso(row["expires_at"]) <= _utc_now():
                return False
            valid = verify_password(otp, row["otp_hash"])
            if valid:
                conn.execute("DELETE FROM user_otps WHERE id = ?", (row["id"],))
            return valid

    def _ensure_password_policy(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO password_policies(id, minimum_length, require_uppercase, require_lowercase, require_numbers, require_special_characters, block_common_passwords, minimum_entropy, lockout_threshold, lockout_duration_minutes, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            , (
                DEFAULT_PASSWORD_POLICY["minimum_length"],
                int(DEFAULT_PASSWORD_POLICY["require_uppercase"]),
                int(DEFAULT_PASSWORD_POLICY["require_lowercase"]),
                int(DEFAULT_PASSWORD_POLICY["require_numbers"]),
                int(DEFAULT_PASSWORD_POLICY["require_special_characters"]),
                int(DEFAULT_PASSWORD_POLICY["block_common_passwords"]),
                DEFAULT_PASSWORD_POLICY["minimum_entropy"],
                DEFAULT_PASSWORD_POLICY["lockout_threshold"],
                DEFAULT_PASSWORD_POLICY["lockout_duration_minutes"],
                _to_iso(_utc_now()),
            ),
        )

    def _migrate_user_schema(self, conn: sqlite3.Connection) -> None:
        existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "status" not in existing_columns:
            conn.execute(f"ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT '{STATUS_ACTIVE}'")
        if "last_login" not in existing_columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
        if "updated_at" not in existing_columns:
            conn.execute("ALTER TABLE users ADD COLUMN updated_at TEXT")

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' REFERENCES roles(name),
    status TEXT NOT NULL DEFAULT 'active',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_login TEXT,
    updated_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    subject_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    details TEXT,
    source_ip TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_policies (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    minimum_length INTEGER NOT NULL DEFAULT 12,
    require_uppercase INTEGER NOT NULL DEFAULT 1,
    require_lowercase INTEGER NOT NULL DEFAULT 1,
    require_numbers INTEGER NOT NULL DEFAULT 1,
    require_special_characters INTEGER NOT NULL DEFAULT 1,
    block_common_passwords INTEGER NOT NULL DEFAULT 1,
    minimum_entropy INTEGER NOT NULL DEFAULT 60,
    lockout_threshold INTEGER NOT NULL DEFAULT 5,
    lockout_duration_minutes INTEGER NOT NULL DEFAULT 15,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def _row_to_user(row: sqlite3.Row | None) -> AuthUser | None:
    if not row:
        return None
    locked_until = row["locked_until"]
    return AuthUser(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        role=row["role"],
        password_hash=row["password_hash"],
        status=row["status"],
        is_locked=bool(locked_until and _from_iso(locked_until) > _utc_now()),
        failed_attempts=row["failed_attempts"],
        locked_until=locked_until,
        last_login=row["last_login"],
        updated_at=row["updated_at"],
        created_at=row["created_at"],
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _to_iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _from_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
