import os
import secrets
import smtplib
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable, Optional

from .core import ROLE_ADMIN, ROLE_USER, hash_password, verify_password

DEFAULT_DB_PATH = Path(os.environ.get("PASSWORD_TOOL_DB", "password_tool.sqlite3"))
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
OTP_TTL_MINUTES = 10
SESSION_TTL_HOURS = 1


class AuthError(Exception):
    """Raised for authentication and authorization failures."""


@dataclass(frozen=True)
class AuthUser:
    id: int
    username: str
    email: str
    role: str
    password_hash: str
    is_locked: bool
    failed_attempts: int
    locked_until: Optional[str]
    created_at: str


@dataclass(frozen=True)
class SessionInfo:
    token: str
    user_id: int
    username: str
    role: str
    expires_at: str


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

        with self._connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users(username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, email, hash_password(password, algorithm), role),
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
        if not self._consume_valid_otp(user.id, otp):
            raise AuthError("Invalid or expired verification code.")
        return self.create_session(user.id)

    def authenticate_user(self, username: str, password: str, otp: str) -> SessionInfo:
        user = self.get_user(username)
        if not user:
            raise AuthError("Invalid username or password.")
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
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
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
        is_locked=bool(locked_until and _from_iso(locked_until) > _utc_now()),
        failed_attempts=row["failed_attempts"],
        locked_until=locked_until,
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
