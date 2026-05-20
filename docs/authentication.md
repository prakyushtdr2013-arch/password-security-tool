# Authentication, RBAC, and 2FA

PassGuard uses `password_security_tool.auth.AuthService` for registration, login, role checks, email OTP verification, account lockout, server-side sessions, and logout.

## Database Schema

```sql
CREATE TABLE roles (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' REFERENCES roles(name),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
);
```

## Backend Usage

```python
from password_security_tool.auth import AuthService

auth = AuthService("password_tool.sqlite3")
auth.register_user("alice", "alice@example.com", "S3cure!Passw0rd")
auth.register_user("admin", "admin@example.com", "Admin123!", role="admin")

auth.start_login("alice", "S3cure!Passw0rd")
session = auth.verify_login_otp("alice", "123456")

auth.require_role(session.token, {"user", "admin"})
auth.logout(session.token)
```

## Gmail App Password 2FA

Set these environment variables before running the web app:

```powershell
$env:GMAIL_ADDRESS="youraccount@gmail.com"
$env:GMAIL_APP_PASSWORD="your-16-character-app-password"
$env:ADMIN_EMAIL="admin@example.com"
$env:ADMIN_PASSWORD="Admin123!"
$env:SECRET_KEY="replace-with-a-long-random-secret"
```

When Gmail credentials are not configured, OTP delivery runs in development dry-run mode and the code is flashed in the UI or printed in the CLI.

## Security Notes

- Passwords are stored as Argon2 hashes by default; bcrypt is also supported.
- Login requires password verification plus a six-digit email OTP for admins and standard users.
- OTPs are hashed with bcrypt in SQLite and expire after 10 minutes.
- Five failed password attempts lock the account for 15 minutes.
- Sessions are random server-side tokens stored in SQLite with an eight-hour expiry.
- Flask cookies are HTTP-only and SameSite=Lax; set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.
- RBAC supports `admin` and `user`; protected routes call `require_role`.

## Short Testing Steps

```powershell
python -m pip install -e .
pytest -q
python -m password_security_tool.cli register alice alice@example.com "S3cure!Passw0rd"
python -m password_security_tool.cli login alice "S3cure!Passw0rd"
python -m password_security_tool.cli login alice "S3cure!Passw0rd" --otp 123456
python -m password_security_tool.cli serve
```

For the CLI OTP step, use the OTP printed in development mode instead of `123456`.
