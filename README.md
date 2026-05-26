# Password Security Tool

A Python password security toolkit for password analysis, breach checking, secure generation, RBAC, 2FA, and demonstration-grade web security controls.

## Overview

Password Security Tool helps developers and security teams understand password risk with:
- strength scoring, entropy and crack-time estimation
- pattern detection and improvement suggestions
- Have I Been Pwned breach checking
- secure random password generation
- bcrypt / Argon2 hash demonstration
- Flask-based user/admin web interface
- registration, login, OTP 2FA, and role-based access control

## Features

- CLI commands for analysis, generation, breach lookup, and hash demo
- Local Flask web application with signup, login, verify OTP, dashboard, analyzer, and generator
- Admin dashboard with user management, password policy controls, and audit event review
- Secure default session, cookie, and CSP settings
- Optional Gmail app-password email delivery for OTPs or dry-run development mode
- SQLite-backed user, OTP, and session management

## Installation

```bash
python -m pip install -e .
```

## CLI Quick Start

Analyze a password:

```bash
python -m password_security_tool.cli analyze "P@ssw0rd!"
```

Generate a password:

```bash
python -m password_security_tool.cli generate --length 18
```

Check password breach status:

```bash
python -m password_security_tool.cli check-breach "YourPassword123!"
```

Show bcrypt and Argon2 hash output:

```bash
python -m password_security_tool.cli hash-demo "YourPassword123!"
```

Run the local web interface:

```bash
python -m password_security_tool.cli serve --host 127.0.0.1 --port 5000
```

## Web Interface

Open the app in your browser:

```text
http://127.0.0.1:5000
```

The web UI includes:
- signup and password-protected login
- OTP verification for secure authentication
- password strength analysis and suggestions
- random password generation
- admin user management and policy controls

A built-in admin account is created automatically if missing:

```text
username: admin
password: Admin@123456!
```

## Environment Variables

For production email OTP delivery, set these environment variables:

```powershell
$env:GMAIL_ADDRESS="youraccount@gmail.com"
$env:GMAIL_APP_PASSWORD="your-16-character-app-password"
$env:SECRET_KEY="replace-with-a-long-random-secret"
$env:PASSWORD_TOOL_DB="password_tool.sqlite3"
```

When Gmail credentials are not configured, OTPs run in development dry-run mode and are displayed in the UI/CLI for testing.

## Project Structure

- `src/password_security_tool/cli.py` — command-line entrypoint
- `src/password_security_tool/web.py` — Flask web application
- `src/password_security_tool/auth.py` — registration, login, RBAC, OTP, and session logic
- `src/password_security_tool/core.py` — password analysis, generation, hashing, and breach lookup
- `docs/` — usage, authentication, and engine documentation

## Testing

Run the automated test suite:

```bash
pytest -q
```

## Documentation

- [Usage guide](docs/usage.md)
- [Authentication and 2FA](docs/authentication.md)
- [Password analysis engine](docs/password_analysis_engine.md)
- [Documentation index](docs/index.md)

## License

This project is licensed under the MIT License.

