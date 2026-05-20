# Password Security Tool

A Python-based password strength checker and secure password manager with RBAC, 2FA, hash demonstrations, breach checks, and password generation.

## Features

- Secure registration and login with role-based access control (RBAC)
- Email OTP 2FA using Gmail app-password SMTP in production and dry-run codes in development
- Login attempt limiting, temporary account lockout, and server-side logout/session invalidation
- Password entropy and complexity scoring
- Detection of weak patterns and common passwords
- Have I Been Pwned breach lookups via the k-Anonymity API
- Secure password generator with configurable sets
- bcrypt and Argon2 hashing demonstrations
- Crack-time estimation for password strength

## Installation

```bash
python -m pip install -e .
```

## Usage

Analyze a password:

```bash
python -m password_security_tool.cli analyze "P@ssw0rd!"
```

Generate a password:

```bash
python -m password_security_tool.cli generate --length 18
```

Check a password against breaches:

```bash
python -m password_security_tool.cli check-breach "YourPassword123!"
```

Show hash examples:

```bash
python -m password_security_tool.cli hash-demo "YourPassword123!"
```

Run the local web interface:

```bash
python -m password_security_tool.cli serve
```

Then open:

```text
http://127.0.0.1:5000
```

A demo login is available:

```text
username: admin
password: Admin123!
```

The admin email defaults to `admin@example.com`. Set `GMAIL_ADDRESS`, `GMAIL_APP_PASSWORD`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `SECRET_KEY` for a real deployment-style local run. See [docs/authentication.md](docs/authentication.md) for the schema, backend API, RBAC, 2FA, and testing steps.

## Development

Run tests:

```bash
pytest -q
```

