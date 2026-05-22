# Password Security Tool

A Python password security toolkit that combines password strength analysis, breach checking, secure generation, RBAC, and 2FA in a single package.

## Key Features

- Registration, login, and role-based access control (RBAC)
- Email OTP 2FA with production Gmail app-password support and development dry-run mode
- Password entropy, complexity, dictionary match, substitution, keyboard-pattern, sequential, and repeated-character analysis
- Have I Been Pwned breach lookups via the k-Anonymity API
- Secure password generation with configurable length and character sets
- Hash demonstrations for bcrypt and Argon2
- Flask-based local web interface with admin and user workflows

## Installation

```bash
python -m pip install -e .
```

## Quick Start

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

Show hash examples:

```bash
python -m password_security_tool.cli hash-demo "YourPassword123!"
```

Run the local web UI:

```bash
python -m password_security_tool.cli serve
```

Open your browser at:

```text
http://127.0.0.1:5000
```

A demo admin login is available:

```text
username: admin
password: Admin123!
```

## Documentation

- [Usage guide](docs/usage.md)
- [Authentication and 2FA](docs/authentication.md)
- [Password analysis engine](docs/password_analysis_engine.md)
- [Documentation index](docs/index.md)

## Development

Run tests with:

```bash
pytest -q
```

