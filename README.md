# Password Security Tool

A Python-based password strength checker and secure password manager with RBAC, 2FA, hash demonstrations, breach checks, and password generation.

## Features

- Secure login with role-based access control (RBAC)
- Optional 2FA using TOTP
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

## Development

Run tests:

```bash
pytest -q
```

