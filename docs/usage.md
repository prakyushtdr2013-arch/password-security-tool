# Password Security Tool Usage

## Install

```bash
python -m pip install -e .
```

## Analyze a password

```bash
python -m password_security_tool.cli analyze "P@ssw0rd!"
```

## Generate a secure password

```bash
python -m password_security_tool.cli generate --length 20
```

## Check password breach status

```bash
python -m password_security_tool.cli check-breach "YourPassword123!"
```

## Hash demonstration

```bash
python -m password_security_tool.cli hash-demo "YourPassword123!"
```
