import argparse
from typing import List

from .auth import AuthError, AuthService
from .core import (
    calculate_entropy,
    complexity_score,
    detect_patterns,
    estimate_crack_time,
    generate_password,
    hash_password,
    pwned_passwords_count,
    strength_meter,
    suggest_improvements,
    verify_password,
)


def analyze_password(password: str) -> None:
    score = complexity_score(password)
    print(f"Password: {password}")
    print(f"Complexity score: {score}/100")
    print(f"Strength: {strength_meter(score)}")
    print(f"Entropy: {calculate_entropy(password)} bits")
    patterns = detect_patterns(password)
    if patterns:
        print("Detected patterns:")
        for pattern in patterns:
            print(f" - {pattern}")
    else:
        print("No obvious weak patterns detected.")
    suggestions = suggest_improvements(password)
    if suggestions:
        print("Suggestions:")
        for suggestion in suggestions:
            print(f" - {suggestion}")
    else:
        print("This password is well-balanced.")
    crack_time, unit = estimate_crack_time(password)
    print(f"Estimated crack time: {crack_time} {unit}")


def hash_demo(password: str) -> None:
    bcrypt_hash = hash_password(password, algorithm="bcrypt")
    argon2_hash = hash_password(password, algorithm="argon2")
    print("bcrypt:")
    print(f"  {bcrypt_hash}")
    print("Argon2:")
    print(f"  {argon2_hash}")


def check_breach(password: str) -> None:
    count = pwned_passwords_count(password)
    if count:
        print(f"This password has been seen {count} times in breached datasets.")
    else:
        print("No breach matches found for this password.")


def generate_command(args: argparse.Namespace) -> None:
    password = generate_password(
        length=args.length,
        upper=not args.no_upper,
        lower=not args.no_lower,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
    )
    print(password)


def register_command(args: argparse.Namespace) -> None:
    auth = AuthService(args.db)
    user = auth.register_user(args.username, args.email, args.password, role=args.role, algorithm=args.algorithm)
    print(f"Registered {user.username} with role {user.role}.")
    print("Email OTP will be required at login.")


def login_command(args: argparse.Namespace) -> None:
    auth = AuthService(args.db)
    try:
        if args.otp:
            session_info = auth.authenticate_user(args.username, args.password, args.otp)
            print(f"Login successful. Session token: {session_info.token}")
            return

        auth.start_login(args.username, args.password)
        print("OTP sent to the user's email address.")
        if auth.otp_service.dry_run and auth.otp_service.last_otp:
            print(f"Development OTP: {auth.otp_service.last_otp}")
        print("Run login again with --otp <code> to create a session.")
    except AuthError as exc:
        print(f"Login failed: {exc}")


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Password Security Tool CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze password strength")
    analyze.add_argument("password", help="Password to analyze")

    breach = subparsers.add_parser("check-breach", help="Check the password against Have I Been Pwned")
    breach.add_argument("password", help="Password to check")

    generate = subparsers.add_parser("generate", help="Generate a secure password")
    generate.add_argument("--length", type=int, default=16, help="Password length")
    generate.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    generate.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    generate.add_argument("--no-digits", action="store_true", help="Exclude digits")
    generate.add_argument("--no-symbols", action="store_true", help="Exclude punctuation")

    hash_demo_parser = subparsers.add_parser("hash-demo", help="Show bcrypt and Argon2 hashes")
    hash_demo_parser.add_argument("password", help="Password to hash")

    serve = subparsers.add_parser("serve", help="Run the local web interface on localhost")
    serve.add_argument("--host", default="127.0.0.1", help="Host to bind")
    serve.add_argument("--port", type=int, default=5000, help="Port to bind")

    login = subparsers.add_parser("login", help="Demonstrate a user login with RBAC and optional 2FA")
    login.add_argument("username", help="Username")
    login.add_argument("password", help="Password")
    login.add_argument("--otp", help="Email OTP for 2FA")
    login.add_argument("--db", default="password_tool.sqlite3", help="SQLite database path")

    register = subparsers.add_parser("register", help="Register a demo user")
    register.add_argument("username", help="Username")
    register.add_argument("email", help="Email address for login OTP delivery")
    register.add_argument("password", help="Password")
    register.add_argument("--role", choices=["admin", "user"], default="user", help="User role")
    register.add_argument("--algorithm", choices=["argon2", "bcrypt"], default="argon2", help="Password hashing algorithm")
    register.add_argument("--db", default="password_tool.sqlite3", help="SQLite database path")

    args = parser.parse_args(argv)
    if args.command == "analyze":
        analyze_password(args.password)
    elif args.command == "check-breach":
        check_breach(args.password)
    elif args.command == "generate":
        generate_command(args)
    elif args.command == "hash-demo":
        hash_demo(args.password)
    elif args.command == "serve":
        from .web import create_app

        app = create_app()
        app.run(host=args.host, port=args.port)
    elif args.command == "login":
        login_command(args)
    elif args.command == "register":
        register_command(args)


if __name__ == "__main__":
    main()
