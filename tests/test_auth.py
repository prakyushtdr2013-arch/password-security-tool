import sqlite3

import pytest

from password_security_tool.auth import (
    AuthError,
    AuthService,
    EmailOTPService,
    MAX_FAILED_ATTEMPTS,
    ROLE_ADMIN,
    STATUS_DISABLED,
)


def build_auth(tmp_path):
    otp_service = EmailOTPService(dry_run=True)
    return AuthService(tmp_path / "auth.sqlite3", otp_service=otp_service), otp_service


def test_registration_login_otp_and_logout(tmp_path):
    auth, otp_service = build_auth(tmp_path)
    user = auth.register_user("alice", "alice@example.com", "S3cure!Passw0rd", algorithm="bcrypt")

    assert user.role == "user"
    auth.start_login("alice", "S3cure!Passw0rd")
    session = auth.verify_login_otp("alice", otp_service.last_otp)

    assert session.username == "alice"
    assert auth.get_session(session.token).role == "user"

    auth.logout(session.token)
    assert auth.get_session(session.token) is None


def test_admin_role_required(tmp_path):
    auth, otp_service = build_auth(tmp_path)
    auth.register_user("admin", "admin@example.com", "Admin!Passw0rd", role="admin", algorithm="bcrypt")
    auth.start_login("admin", "Admin!Passw0rd")
    session = auth.verify_login_otp("admin", otp_service.last_otp)

    assert auth.require_role(session.token, {"admin"}).username == "admin"
    with pytest.raises(AuthError):
        auth.require_role(session.token, {"user"})


def test_account_lockout_after_failed_attempts(tmp_path):
    auth, _ = build_auth(tmp_path)
    auth.register_user("bob", "bob@example.com", "S3cure!Passw0rd", algorithm="bcrypt")

    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthError):
            auth.start_login("bob", "wrong-password")

    user = auth.get_user("bob")
    assert user.is_locked
    assert user.failed_attempts == MAX_FAILED_ATTEMPTS

    with pytest.raises(AuthError, match="temporarily locked"):
        auth.start_login("bob", "S3cure!Passw0rd")


def test_database_schema_contains_users_roles_sessions_and_otps(tmp_path):
    auth, _ = build_auth(tmp_path)
    with sqlite3.connect(auth.db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }

    assert {"users", "roles", "sessions", "user_otps", "user_audit_logs", "password_policies"}.issubset(tables)


def test_admin_user_management_and_audit_events(tmp_path):
    auth, _ = build_auth(tmp_path)
    auth.register_user("admin", "admin@example.com", "Admin!Passw0rd", role=ROLE_ADMIN, algorithm="bcrypt")
    auth.register_user("bob", "bob@example.com", "S3cure!Passw0rd", algorithm="bcrypt")

    assert len(auth.list_users()) == 2
    auth.update_user_status("bob", STATUS_DISABLED, actor_user_id=1)
    assert auth.get_user("bob").status == STATUS_DISABLED

    auth.change_user_role("bob", ROLE_ADMIN, actor_user_id=1)
    assert auth.get_user("bob").role == ROLE_ADMIN

    auth.set_password_policy({
        "minimum_length": 16,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special_characters": True,
        "block_common_passwords": True,
        "minimum_entropy": 70,
        "lockout_threshold": 5,
        "lockout_duration_minutes": 15,
    })
    assert auth.get_password_policy()["minimum_length"] == 16

    events = auth.get_recent_audit_events(10)
    assert any(event["event_type"] == "user_status_changed" for event in events)
