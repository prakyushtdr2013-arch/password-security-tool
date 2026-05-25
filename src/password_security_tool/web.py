import os
import secrets
from functools import wraps
from typing import Any, Dict

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException

from .auth import AuthError, AuthService, STATUS_ACTIVE, STATUS_DISABLED
from .core import (
    ROLE_ADMIN,
    ROLE_USER,
    calculate_entropy,
    complexity_score,
    detect_patterns,
    estimate_crack_time,
    generate_password,
    pwned_passwords_count,
    strength_meter,
    suggest_improvements,
)


def _current_user(auth: AuthService) -> Any:
    """Get the current authenticated user from session."""
    auth_token = session.get("auth_token")
    if auth_token:
        return auth.get_session(auth_token)
    return None


def _current_session(auth: AuthService) -> Any:
    """Get the current session object."""
    return _current_user(auth)


def _require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not _current_user(auth):
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def _require_admin(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = _current_user(auth)
        if not user or user.role != ROLE_ADMIN:
            flash("You do not have permission to access this page.", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def _configure_app(app: Flask) -> None:
    """Configure Flask app settings."""
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour


def _ensure_admin_user(auth: AuthService) -> None:
    """Ensure admin user exists."""
    try:
        auth.get_user("admin")
    except AuthError:
        auth.register_user("admin", "admin@example.com", "Admin@123456!", role=ROLE_ADMIN)


def _register_routes(app: Flask, auth: AuthService) -> None:
    """Register all Flask routes."""
    
    @app.before_request
    def before_request():
        """Check and enforce session timeout before each request."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not token or token != session.get("csrf_token"):
                abort(400, "Invalid CSRF token")

        auth_token = session.get("auth_token")
        if auth_token:
            active_session = auth.get_session(auth_token)
            if not active_session:
                session.clear()
                if request.endpoint not in ("login", "signup", "static"):
                    flash("Your session has expired. Please log in again.", "warning")

    @app.context_processor
    def inject_user():
        active = _current_session(auth)
        return {
            "current_user": active.username if active else None,
            "current_role": active.role if active else None,
            "csrf_token": session.get("csrf_token"),
        }

    def _apply_security_headers(response):
        """Set security headers including Content Security Policy."""
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @app.after_request
    def set_security_headers(response):
        return _apply_security_headers(response)

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        response = error.get_response()
        return _apply_security_headers(response)

    @app.route("/")
    def index() -> Any:
        if _current_user(auth):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/signup", methods=["GET", "POST"])
    def signup() -> Any:
        if _current_user(auth):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form["username"].strip()
            email = request.form["email"].strip()
            password = request.form["password"]
            if not username or not email or not password:
                flash("Username, email, and password are required.", "danger")
            else:
                try:
                    auth.register_user(username, email, password, role=ROLE_USER)
                    flash("Account created. Check your email for the OTP after login.", "success")
                    return redirect(url_for("login"))
                except AuthError as exc:
                    flash(str(exc), "danger")
        return render_template("signup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if _current_user(auth):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            try:
                user = auth.start_login(username, password)
                session.clear()
                session["pending_username"] = user.username
                if auth.otp_service.dry_run and auth.otp_service.last_otp:
                    flash(f"Development OTP: {auth.otp_service.last_otp}", "info")
                flash("Verification code sent to your email.", "success")
                return redirect(url_for("verify_otp"))
            except AuthError as exc:
                flash(str(exc), "danger")
        return render_template("login.html")

    @app.route("/verify-otp", methods=["GET", "POST"])
    def verify_otp() -> Any:
        pending_username = session.get("pending_username")
        if not pending_username:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        
        if request.method == "POST":
            otp = request.form["otp"].strip()
            try:
                auth_token = auth.verify_otp(pending_username, otp)
                session.clear()
                session["auth_token"] = auth_token
                flash("Logged in successfully!", "success")
                return redirect(url_for("dashboard"))
            except AuthError as exc:
                flash(str(exc), "danger")
        return render_template("verify_otp.html")

    @app.route("/logout")
    def logout() -> Any:
        session.clear()
        flash("Logged out successfully.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @_require_auth
    def dashboard() -> Any:
        user = _current_user(auth)
        return render_template("dashboard.html", user=user)

    @app.route("/analyze", methods=["GET", "POST"])
    @_require_auth
    def analyze() -> Any:
        result = None
        if request.method == "POST":
            password = request.form.get("password", "")
            if password:
                result = {
                    "password": password,
                    "strength": strength_meter(password),
                    "entropy": calculate_entropy(password),
                    "complexity_score": complexity_score(password),
                    "patterns": detect_patterns(password),
                    "crack_time": estimate_crack_time(password),
                    "suggestions": suggest_improvements(password),
                }
        return render_template("analyze.html", result=result)

    @app.route("/generate")
    @_require_auth
    def generate() -> Any:
        length = request.args.get("length", 16, type=int)
        password = generate_password(length=max(8, min(length, 128)))
        return render_template("generate.html", generated_password=password)

    @app.route("/admin")
    @_require_admin
    def admin() -> Any:
        users = auth.list_users()
        policy = auth.get_password_policy()
        audit_events = auth.get_recent_audit_events(25)
        active = _current_session(auth)

        stats = {
            "total_users": len(users),
            "active_sessions": auth.get_active_session_count(),
            "locked_users": auth.get_locked_user_count(),
            "disabled_users": sum(1 for user in users if user.status == STATUS_DISABLED),
        }

        if request.method == "POST":
            action = request.form.get("admin_action")
            username = request.form.get("target_user")
            try:
                if action in {"disable", "enable"}:
                    if not username:
                        raise AuthError("No user selected.")
                    if username == "admin" and action == "disable":
                        raise AuthError("Cannot disable the built-in admin account.")
                    status = STATUS_DISABLED if action == "disable" else STATUS_ACTIVE
                    auth.update_user_status(username, status, actor_user_id=active.user_id)
                    flash(f"User {username} has been {status}.", "success")
                elif action == "set_role":
                    if not username:
                        raise AuthError("No user selected.")
                    new_role = request.form.get("role")
                    if new_role not in {ROLE_ADMIN, ROLE_USER}:
                        raise AuthError("Invalid role selected.")
                    auth.change_user_role(username, new_role, actor_user_id=active.user_id)
                    flash(f"Role for {username} updated to {new_role}.", "success")
                elif action == "update_policy":
                    updated_policy = {
                        "minimum_length": int(request.form.get("minimum_length", policy["minimum_length"])),
                        "require_uppercase": bool(request.form.get("require_uppercase")),
                        "require_lowercase": bool(request.form.get("require_lowercase")),
                        "require_numbers": bool(request.form.get("require_numbers")),
                        "require_special_characters": bool(request.form.get("require_special_characters")),
                        "block_common_passwords": bool(request.form.get("block_common_passwords")),
                        "minimum_entropy": int(request.form.get("minimum_entropy", policy["minimum_entropy"])),
                        "lockout_threshold": int(request.form.get("lockout_threshold", policy["lockout_threshold"])),
                        "lockout_duration_minutes": int(request.form.get("lockout_duration_minutes", policy["lockout_duration_minutes"])),
                    }
                    auth.set_password_policy(updated_policy)
                    auth.record_audit_event(
                        "password_policy_updated",
                        actor_user_id=active.user_id,
                        details="Admin updated password policy settings.",
                    )
                    flash("Password policy has been updated.", "success")
                else:
                    raise AuthError("Unknown admin action.")
            except AuthError as exc:
                flash(str(exc), "danger")

            users = auth.list_users()
            policy = auth.get_password_policy()
            audit_events = auth.get_recent_audit_events(25)
            stats = {
                "total_users": len(users),
                "active_sessions": auth.get_active_session_count(),
                "locked_users": auth.get_locked_user_count(),
                "disabled_users": sum(1 for user in users if user.status == STATUS_DISABLED),
            }

        return render_template(
            "admin.html",
            users=users,
            policy=policy,
            stats=stats,
            audit_events=audit_events,
        )


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    _configure_app(app)

    auth = AuthService(os.environ.get("PASSWORD_TOOL_DB", "password_tool.sqlite3"))
    _ensure_admin_user(auth)
    _register_routes(app, auth)

    return app


def main() -> None:
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
