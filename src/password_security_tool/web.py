import os
from functools import wraps
from typing import Any, Dict

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .auth import AuthError, AuthService
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


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("SECRET_KEY", "dev-password-tool-secret")
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true",
        PERMANENT_SESSION_LIFETIME=60 * 60 * 1,
    )

    auth = AuthService(os.environ.get("PASSWORD_TOOL_DB", "password_tool.sqlite3"))
    if not auth.get_user("admin"):
        try:
            auth.register_user(
                "admin",
                os.environ.get("ADMIN_EMAIL", "admin@example.com"),
                os.environ.get("ADMIN_PASSWORD", "Admin123!"),
                role=ROLE_ADMIN,
            )
        except AuthError:
            pass

    def current_session():
        return auth.get_session(session.get("auth_token"))

    def current_user() -> str | None:
        active = current_session()
        return active.username if active else None

    def login_required(view):
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if not current_session():
                session.clear()
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def roles_required(*roles: str):
        def decorator(view):
            @wraps(view)
            def wrapped(*args: Any, **kwargs: Any):
                try:
                    auth.require_role(session.get("auth_token"), roles)
                except AuthError as exc:
                    flash(str(exc), "danger")
                    return redirect(url_for("dashboard"))
                return view(*args, **kwargs)

            return wrapped

        return decorator

    @app.before_request
    def session_timeout_handler() -> None:
        """Check and enforce session timeout before each request."""
        auth_token = session.get("auth_token")
        if auth_token:
            active_session = auth.get_session(auth_token)
            if not active_session:
                session.clear()
                if request.endpoint not in ("login", "signup", "static"):
                    flash("Your session has expired. Please log in again.", "warning")

    def build_analysis(password: str) -> Dict[str, Any]:
        score = complexity_score(password)
        crack_time, crack_unit = estimate_crack_time(password)
        return {
            "score": score,
            "strength": strength_meter(score),
            "entropy": calculate_entropy(password),
            "patterns": detect_patterns(password),
            "suggestions": suggest_improvements(password),
            "crack_time": crack_time,
            "crack_unit": crack_unit,
        }

    @app.context_processor
    def inject_user():
        active = current_session()
        return {"current_user": active.username if active else None, "current_role": active.role if active else None}

    @app.route("/")
    def index() -> Any:
        if current_user():
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/signup", methods=["GET", "POST"])
    def signup() -> Any:
        if current_user():
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
        if current_user():
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
            return redirect(url_for("login"))
        if request.method == "POST":
            otp = request.form["otp"].strip()
            try:
                auth_session = auth.verify_login_otp(pending_username, otp)
                session.clear()
                session.permanent = True
                session["auth_token"] = auth_session.token
                flash(f"Welcome back, {auth_session.username}!", "success")
                return redirect(url_for("dashboard"))
            except AuthError as exc:
                flash(str(exc), "danger")
        return render_template("verify_otp.html", username=pending_username)

    @app.route("/logout")
    @login_required
    def logout() -> Any:
        auth.logout(session.get("auth_token"))
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard() -> Any:
        return render_template("dashboard.html")

    @app.route("/analyze", methods=["GET", "POST"])
    @login_required
    def analyze() -> Any:
        analysis = None
        breach_count = None
        password = ""
        if request.method == "POST":
            password = request.form["password"]
            analysis = build_analysis(password)
            breach_count = pwned_passwords_count(password)
        return render_template("analyze.html", password=password, analysis=analysis, breach_count=breach_count)

    @app.route("/generate", methods=["GET", "POST"])
    @login_required
    def generate() -> Any:
        generated_password = ""
        analysis = None
        options = {
            "length": 16,
            "upper": True,
            "lower": True,
            "digits": True,
            "symbols": True,
            "exclude_ambiguous": False,
            "passphrase": False,
        }

        if request.method == "POST":
            options["length"] = int(request.form.get("length", 16))
            options["upper"] = bool(request.form.get("upper"))
            options["lower"] = bool(request.form.get("lower"))
            options["digits"] = bool(request.form.get("digits"))
            options["symbols"] = bool(request.form.get("symbols"))
            options["exclude_ambiguous"] = bool(request.form.get("exclude_ambiguous"))
            options["passphrase"] = bool(request.form.get("passphrase"))
            try:
                generated_password = generate_password(
                    length=options["length"],
                    upper=options["upper"],
                    lower=options["lower"],
                    digits=options["digits"],
                    symbols=options["symbols"],
                    exclude_ambiguous=options["exclude_ambiguous"],
                    passphrase=options["passphrase"],
                )
                analysis = build_analysis(generated_password)
            except ValueError as exc:
                flash(str(exc), "danger")

        return render_template(
            "generate.html",
            generated_password=generated_password,
            analysis=analysis,
            options=options,
        )

    @app.route("/breach", methods=["GET", "POST"])
    @login_required
    def breach() -> Any:
        breach_count = None
        password = ""
        if request.method == "POST":
            password = request.form["password"]
            breach_count = pwned_passwords_count(password)
        return render_template("breach.html", password=password, breach_count=breach_count)

    @app.route("/profile")
    @login_required
    def profile() -> Any:
        user = auth.get_user(current_user())
        return render_template("profile.html", user=user)

    @app.route("/admin")
    @login_required
    @roles_required(ROLE_ADMIN)
    def admin() -> Any:
        return render_template("admin.html")

    return app


def main() -> None:
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
