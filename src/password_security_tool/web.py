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

from .core import (
    ROLE_ADMIN,
    ROLE_USER,
    UserManager,
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

    manager = UserManager()
    # Seed a demo admin account for quick login.
    if not manager.get_user("admin"):
        manager.register_user("admin", "Admin123!", role=ROLE_ADMIN)

    def current_user() -> str | None:
        return session.get("username")

    def login_required(view):
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if not current_user():
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

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
        return {"current_user": current_user()}

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
            password = request.form["password"]
            if not username or not password:
                flash("Both username and password are required.", "danger")
            else:
                try:
                    manager.register_user(username, password)
                    session["username"] = username
                    flash("Welcome! Your account has been created.", "success")
                    return redirect(url_for("dashboard"))
                except ValueError as exc:
                    flash(str(exc), "danger")
        return render_template("signup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if current_user():
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            if manager.authenticate_user(username, password):
                session["username"] = username
                flash(f"Welcome back, {username}!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout() -> Any:
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
        if request.method == "POST":
            length = int(request.form.get("length", 16))
            generated_password = generate_password(length=length)
        return render_template("generate.html", generated_password=generated_password)

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
        user = manager.get_user(current_user())
        return render_template("profile.html", user=user)

    return app


def main() -> None:
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
