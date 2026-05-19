from flask import Flask, redirect, render_template_string, request, url_for

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
)

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Password Security Tool</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      input, button, select { font-size: 1rem; margin: 0.25rem 0; }
      .card { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
      .result { background: #f9f9f9; padding: 1rem; border-radius: 8px; margin-top: 1rem; }
    </style>
  </head>
  <body>
    <h1>Password Security Tool</h1>
    <div class="card">
      <h2>Analyze Password</h2>
      <form method="post" action="{{ url_for('analyze') }}">
        <label>Password</label><br />
        <input type="password" name="password" value="{{ password or '' }}" required /><br />
        <button type="submit">Analyze</button>
      </form>
    </div>

    <div class="card">
      <h2>Generate Password</h2>
      <form method="post" action="{{ url_for('generate') }}">
        <label>Length</label><br />
        <input type="number" name="length" value="16" min="8" max="64" /><br />
        <button type="submit">Generate</button>
      </form>
      {% if generated_password %}
      <div class="result">
        <strong>Generated:</strong> <code>{{ generated_password }}</code>
      </div>
      {% endif %}
    </div>

    {% if analysis %}
    <div class="card">
      <h2>Analysis Results</h2>
      <div class="result">
        <p><strong>Score:</strong> {{ analysis.score }}/100</p>
        <p><strong>Strength:</strong> {{ analysis.strength }}</p>
        <p><strong>Entropy:</strong> {{ analysis.entropy }} bits</p>
        <p><strong>Estimated crack time:</strong> {{ analysis.crack_time }} {{ analysis.crack_unit }}</p>
        <p><strong>Patterns:</strong> {{ analysis.patterns or 'None' }}</p>
        <p><strong>Suggestions:</strong></p>
        <ul>{% for suggestion in analysis.suggestions %}<li>{{ suggestion }}</li>{% endfor %}</ul>
      </div>
    </div>
    {% endif %}

    {% if breach_count is not none %}
    <div class="card">
      <h2>Breach Check</h2>
      <div class="result">
        {% if breach_count > 0 %}
          <p>This password appears in breaches <strong>{{ breach_count }}</strong> times.</p>
        {% else %}
          <p>No breach matches found.</p>
        {% endif %}
      </div>
    </div>
    {% endif %}

  </body>
</html>
"""


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    def index() -> str:
        return render_template_string(HTML_TEMPLATE, password="", analysis=None, generated_password=None, breach_count=None)

    @app.route("/analyze", methods=["POST"])
    def analyze() -> str:
        password = request.form["password"]
        score = complexity_score(password)
        analysis = {
            "score": score,
            "strength": strength_meter(score),
            "entropy": calculate_entropy(password),
            "patterns": detect_patterns(password),
            "suggestions": suggest_improvements(password),
            "crack_time": estimate_crack_time(password)[0],
            "crack_unit": estimate_crack_time(password)[1],
        }
        breach_count = pwned_passwords_count(password)
        return render_template_string(
            HTML_TEMPLATE,
            password=password,
            analysis=analysis,
            generated_password=None,
            breach_count=breach_count,
        )

    @app.route("/generate", methods=["POST"])
    def generate() -> str:
        length = int(request.form.get("length", 16))
        generated_password = generate_password(length=length)
        return render_template_string(
            HTML_TEMPLATE,
            password=generated_password,
            analysis=None,
            generated_password=generated_password,
            breach_count=None,
        )

    return app


def main() -> None:
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
