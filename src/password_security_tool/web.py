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