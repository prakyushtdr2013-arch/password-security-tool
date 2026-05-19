import hashlib
import math
import re
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import argon2
import bcrypt
import pyotp
import requests

COMMON_PASSWORDS_PATH = Path(__file__).parent / "data" / "common_passwords.txt"
KEYBOARD_PATTERNS = [
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "123456",
    "password",
    "admin",
    "letmein",
]

ROLE_ADMIN = "admin"
ROLE_USER = "user"


@dataclass
class User:
    username: str
    role: str
    password_hash: str
    totp_secret: str = field(default_factory=pyotp.random_base32)


class UserManager:
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}

    def register_user(self, username: str, password: str, role: str = ROLE_USER, algorithm: str = "bcrypt") -> User:
        if role not in {ROLE_ADMIN, ROLE_USER}:
            raise ValueError("Invalid role")
        if username.lower() in self.users:
            raise ValueError("Username already exists")
        password_hash = hash_password(password, algorithm)
        user = User(username=username, role=role, password_hash=password_hash)
        self.users[username.lower()] = user
        return user

    def authenticate_user(self, username: str, password: str, token: Optional[str] = None) -> bool:
        user = self.users.get(username.lower())
        if not user:
            return False
        if not verify_password(password, user.password_hash):
            return False
        if token and not verify_totp(user.totp_secret, token):
            return False
        return True

    def authorize(self, username: str, required_role: str) -> bool:
        user = self.users.get(username.lower())
        return bool(user and user.role == required_role)

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username.lower())


def hash_password(password: str, algorithm: str = "bcrypt") -> str:
    value = password.encode("utf-8")
    if algorithm == "argon2":
        hasher = argon2.PasswordHasher()
        return f"argon2${hasher.hash(password)}"
    return f"bcrypt${bcrypt.hashpw(value, bcrypt.gensalt()).decode('utf-8')}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        prefix, hash_value = password_hash.split("$", 1)
    except ValueError:
        return False

    value = password.encode("utf-8")
    if prefix == "argon2":
        hasher = argon2.PasswordHasher()
        try:
            return hasher.verify(hash_value, password)
        except argon2.exceptions.VerifyMismatchError:
            return False
    if prefix == "bcrypt":
        return bcrypt.checkpw(value, hash_value.encode("utf-8"))
    return False


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(token, valid_window=window))


def _load_common_passwords() -> set[str]:
    if not COMMON_PASSWORDS_PATH.exists():
        return set()
    with COMMON_PASSWORDS_PATH.open("r", encoding="utf-8") as handle:
        return {line.strip().lower() for line in handle if line.strip()}


def calculate_entropy(password: str) -> float:
    categories = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    charset_size = 0
    if categories["lower"]:
        charset_size += 26
    if categories["upper"]:
        charset_size += 26
    if categories["digits"]:
        charset_size += 10
    if categories["symbols"]:
        charset_size += 32
    if charset_size == 0 or len(password) == 0:
        return 0.0
    return round(len(password) * math.log2(charset_size), 2)


def complexity_score(password: str) -> int:
    entropy = calculate_entropy(password)
    length_bonus = min(max(len(password) - 8, 0), 20)
    variety = sum(
        bool(re.search(pattern, password))
        for pattern in [r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"]
    )
    variety_bonus = variety * 10
    score = int(min(max(entropy / 2 + length_bonus + variety_bonus, 0), 100))
    if is_common_password(password):
        score = min(score, 20)
    return score


def is_common_password(password: str) -> bool:
    return password.lower() in _load_common_passwords()


def detect_patterns(password: str) -> List[str]:
    findings: List[str] = []
    if re.search(r"(.)\1{2,}", password):
        findings.append("Repeated characters")
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789)", password):
        findings.append("Numeric sequence")
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password.lower():
            findings.append(f"Keyboard pattern: {pattern}")
    return findings


def strength_meter(score: int) -> str:
    if score < 35:
        return "Weak"
    if score < 65:
        return "Moderate"
    return "Strong"


def suggest_improvements(password: str) -> List[str]:
    suggestions: List[str] = []
    if len(password) < 12:
        suggestions.append("Increase length to 12 or more characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add digits.")
    if not re.search(r"[^A-Za-z0-9]", password):
        suggestions.append("Add symbols or punctuation.")
    if is_common_password(password):
        suggestions.append("Avoid common passwords or simple dictionary words.")
    if detect_patterns(password):
        suggestions.append("Avoid keyboard sequences and repeated characters.")
    return suggestions


def generate_password(
    length: int = 16,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    alphabet = ""
    if upper:
        alphabet += string.ascii_uppercase
    if lower:
        alphabet += string.ascii_lowercase
    if digits:
        alphabet += string.digits
    if symbols:
        alphabet += string.punctuation
    if not alphabet:
        raise ValueError("At least one character category must be enabled.")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def pwned_passwords_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
    response.raise_for_status()
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def estimate_crack_time(password: str, guesses_per_second: float = 1e9) -> Tuple[float, str]:
    charset_size = sum(
        bool(re.search(pattern, password))
        for pattern in [r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"]
    )
    if charset_size == 0 or len(password) == 0:
        return 0.0, "Instant"
    guesses = charset_size**len(password)
    seconds = guesses / guesses_per_second
    years = seconds / (60 * 60 * 24 * 365)
    label = "years"
    if years < 1:
        label = "seconds"
        seconds = seconds
        return seconds, label
    return round(years, 2), label
