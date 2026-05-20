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
    "qwertyuiop",
    "asdfgh",
    "asdfghjkl",
    "zxcvbn",
    "password",
    "admin",
    "letmein",
]
COMMON_SUBSTITUTIONS = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "0": "o",
        "1": "i",
        "!": "i",
        "3": "e",
        "$": "s",
        "5": "s",
        "7": "t",
        "+": "t",
    }
)
SEQUENTIAL_ALPHABETS = [
    string.ascii_lowercase,
    string.ascii_lowercase[::-1],
    string.digits,
    string.digits[::-1],
]

AMBIGUOUS_CHARACTERS = set("Il1O0o{}[]()/\\'\"`~,;:.<>")
WORDLIST = [
    "able", "breeze", "canvas", "dawn", "ember", "feather", "glow", "harbor",
    "island", "jewel", "kettle", "lunar", "mosaic", "nebula", "orchid", "pioneer",
    "quartz", "raven", "sage", "tango", "umbra", "velvet", "wander", "xenon",
    "yarn", "zephyr", "apex", "brisk", "cinder", "drift", "elixir", "fjord",
    "garnet", "haven", "indigo", "jade", "kinetic", "lucid", "mythic", "nova",
    "opal", "prism", "quill", "rift", "solace", "tide", "urban", "vista",
    "whisper", "yearn", "zenith", "atlas", "brook", "crest", "ember", "flint",
]

ROLE_ADMIN = "admin"
ROLE_USER = "user"


@dataclass
class User:
    username: str
    role: str
    password_hash: str
    totp_secret: str = field(default_factory=pyotp.random_base32)


@dataclass(frozen=True)
class PasswordAnalysis:
    password: str
    entropy: float
    score: int
    strength: str
    length_score: int
    variety_score: int
    entropy_score: int
    penalties: int
    patterns: List[str]
    suggestions: List[str]
    is_dictionary_match: bool


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
    charset_size = _charset_size(password)
    if charset_size == 0 or len(password) == 0:
        return 0.0
    return round(len(password) * math.log2(charset_size), 2)


def complexity_score(password: str) -> int:
    return analyze_password_strength(password).score


def analyze_password_strength(password: str) -> PasswordAnalysis:
    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)
    dictionary_match = is_common_password(password) or is_common_password(_normalize_substitutions(password))

    length_score = _length_score(password)
    variety_score = _variety_score(password)
    entropy_score = min(int(entropy / 1.5), 35)
    penalties = _weakness_penalty(password, patterns, dictionary_match)
    score = min(max(length_score + variety_score + entropy_score - penalties, 0), 100)

    return PasswordAnalysis(
        password=password,
        entropy=entropy,
        score=score,
        strength=strength_meter(score),
        length_score=length_score,
        variety_score=variety_score,
        entropy_score=entropy_score,
        penalties=penalties,
        patterns=patterns,
        suggestions=_build_suggestions(password, patterns, dictionary_match),
        is_dictionary_match=dictionary_match,
    )


def is_common_password(password: str) -> bool:
    return password.lower() in _load_common_passwords()


def detect_patterns(password: str) -> List[str]:
    findings: List[str] = []
    lowered = password.lower()
    normalized = _normalize_substitutions(password)

    if re.search(r"(.)\1{2,}", lowered):
        findings.append("Repeated characters")
    if _contains_sequence(lowered, min_length=3):
        findings.append("Sequential characters")
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lowered:
            findings.append(f"Keyboard pattern: {pattern}")
    if normalized != lowered and is_common_password(normalized):
        findings.append(f"Common substitution for dictionary word: {normalized}")
    return findings


def strength_meter(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Moderate"
    if score < 80:
        return "Strong"
    return "Very Strong"


def suggest_improvements(password: str) -> List[str]:
    return analyze_password_strength(password).suggestions


def _build_suggestions(password: str, patterns: List[str], dictionary_match: bool) -> List[str]:
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
    if dictionary_match:
        suggestions.append("Avoid common passwords or simple dictionary words.")
    if patterns:
        suggestions.append("Avoid keyboard sequences, sequential characters, repeated characters, and predictable substitutions.")
    return suggestions


def _charset_size(password: str) -> int:
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset_size += 32
    return charset_size


def _length_score(password: str) -> int:
    length = len(password)
    if length >= 16:
        return 25
    if length >= 12:
        return 20
    if length >= 8:
        return 12
    if length >= 6:
        return 6
    return 0


def _variety_score(password: str) -> int:
    categories = [
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ]
    return sum(categories) * 10


def _weakness_penalty(password: str, patterns: List[str], dictionary_match: bool) -> int:
    penalty = 0
    if dictionary_match:
        penalty += 45
    penalty += min(len(patterns) * 12, 36)
    if len(set(password.lower())) <= 3 and password:
        penalty += 15
    return penalty


def _normalize_substitutions(password: str) -> str:
    return password.lower().translate(COMMON_SUBSTITUTIONS)


def _contains_sequence(password: str, min_length: int = 3) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", password.lower())
    if len(compact) < min_length:
        return False
    for alphabet in SEQUENTIAL_ALPHABETS:
        for size in range(min_length, min(len(compact), 6) + 1):
            for start in range(0, len(compact) - size + 1):
                if compact[start : start + size] in alphabet:
                    return True
    return False


def _build_alphabet(
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
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
    if exclude_ambiguous:
        alphabet = "".join(ch for ch in alphabet if ch not in AMBIGUOUS_CHARACTERS)
    return alphabet


def generate_password(
    length: int = 16,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    passphrase: bool = False,
) -> str:
    if passphrase:
        word_count = max(3, min(length, 12))
        return "-".join(secrets.choice(WORDLIST) for _ in range(word_count))

    alphabet = _build_alphabet(upper, lower, digits, symbols, exclude_ambiguous)
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
    charset_size = _charset_size(password)
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
