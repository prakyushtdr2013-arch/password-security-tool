import re

from password_security_tool.core import (
    analyze_password_strength,
    calculate_entropy,
    complexity_score,
    detect_patterns,
    generate_password,
    hash_password,
    is_common_password,
    strength_meter,
    verify_password,
)


def test_calculate_entropy_runs():
    entropy = calculate_entropy("P@ssw0rd123")
    assert entropy > 0


def test_complexity_score_and_strength():
    weak = complexity_score("password")
    strong = complexity_score("S3cure!Pa55wordVault")
    assert weak < strong
    assert strength_meter(weak) == "Very Weak"
    assert strength_meter(strong) in {"Strong", "Very Strong"}


def test_password_analysis_exposes_scoring_breakdown():
    analysis = analyze_password_strength("S3cure!Pa55wordVault")
    assert analysis.entropy > 0
    assert analysis.length_score > 0
    assert analysis.variety_score == 40
    assert analysis.score >= 60
    assert analysis.strength in {"Strong", "Very Strong"}


def test_detect_patterns():
    patterns = detect_patterns("qwerty1234")
    assert any("Keyboard pattern" in p for p in patterns)
    assert "Sequential characters" in patterns


def test_detect_common_substitution_dictionary_attack():
    analysis = analyze_password_strength("P@ssw0rd")
    assert analysis.is_dictionary_match
    assert any("Common substitution" in p for p in analysis.patterns)
    assert analysis.score < 40


def test_detect_repeated_and_alpha_numeric_sequences():
    repeated = detect_patterns("aaaaaa")
    sequential = detect_patterns("abc123")
    assert "Repeated characters" in repeated
    assert "Sequential characters" in sequential


def test_generate_password_length():
    value = generate_password(length=20)
    assert len(value) == 20
    assert re.search(r"[A-Z]", value)
    assert re.search(r"[a-z]", value)
    assert re.search(r"[0-9]", value)


def test_generate_password_excludes_ambiguous():
    value = generate_password(length=32, exclude_ambiguous=True)
    assert not re.search(r"[Il1O0o]", value)


def test_generate_passphrase_style():
    value = generate_password(length=5, passphrase=True)
    assert value.count("-") == 4
    assert len(value.split("-")) == 5
    assert re.search(r"^[a-z]+(-[a-z]+)+$", value)


def test_hash_and_verify_password():
    original = "S3curePa$$"
    hashed = hash_password(original, algorithm="bcrypt")
    assert verify_password(original, hashed)


def test_common_password_detection():
    assert is_common_password("password")
    assert not is_common_password("Uniqu3P@ssw0rd!")
