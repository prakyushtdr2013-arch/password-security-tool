# Password Strength Analysis Engine

The password analysis engine lives in `password_security_tool.core`. The main entry point is:

```python
from password_security_tool.core import analyze_password_strength

analysis = analyze_password_strength("S3cure!Pa55wordVault")
print(analysis.score, analysis.strength, analysis.patterns)
```

## What It Analyses

- Entropy using `length * log2(character_set_size)`.
- Length strength using tiered length points.
- Character variety across lowercase, uppercase, numbers, and special characters.
- Dictionary attack risk using `data/common_passwords.txt`.
- Common substitution attacks by normalizing values such as `@ -> a`, `0 -> o`, `$ -> s`, and `3 -> e`.
- Keyboard patterns such as `qwerty`, `asdfgh`, and `zxcvbn`.
- Sequential patterns such as `abc`, `cba`, `123`, and `321`.
- Repeated characters such as `aaaaaa`.

## Scoring Method

The score is out of 100:

```text
score = length_score + variety_score + entropy_score - weakness_penalties
```

- `length_score`: up to 25 points.
- `variety_score`: up to 40 points, 10 points each for lowercase, uppercase, numbers, and symbols.
- `entropy_score`: up to 35 points.
- `weakness_penalties`: subtracts points for dictionary matches, repeated characters, keyboard patterns, sequential characters, and predictable substitutions.

## Strength Classification

```text
0-19    Very Weak
20-39   Weak
40-59   Moderate
60-79   Strong
80-100  Very Strong
```

## Sample Test Cases

```python
from password_security_tool.core import analyze_password_strength, detect_patterns

assert analyze_password_strength("password").strength == "Very Weak"
assert analyze_password_strength("P@ssw0rd").is_dictionary_match
assert "Repeated characters" in detect_patterns("aaaaaa")
assert "Sequential characters" in detect_patterns("abc123")
assert any("Keyboard pattern" in item for item in detect_patterns("qwerty1234"))
assert analyze_password_strength("S3cure!Pa55wordVault").strength in {"Strong", "Very Strong"}
```
