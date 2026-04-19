import re
import math
import hashlib

# ─────────────────────────────────────────────
#  Common weak passwords dictionary
# ─────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "letmein", "monkey", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "superman", "michael", "football", "iloveyou", "admin",
    "login", "hello", "charlie", "donald", "batman",
    "trustno1", "pass", "test", "guest", "1234",
}

# ─────────────────────────────────────────────
#  Entropy calculator
# ─────────────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0.0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(password)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy * length, 2)

# ─────────────────────────────────────────────
#  Character set analysis
# ─────────────────────────────────────────────
def analyze_charset(password: str) -> dict:
    return {
        "lowercase":   bool(re.search(r"[a-z]", password)),
        "uppercase":   bool(re.search(r"[A-Z]", password)),
        "digits":      bool(re.search(r"\d", password)),
        "symbols":     bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password)),
    }

# ─────────────────────────────────────────────
#  Breach simulation via SHA-1 hash prefix
# ─────────────────────────────────────────────
def simulate_breach_check(password: str) -> bool:
    """
    Simulates a HaveIBeenPwned-style check using SHA-1 hashing.
    In a real implementation this would query the HIBP k-anonymity API.
    Here we flag passwords whose hash starts with common known prefixes.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    # Simulated list of known-breached hash prefixes (first 5 chars)
    known_breach_prefixes = {
        "B94D2",  # 'password' SHA-1 prefix
        "7C4A8",  # '123456'
        "F7C3B",  # 'qwerty'
        "0DDE5",  # 'abc123'
        "5BAA6",  # 'password' alternate
        "CBF50",  # 'letmein'
    }
    return sha1[:5] in known_breach_prefixes

# ─────────────────────────────────────────────
#  Scoring engine
# ─────────────────────────────────────────────
def score_password(password: str) -> tuple[int, list]:
    """Returns a score (0–100) and a list of penalty/bonus notes."""
    score = 0
    notes = []
    charset = analyze_charset(password)
    length = len(password)

    # Length scoring
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        notes.append("Too short — use at least 8 characters")

    # Character variety
    variety = sum(charset.values())
    score += variety * 10
    if not charset["uppercase"]:
        notes.append("Add uppercase letters (A–Z)")
    if not charset["lowercase"]:
        notes.append("Add lowercase letters (a–z)")
    if not charset["digits"]:
        notes.append("Add numbers (0–9)")
    if not charset["symbols"]:
        notes.append("Add symbols (!@#$%^&*...)")

    # Entropy bonus
    entropy = calculate_entropy(password)
    if entropy > 50:
        score += 20
    elif entropy > 30:
        score += 10

    # Penalties
    if password.lower() in COMMON_PASSWORDS:
        score -= 40
        notes.append("This is a very common password — avoid it entirely")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        notes.append("Avoid repeating characters (e.g. 'aaa', '111')")

    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|wer)", password.lower()):
        score -= 10
        notes.append("Avoid sequential patterns (e.g. '123', 'abc', 'qwe')")

    if simulate_breach_check(password):
        score -= 30
        notes.append("This password has appeared in known data breaches")

    return max(0, min(score, 100)), notes

# ─────────────────────────────────────────────
#  Strength label
# ─────────────────────────────────────────────
def get_strength_label(score: int) -> str:
    if score >= 80:
        return "STRONG 💪"
    elif score >= 60:
        return "MODERATE ⚠️"
    elif score >= 40:
        return "WEAK ❌"
    else:
        return "VERY WEAK 🚨"

# ─────────────────────────────────────────────
#  Recommendation engine
# ─────────────────────────────────────────────
def generate_recommendation(password: str, score: int) -> str:
    """Suggests a stronger version of the password."""
    if score >= 80:
        return "Your password is strong! No changes needed."

    suggestion = password
    charset = analyze_charset(password)

    if not charset["uppercase"]:
        suggestion = suggestion[:2] + suggestion[2].upper() + suggestion[3:] if len(suggestion) > 2 else suggestion.upper()
    if not charset["digits"]:
        suggestion += "42"
    if not charset["symbols"]:
        suggestion += "!#"
    if len(suggestion) < 12:
        suggestion += "Xk9@"

    return f"Consider something like: {suggestion}"

# ─────────────────────────────────────────────
#  Display results
# ─────────────────────────────────────────────
def display_results(password: str):
    score, notes = score_password(password)
    label = get_strength_label(score)
    entropy = calculate_entropy(password)
    charset = analyze_charset(password)
    breached = simulate_breach_check(password)
    recommendation = generate_recommendation(password, score)

    print("\n" + "=" * 50)
    print("       PASSWORD STRENGTH ANALYZER")
    print("=" * 50)
    print(f"  Password : {'*' * len(password)}")
    print(f"  Length   : {len(password)} characters")
    print(f"  Entropy  : {entropy} bits")
    print(f"  Score    : {score}/100")
    print(f"  Strength : {label}")
    print("-" * 50)
    print("  Character Set:")
    print(f"    Lowercase : {'✔' if charset['lowercase'] else '✘'}")
    print(f"    Uppercase : {'✔' if charset['uppercase'] else '✘'}")
    print(f"    Digits    : {'✔' if charset['digits'] else '✘'}")
    print(f"    Symbols   : {'✔' if charset['symbols'] else '✘'}")
    print(f"  Breach Check: {'⚠️  FOUND in known breaches' if breached else '✔ Not found in breach database'}")
    print("-" * 50)
    if notes:
        print("  Issues Found:")
        for note in notes:
            print(f"    • {note}")
    else:
        print("  No issues found!")
    print("-" * 50)
    print(f"  Recommendation:\n    {recommendation}")
    print("=" * 50 + "\n")

# ─────────────────────────────────────────────
#  Main CLI loop
# ─────────────────────────────────────────────
def main():
    print("\n🔐 Welcome to Password Strength Analyzer")
    print("   Type 'quit' to exit\n")
    while True:
        password = input("Enter a password to analyze: ").strip()
        if password.lower() == "quit":
            print("Goodbye!")
            break
        if not password:
            print("Please enter a password.\n")
            continue
        display_results(password)

if __name__ == "__main__":
    main()
