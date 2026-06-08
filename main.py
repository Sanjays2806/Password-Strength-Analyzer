import math
import re
import secrets

PREVIOUS_PASSWORDS = ["Password123!", "Admin2026*", "LetMeIn$$$"]
COMMON_PASSWORDS = ["password", "12345678", "qwerty", "password123", "welcome"]

def analyze_password(password):
    score = 0
    feedback = []
    
    if password in PREVIOUS_PASSWORDS:
        return {
            "status": "REJECTED",
            "score": 0,
            "feedback": ["This password matches a previously used password. Reuse is strictly prohibited."]
        }

    if password.lower() in COMMON_PASSWORDS:
        return {
            "status": "WEAK",
            "score": 1,
            "feedback": ["This is a highly common password, highly vulnerable to dictionary attacks."]
        }

    length = len(password)
    if length < 8:
        feedback.append("Critically short. Minimum length should be 8 characters (12+ preferred).")
    elif length >= 12:
        score += 2
    else:
        score += 1

    has_upper = re.search(r"[A-Z]", password)
    has_lower = re.search(r"[a-z]", password)
    has_digit = re.search(r"\d", password)
    has_special = re.search(r"[ !@#$%^&*(),.?\":{}|<>_+\-=\[\]\\/;`~]", password)

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 32

    varieties = sum(bool(x) for x in [has_upper, has_lower, has_digit, has_special])
    score += varieties

    if not has_upper: feedback.append("Add uppercase letters.")
    if not has_lower: feedback.append("Add lowercase letters.")
    if not has_digit: feedback.append("Add numbers.")
    if not has_special: feedback.append("Add special characters.")

    if pool_size > 0 and length > 0:
        entropy = length * math.log2(pool_size)
    else:
        entropy = 0

    if entropy < 40 or score <= 3:
        verdict = "Weak"
    elif entropy < 60 or score <= 5:
        verdict = "Moderate"
    else:
        verdict = "Strong"

    return {
        "status": verdict,
        "entropy": round(entropy, 2),
        "feedback": feedback if feedback else ["Great job! Your password meets modern security standards."]
    }

def suggest_alternative():
    words = ["Correct", "Horse", "Battery", "Staple", "Purple", "Matrix", "Cipher", "Secure", "Quantum", "Vault"]
    suggested = "-".join(secrets.choice(words) for _ in range(3)) + str(secrets.randbelow(90) + 10) + "!"
    return suggested

if __name__ == "__main__":
    print("--- Password Strength Analyzer ---")
    user_input = input("Enter a password to test: ").strip()
    
    analysis = analyze_password(user_input)
    
    print("\n--- Results ---")
    print(f"Verdict: {analysis['status']}")
    if "entropy" in analysis:
        print(f"Entropy: {analysis['entropy']} bits")
    
    print("\nFeedback:")
    for line in analysis['feedback']:
        print(f"- {line}")
        
    if analysis['status'] != "Strong":
        print(f"\nSuggested Secure Alternative: {suggest_alternative()}")
