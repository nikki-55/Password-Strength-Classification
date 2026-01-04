import math
import re
import string

def load_common_passwords(file_path="common_passwords.txt"):
    try:
        with open(file_path, "r") as f:
            return [line.strip().lower() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        return []

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = load_common_passwords()

    # 1) Length
    def length_score(self, password):
        length = len(password)
        if length < 8:
            return 0
        elif 8 <= length <= 12:
            return 1
        else:
            return 2

    # 2) Character diversity
    def diversity_score(self, password):
        buckets = 0
        if any(c.islower() for c in password): buckets += 1
        if any(c.isupper() for c in password): buckets += 1
        if any(c.isdigit() for c in password): buckets += 1
        if any(c in string.punctuation for c in password): buckets += 1
        if buckets <= 1: return 0
        if buckets == 2: return 1
        return 2

    # 3) Entropy (approximate)
    def entropy_score(self, password):
        charset = 0
        if any(c.islower() for c in password): charset += 26
        if any(c.isupper() for c in password): charset += 26
        if any(c.isdigit() for c in password): charset += 10
        if any(c in string.punctuation for c in password): charset += 32
        if charset == 0: return 0
        entropy_bits = len(password) * math.log2(charset)
        if entropy_bits < 30: return 0
        if entropy_bits < 50: return 1
        return 2

    # 4) Common patterns/dictionary
    def common_pattern_score(self, password):
        p = password.lower()
        if p in self.common_passwords:
            return 0
        if re.search(r"(123|abc|qwerty|password|111|000)", p):
            return 0
        return 2

    # 5) Repetition / sequences
    def repetition_score(self, password):
        p = password
        if re.search(r"(.)\1\1", p):  # any triple repeat
            return 0
        if re.search(r"(0123|1234|2345|abcd|qwerty)", p.lower()):
            return 0
        return 2

    def evaluate(self, password):
        total = (
            self.length_score(password)
            + self.diversity_score(password)
            + self.entropy_score(password)
            + self.common_pattern_score(password)
            + self.repetition_score(password)
        )
        if total <= 2: label = "Very Weak"
        elif total <= 4: label = "Weak"
        elif total <= 6: label = "Medium"
        elif total <= 8: label = "Strong"
        else: label = "Very Strong"
        return total, label, self.suggestions(password, total)

    def suggestions(self, password, total_score):
        tips = []
        if len(password) < 8: tips.append("Use at least 8 characters.")
        if not any(c.isupper() for c in password): tips.append("Add uppercase letters.")
        if not any(c.islower() for c in password): tips.append("Add lowercase letters.")
        if not any(c.isdigit() for c in password): tips.append("Include numbers.")
        if not any(c in string.punctuation for c in password): tips.append("Add special symbols (!,@,#, etc.).")
        if re.search(r"(123|abc|password|qwerty)", password.lower()):
            tips.append("Avoid common patterns or sequences.")
        if total_score >= 8:
            tips.append("Your password is strong!")
        return tips
