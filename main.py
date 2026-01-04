from password_checker import PasswordStrengthChecker

def run():
    checker = PasswordStrengthChecker()
    while True:
        pwd = input("Enter a password (or type 'exit' to quit): ")
        if pwd.lower() == "exit":
            break
        score, label, suggestions = checker.evaluate(pwd)
        print(f"\nPassword Strength: {label} (Score: {score}/10)")
        print("Suggestions:")
        for s in suggestions:
            print(f" - {s}")
        print("\n" + "-"*50 + "\n")

if __name__ == "__main__":
    run()

