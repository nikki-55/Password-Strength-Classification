# gui.py — Password Strength Studio (with Attacker Speed slider + History log)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import math, re, string, csv
from password_checker import PasswordStrengthChecker
import time

# Visual bands
BANDS = [
    ("Very Weak", 0, 2, "#e53935", 0.15),
    ("Weak", 3, 4, "#fb8c00", 0.35),
    ("Medium", 5, 6, "#fdd835", 0.55),
    ("Strong", 7, 8, "#43a047", 0.8),
    ("Very Strong", 9, 10, "#1e88e5", 1.0),
]

def band_for_score(score):
    for name, lo, hi, color, fill in BANDS:
        if lo <= score <= hi:
            return name, color, fill
    return "Very Weak", "#e53935", 0.15

# Entropy & crack-time estimation
def entropy_bits(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += 32
    if charset == 0: return 0.0
    return len(password) * math.log2(charset)

def human_time(seconds):
    if seconds < 1:
        return f"{seconds:.2e} sec"
    mins = seconds / 60
    if mins < 1:
        return f"{seconds:.2f} sec"
    hours = mins / 60
    if hours < 1:
        return f"{mins:.2f} min"
    days = hours / 24
    if days < 1:
        return f"{hours:.2f} hr"
    years = days / 365
    if years < 1:
        return f"{days:.2f} days"
    if years < 1000:
        return f"{years:.2f} years"
    return f"> {years:.2e} years"

def estimate_crack_time(entropy, guesses_per_second=1e9):
    if entropy <= 0: return "Instant"
    # Cap entropy to avoid extremely large exponent math issues
    if entropy > 1200:
        return "> extremely large"
    guesses = 2 ** entropy
    seconds = guesses / guesses_per_second
    return human_time(seconds)

# Weak-segment extractor (explainable)
def find_weak_segments(password, common_list):
    segments = []
    p = password
    lower = p.lower()

    for w in common_list:
        if w and w in lower:
            segments.append((w, "Common dictionary word"))

    for m in re.finditer(r"(\d{3,})", p):
        segments.append((m.group(1), "Numeric sequence"))

    for m in re.finditer(r"([A-Za-z]{3,})", p):
        segments.append((m.group(1), "Alphabetic sequence"))

    for m in re.finditer(r"(.)\1{2,}", p):
        segments.append((m.group(0), "Repeated characters"))

    for m in re.finditer(r"(19\d{2}|20\d{2})", p):
        segments.append((m.group(1), "Year-like sequence"))

    kb = re.search(r"(qwerty|asdf|zxcv|password|admin|welcome)", lower)
    if kb:
        segments.append((kb.group(1), "Keyboard/common pattern"))

    uniq = []
    seen = set()
    for seg in segments:
        if seg[0] not in seen:
            uniq.append(seg)
            seen.add(seg[0])
    return uniq

# Smart password generator (readable + secure)
def smart_suggest(password):
    root = "Secure"
    m = re.search(r"[A-Za-z]{4,}", password)
    if m:
        root = m.group(0).capitalize()

    generated = f"{root}@!24"
    while len(generated) < 12:
        generated += "X9"
    return generated

# Utility to mask password in the history view for privacy
def mask_password(pwd):
    if not pwd:
        return ""
    if len(pwd) <= 4:
        return "*" * len(pwd)
    return pwd[:2] + "*" * (len(pwd)-4) + pwd[-2:]

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Studio — Advanced")
        self.geometry("880x640")
        self.resizable(False, False)
        self.checker = PasswordStrengthChecker()
        self.history = []  # list of dicts

        # Top input
        top = tk.Frame(self)
        top.pack(pady=8)
        tk.Label(top, text="Enter Password:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky="w")
        self.var_pwd = tk.StringVar()
        self.entry = tk.Entry(top, textvariable=self.var_pwd, show="•", width=52, font=("Segoe UI", 11))
        self.entry.grid(row=1, column=0, padx=(0,6))
        self.show_var = tk.BooleanVar()
        tk.Checkbutton(top, text="Show", variable=self.show_var, command=self.toggle_show).grid(row=1, column=1)

        # Strength label and bar
        self.lbl_strength = tk.Label(self, text="Strength: —", font=("Segoe UI", 12, "bold"))
        self.lbl_strength.pack(pady=(8,4))
        self.style = ttk.Style(self)
        self.style.theme_use("default")
        self.style.configure("Strength.Horizontal.TProgressbar", thickness=22)
        self.pbar = ttk.Progressbar(self, orient="horizontal", length=820,
                                    mode="determinate", maximum=100,
                                    style="Strength.Horizontal.TProgressbar")
        self.pbar.pack()

        # Entropy, crack time and attacker speed slider
        info = tk.Frame(self)
        info.pack(pady=6)
        self.lbl_entropy = tk.Label(info, text="Entropy: — bits", font=("Segoe UI", 10))
        self.lbl_entropy.grid(row=0, column=0, padx=12)
        self.lbl_crack = tk.Label(info, text="Estimated crack time: —", font=("Segoe UI", 10))
        self.lbl_crack.grid(row=0, column=1, padx=12)

        # Attacker speed control (10^exp guesses/sec)
        speed_frame = tk.Frame(info)
        speed_frame.grid(row=0, column=2, padx=12)
        tk.Label(speed_frame, text="Attacker speed (guesses/sec):", font=("Segoe UI",9)).pack(anchor="w")
        # exponent from 3..12 (1e3 to 1e12)
        self.speed_exp = tk.IntVar(value=9)  # default 1e9
        self.speed_slider = tk.Scale(speed_frame, from_=3, to=12, orient="horizontal",
                                     variable=self.speed_exp, showvalue=True, length=200,
                                     command=self.on_speed_change)
        self.speed_slider.pack()
        self.lbl_speed_val = tk.Label(speed_frame, text="1e9 guesses/sec", font=("Segoe UI",9))
        self.lbl_speed_val.pack()

        # Main middle: Weak segments and suggestions and actions
        mid = tk.Frame(self)
        mid.pack(pady=8)
        left = tk.Frame(mid)
        left.grid(row=0, column=0, padx=8)
        right = tk.Frame(mid)
        right.grid(row=0, column=1, padx=8)

        tk.Label(left, text="Weak Segments (explainable):", font=("Segoe UI", 10, "underline")).pack(anchor="w")
        self.txt_weak = tk.Text(left, width=48, height=12, font=("Consolas", 10))
        self.txt_weak.pack()
        self.txt_weak.config(state="disabled")

        tk.Label(right, text="Actionable Suggestions:", font=("Segoe UI", 10, "underline")).pack(anchor="w")
        self.txt_sugg = tk.Text(right, width=48, height=12, font=("Consolas", 10))
        self.txt_sugg.pack()
        self.txt_sugg.config(state="disabled")

        # Bottom left: suggestion + controls
        bottom = tk.Frame(self)
        bottom.pack(pady=8, fill="x")
        leftb = tk.Frame(bottom)
        leftb.grid(row=0, column=0, padx=8, sticky="w")
        tk.Label(leftb, text="Suggested Improved Password:", font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w")
        self.var_suggest = tk.StringVar()
        self.entry_suggest = tk.Entry(leftb, textvariable=self.var_suggest, width=44, font=("Segoe UI", 11))
        self.entry_suggest.grid(row=1, column=0, padx=(0,8))

        btns = tk.Frame(leftb)
        btns.grid(row=1, column=1, sticky="n")
        tk.Button(btns, text="Generate", width=12, command=self.on_generate).pack(pady=(0,4))
        tk.Button(btns, text="Copy", width=12, command=self.copy_suggestion).pack(pady=(0,4))
        tk.Button(btns, text="Export CSV", width=12, command=self.export_csv).pack(pady=(0,4))

        # Bottom right: History table and history controls
        hist_frame = tk.Frame(bottom)
        hist_frame.grid(row=0, column=1, padx=12, sticky="e")

        tk.Label(hist_frame, text="Session History:", font=("Segoe UI", 10, "underline")).pack(anchor="w")
        self.tree = ttk.Treeview(hist_frame, columns=("pwd","score","label","entropy","crack","suggested"), show="headings", height=8)
        self.tree.column("pwd", width=160, anchor="w")
        self.tree.column("score", width=60, anchor="center")
        self.tree.column("label", width=90, anchor="center")
        self.tree.column("entropy", width=90, anchor="center")
        self.tree.column("crack", width=160, anchor="center")
        self.tree.column("suggested", width=200, anchor="w")
        self.tree.heading("pwd", text="Password (masked)")
        self.tree.heading("score", text="Score")
        self.tree.heading("label", text="Label")
        self.tree.heading("entropy", text="Entropy(bits)")
        self.tree.heading("crack", text="Crack Time")
        self.tree.heading("suggested", text="Suggested")

        self.tree.pack()
        # double click to copy suggestion
        self.tree.bind("<Double-1>", self.on_history_double)

        hbtns = tk.Frame(hist_frame)
        hbtns.pack(pady=(6,0))
        tk.Button(hbtns, text="Add to History", width=14, command=self.add_to_history).pack(side="left", padx=4)
        tk.Button(hbtns, text="Save History (CSV)", width=14, command=self.save_history_csv).pack(side="left", padx=4)
        tk.Button(hbtns, text="Clear History", width=14, command=self.clear_history).pack(side="left", padx=4)

        # Bind input changes
        self.var_pwd.trace_add("write", self.on_change)
        self.entry.focus()

    # ---------- Event handlers ----------
    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "•")

    def on_speed_change(self, *_):
        exp = self.speed_exp.get()
        self.lbl_speed_val.config(text=f"1e{exp} guesses/sec")
        # update crack time immediately
        self.on_change()

    def on_change(self, *_):
        pwd = self.var_pwd.get()
        if not pwd:
            self.clear_ui()
            return

        score, label, suggestions = self.checker.evaluate(pwd)
        name, color, fill = band_for_score(score)
        bits = entropy_bits(pwd)
        # compute crack time using selected speed
        guesses_per_sec = 10 ** self.speed_exp.get()
        etime = estimate_crack_time(bits, guesses_per_sec)
        weak = find_weak_segments(pwd, self.checker.common_passwords)
        self.update_ui(score, label, color, fill, bits, etime, weak, suggestions)

    def clear_ui(self):
        self.lbl_strength.config(text="Strength: —")
        self.pbar["value"] = 0
        self.style.configure("Strength.Horizontal.TProgressbar", background="#999")
        self.lbl_entropy.config(text="Entropy: — bits")
        self.lbl_crack.config(text="Estimated crack time: —")
        self.txt_weak.config(state="normal"); self.txt_weak.delete("1.0","end"); self.txt_weak.config(state="disabled")
        self.txt_sugg.config(state="normal"); self.txt_sugg.delete("1.0","end"); self.txt_sugg.config(state="disabled")
        self.var_suggest.set("")

    def update_ui(self, score, label, color, fill, bits, etime, weak, suggestions):
        self.lbl_strength.config(text=f"Strength: {label} (Score {score}/10)")
        self.style.configure("Strength.Horizontal.TProgressbar", background=color)
        self.pbar["value"] = int(fill * 100)
        self.lbl_entropy.config(text=f"Entropy: {bits:.1f} bits")
        self.lbl_crack.config(text=f"Estimated crack time: {etime}")

        # Weak segments
        self.txt_weak.config(state="normal")
        self.txt_weak.delete("1.0","end")
        if weak:
            for seg, reason in weak:
                self.txt_weak.insert("end", f"• '{seg}' — {reason}\n")
        else:
            self.txt_weak.insert("end", "No weak segments found.\n")
        self.txt_weak.config(state="disabled")

        # Suggestions from checker
        self.txt_sugg.config(state="normal")
        self.txt_sugg.delete("1.0","end")
        for s in suggestions:
            self.txt_sugg.insert("end", f"• {s}\n")
        self.txt_sugg.config(state="disabled")

        # auto-suggest improved password (do not overwrite if user edited)
        if not self.var_suggest.get():
            self.var_suggest.set(smart_suggest(self.var_pwd.get()))

    # ---------- History functions ----------
    def add_to_history(self):
        pwd = self.var_pwd.get()
        if not pwd:
            messagebox.showinfo("History", "Type a password first to add.")
            return
        score, label, suggestions = self.checker.evaluate(pwd)
        bits = entropy_bits(pwd)
        guesses_per_sec = 10 ** self.speed_exp.get()
        etime = estimate_crack_time(bits, guesses_per_sec)
        suggested = self.var_suggest.get() or smart_suggest(pwd)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "pwd": pwd,
            "pwd_masked": mask_password(pwd),
            "score": score,
            "label": label,
            "entropy": f"{bits:.1f}",
            "crack": etime,
            "suggested": suggested,
            "time": timestamp
        }
        self.history.append(entry)
        self._insert_history_row(entry)

    def _insert_history_row(self, entry):
        self.tree.insert("", "end", values=(entry["pwd_masked"], entry["score"], entry["label"],
                                           entry["entropy"], entry["crack"], entry["suggested"]))

    def save_history_csv(self):
        if not self.history:
            messagebox.showinfo("Save History", "History is empty.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp","Password(masked)","Score","Label","Entropy(bits)","CrackTime","Suggested"])
            for e in self.history:
                w.writerow([e["time"], e["pwd_masked"], e["score"], e["label"], e["entropy"], e["crack"], e["suggested"]])
        messagebox.showinfo("Saved", f"History saved to:\n{path}")

    def clear_history(self):
        if not self.history:
            return
        if not messagebox.askyesno("Clear History", "Clear session history?"):
            return
        self.history = []
        for i in self.tree.get_children():
            self.tree.delete(i)

    def on_history_double(self, event):
        # copy suggested password from clicked row to clipboard
        item = self.tree.identify_row(event.y)
        if not item:
            return
        vals = self.tree.item(item, "values")
        # suggested is last column (index 5)
        suggested = vals[5] if len(vals) > 5 else ""
        if suggested:
            self.clipboard_clear()
            self.clipboard_append(suggested)
            messagebox.showinfo("Copied", "Suggested password copied to clipboard.")

    # ---------- Other UI actions ----------
    def on_generate(self):
        pwd = self.var_pwd.get()
        if not pwd:
            messagebox.showinfo("Generate", "Enter a password first.")
            return
        new = smart_suggest(pwd)
        self.var_suggest.set(new)
        score, label, _ = self.checker.evaluate(new)
        bits = entropy_bits(new)
        guesses_per_sec = 10 ** self.speed_exp.get()
        etime = estimate_crack_time(bits, guesses_per_sec)
        messagebox.showinfo("Generated", f"Suggested: {new}\n\nScore: {label} ({score}/10)\nEntropy: {bits:.1f} bits\nCrack time: {etime}")

    def copy_suggestion(self):
        s = self.var_suggest.get()
        if s:
            self.clipboard_clear()
            self.clipboard_append(s)
            messagebox.showinfo("Copied", "Suggested password copied!")

    def export_csv(self):
        pwd = self.var_pwd.get()
        if not pwd:
            messagebox.showinfo("Export", "Enter a password first.")
            return
        score, label, suggestions = self.checker.evaluate(pwd)
        bits = entropy_bits(pwd)
        suggested = self.var_suggest.get() or smart_suggest(pwd)
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Password Tested","Score","Label","Entropy(bits)","CrackTime","Suggested Password","Suggestions"])
            w.writerow([pwd, score, label, f"{bits:.1f}", estimate_crack_time(bits, 10 ** self.speed_exp.get()), suggested, " | ".join(suggestions)])
        messagebox.showinfo("Exported", f"Saved to: {path}")

if __name__ == "__main__":
    App().mainloop()
