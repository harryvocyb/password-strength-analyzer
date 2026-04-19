# 🔐 Password Strength Analyzer
A command-line tool built in Python that evaluates password strength using entropy analysis, character diversity scoring, dictionary checks, and breach detection simulation.
Built as part of my cybersecurity learning journey at Montgomery College.


```
==================================================
       PASSWORD STRENGTH ANALYZER
==================================================
  Password : *****************
  Length   : 17 characters
  Entropy  : 63.49 bits
  Score    : 90/100
  Strength : STRONG 💪
--------------------------------------------------
  Character Set:
    Lowercase : ✔
    Uppercase : ✔
    Digits    : ✔
    Symbols   : ✔
  Breach Check: ✔ Not found in breach database
--------------------------------------------------
  No issues found!
--------------------------------------------------
  Recommendation:
    Your password is strong! No changes needed.
==================================================
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔢 Entropy Calculator | Measures true password randomness using Shannon entropy |
| 🔤 Character Set Analysis | Checks for lowercase, uppercase, digits, and symbols |
| 📖 Dictionary Check | Flags passwords from a list of 30+ commonly used passwords |
| 🔴 Breach Detection | Simulates HaveIBeenPwned-style SHA-1 hash prefix checking |
| 🔁 Pattern Detection | Catches sequential (`123`, `abc`, `qwe`) and repeated (`aaa`) patterns |
| 📊 Score 0–100 | Weighted scoring system with penalty and bonus rules |
| 💡 Recommendations | Suggests a stronger version of your password |

---

## 🚀 Getting Started

### Requirements

- Python 3.10 or higher
- No external libraries needed — uses only the Python standard library

### Installation

```bash
git clone https://github.com/hyvocyb/password-strength-analyzer.git
cd password-strength-analyzer
```

### Run

```bash
python3 password_strength_analyzer.py
```

---

## 🧪 Example Results

| Password | Score | Strength |
|---|---|---|
| `password` | 0/100 | VERY WEAK 🚨 |
| `test123` | 10/100 | VERY WEAK 🚨 |
| `Hello@99` | 60/100 | MODERATE ⚠️ |
| `P@ssw0rd!Secure42` | 90/100 | STRONG 💪 |

---

## 🧠 How Scoring Works

```
Base score starts at 0

+ 10–30 pts   Password length (8 / 12 / 16+ characters)
+ 10 pts each Character variety (lowercase, uppercase, digits, symbols)
+ 10–20 pts   Entropy bonus (> 30 bits / > 50 bits)

- 40 pts      Common password match
- 30 pts      Found in breach simulation
- 10 pts      Repeating character patterns
- 10 pts      Sequential character patterns

Final score clamped between 0 and 100
```

---

## 📁 Project Structure

```
password-strength-analyzer/
│
├── password_strength_analyzer.py   # Main script
└── README.md                       # You are here
```

---

## 🔭 Future Improvements

- [ ] Integrate live HaveIBeenPwned API (k-anonymity model)
- [ ] Add a password generator for strong random passwords
- [ ] Build a simple GUI using Tkinter
- [ ] Export analysis report to PDF

---

## 👤 Author

**Hy Khang Vo**
- LinkedIn: [linkedin.com/in/hyvocyb](https://linkedin.com/in/hyvocyb)
- Email: harry.vo.cyb@gmail.com

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
