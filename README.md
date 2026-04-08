# SecureGate

> AI-Powered GitHub Pull Request Security Reviewer

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI-black?style=flat-square&logo=githubactions)
![Groq](https://img.shields.io/badge/Groq-LLaMA_3.3_70B-orange?style=flat-square)
![Bandit](https://img.shields.io/badge/Bandit-SAST-red?style=flat-square)
![Trivy](https://img.shields.io/badge/Trivy-CVE_Scanner-blue?style=flat-square)

---

## What It Does

SecureGate is a GitHub Actions bot that automatically reviews every Pull Request for security vulnerabilities, explains each finding in plain English using AI, and **blocks the merge if risk is critical.**

```
Developer opens PR
        ↓
GitHub Actions triggers SecureGate
        ↓
  ┌─────────────────────────────┐
  │  3 scanners run in parallel │
  │  • Secret Scanner           │
  │  • Bandit SAST              │
  │  • Trivy CVE Scanner        │
  └─────────────────────────────┘
        ↓
  Groq LLaMA 3.3 70B analyzes all findings
        ↓
  Risk score calculated (0–100)
        ↓
  Bot posts full report as PR comment
        ↓
  Score > 80 → Merge BLOCKED ❌
  Score < 80 → Merge APPROVED ✅
```

---

## Features

- **Secret Detection** — catches AWS keys, GitHub tokens, passwords, API keys, private keys, database URLs
- **SAST Analysis** — Bandit scans for SQL injection, command injection, insecure functions, hardcoded credentials
- **Dependency Scanning** — Trivy finds known CVEs in your Python packages
- **AI Security Review** — Groq LLaMA 3.3 explains every finding in plain English with exact fix suggestions
- **Risk Scoring** — weighted 0–100 score based on severity and finding type
- **PR Comments** — posts a beautiful markdown report directly on the PR
- **Merge Blocking** — automatically fails the GitHub Actions check if risk is too high

---

## Tech Stack

| Component | Technology |
|---|---|
| CI/CD | GitHub Actions |
| Secret Detection | Custom regex engine (15 patterns) |
| SAST | Bandit |
| Dependency Scanning | Trivy |
| AI Analysis | Groq — LLaMA 3.3 70B Versatile |
| PR Integration | PyGitHub |
| Language | Python 3.11+ |

---

##  Setup

### 1. Fork or clone this repo

```bash
git clone https://github.com/shahmikh/securegate.git
cd securegate
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Add GitHub Secret

Go to your repo → **Settings** → **Secrets and variables** → **Actions**

Add secret:
- Name: `GROQ_API_KEY`
- Value: your key from [console.groq.com](https://console.groq.com)

### 3. Open a Pull Request

SecureGate triggers automatically on every PR to `main`. Watch the bot post its review!

### 4. Run locally

```bash
cp .env.example .env
# Add your GROQ_API_KEY to .env
python securegate/scanner.py .
```

---

##  Project Structure

```
securegate/
├── .github/
│   └── workflows/
│       └── securegate.yml     # GitHub Actions trigger
├── securegate/
│   ├── scanner.py             # 🎯 Main orchestrator
│   ├── secret_scanner.py      # 🔑 Detects hardcoded secrets
│   ├── sast.py                # 🔍 Bandit SAST analysis
│   ├── container_scan.py      # 📦 Trivy CVE scanning
│   ├── ai_analyzer.py         # 🤖 Groq LLM analysis
│   ├── risk_scorer.py         # 📊 0-100 risk scoring
│   └── pr_commenter.py        # 💬 GitHub PR comments
├── tests/
│   └── vulnerable_sample.py   # Demo file with intentional vulns
├── requirements.txt
└── .env.example
```

---

##  Risk Score Breakdown

| Score | Risk Level | Merge Decision |
|---|---|---|
| 80–100 | CRITICAL | ❌ Blocked |
| 60–79 | HIGH | ❌ Blocked |
| 40–59 | MEDIUM | ⚠️ Warning |
| 20–39 | LOW | ✅ Approved |
| 0–19 | SAFE | ✅ Approved |

---

## Sample PR Comment

SecureGate posts a full markdown report on every PR including:
- Risk score with visual bar
- Executive summary from AI
- Tables of all findings by category
- Exact fix recommendations
- Merge decision with reasoning

---

## ‍Author

**Syed Shahmikh Ali**
- GitHub: [@shahmikh](https://github.com/shahmikh)
- LinkedIn: [syed-shahmikh-ali](https://linkedin.com/in/syed-shahmikh-ali-6b962b201)
- Email: syedshahmikh@gmail.com

---

## License

MIT License
