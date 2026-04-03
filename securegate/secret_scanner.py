import os
import re
from pathlib import Path


# ── SECRET PATTERNS ───────────────────────────────────────────────
# Each pattern: (name, regex, severity, description)
SECRET_PATTERNS = [
    (
        "AWS Access Key",
        r"AKIA[0-9A-Z]{16}",
        "CRITICAL",
        "Hardcoded AWS Access Key ID detected"
    ),
    (
        "AWS Secret Key",
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "CRITICAL",
        "Hardcoded AWS Secret Access Key detected"
    ),
    (
        "Generic API Key",
        r"(?i)(api[_\-\s]?key|apikey)\s*=\s*['\"][a-zA-Z0-9\-_]{20,}['\"]",
        "HIGH",
        "Hardcoded API key detected"
    ),
    (
        "GitHub Token",
        r"ghp_[a-zA-Z0-9]{36}",
        "CRITICAL",
        "Hardcoded GitHub Personal Access Token detected"
    ),
    (
        "GitHub OAuth Token",
        r"gho_[a-zA-Z0-9]{36}",
        "CRITICAL",
        "Hardcoded GitHub OAuth Token detected"
    ),
    (
        "Slack Token",
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "HIGH",
        "Hardcoded Slack token detected"
    ),
    (
        "Stripe Secret Key",
        r"sk_live_[0-9a-zA-Z]{24,}",
        "CRITICAL",
        "Hardcoded Stripe secret key detected"
    ),
    (
        "Stripe Publishable Key",
        r"pk_live_[0-9a-zA-Z]{24,}",
        "HIGH",
        "Hardcoded Stripe publishable key detected"
    ),
    (
        "OpenAI API Key",
        r"sk-proj-[a-zA-Z0-9\-_]{40,}",
        "CRITICAL",
        "Hardcoded OpenAI API key detected"
    ),
    (
        "Groq API Key",
        r"gsk_[a-zA-Z0-9]{50,}",
        "CRITICAL",
        "Hardcoded Groq API key detected"
    ),
    (
        "Private Key Block",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "CRITICAL",
        "Private key material found in code"
    ),
    (
        "Generic Password",
        r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]",
        "HIGH",
        "Hardcoded password detected"
    ),
    (
        "Generic Secret",
        r"(?i)(secret|token)\s*=\s*['\"][a-zA-Z0-9\-_!@#$%]{10,}['\"]",
        "HIGH",
        "Hardcoded secret or token detected"
    ),
    (
        "Database URL",
        r"(?i)(mongodb|postgresql|mysql|redis):\/\/[^\s'\"]+:[^\s'\"]+@",
        "CRITICAL",
        "Database connection string with credentials detected"
    ),
    (
        "Basic Auth URL",
        r"https?:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%]+@",
        "HIGH",
        "URL with embedded credentials detected"
    ),
]

# Files and directories to skip
SKIP_DIRS = {
    ".git", "venv", "node_modules", "__pycache__",
    ".tox", "dist", "build", ".eggs"
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".lock", ".sum"
}

# Files that are allowed to contain secret-like patterns
ALLOWLIST_FILES = {
    ".env.example",
    "README.md",
    "secret_scanner.py",      # scanner itself contains patterns
}


class SecretScanner:
    def __init__(self, scan_path: str = "."):
        self.scan_path = Path(scan_path)
        self.findings  = []

    def _should_skip_file(self, filepath: Path) -> bool:
        """Returns True if file should be skipped."""
        # Skip allowlisted files
        if filepath.name in ALLOWLIST_FILES:
            return True

        # Skip binary/irrelevant extensions
        if filepath.suffix.lower() in SKIP_EXTENSIONS:
            return True

        # Skip hidden directories and known non-code dirs
        for part in filepath.parts:
            if part in SKIP_DIRS:
                return True
            if part.startswith(".") and part != ".":
                return True

        return False

    def _scan_file(self, filepath: Path) -> list:
        """Scans a single file for secret patterns."""
        file_findings = []

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            lines   = content.splitlines()

            for line_num, line in enumerate(lines, 1):
                # Skip comment lines
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for name, pattern, severity, description in SECRET_PATTERNS:
                    matches = re.findall(pattern, line)
                    if matches:
                        # Redact the actual secret value for safe logging
                        redacted = re.sub(
                            pattern,
                            lambda m: m.group()[:6] + "***REDACTED***",
                            line.strip()
                        )
                        file_findings.append({
                            "type":        "SECRET",
                            "name":        name,
                            "severity":    severity,
                            "description": description,
                            "file":        str(filepath.relative_to(
                                               self.scan_path)),
                            "line":        line_num,
                            "snippet":     redacted[:200],
                            "match_count": len(matches)
                        })

        except Exception as e:
            pass   # skip unreadable files silently

        return file_findings

    def scan(self) -> list:
        """Scans all files in scan_path recursively."""
        self.findings = []
        scanned       = 0
        skipped       = 0

        print(f"\n🔍 Secret Scanner — scanning {self.scan_path}")
        print(f"   Patterns loaded: {len(SECRET_PATTERNS)}")

        for filepath in self.scan_path.rglob("*"):
            if not filepath.is_file():
                continue

            if self._should_skip_file(filepath):
                skipped += 1
                continue

            file_findings = self._scan_file(filepath)
            self.findings.extend(file_findings)
            scanned += 1

        print(f"   Files scanned : {scanned}")
        print(f"   Files skipped : {skipped}")
        print(f"   Secrets found : {len(self.findings)}")

        return self.findings

    def print_findings(self):
        """Pretty-prints findings to terminal."""
        if not self.findings:
            print("\n  ✅ No secrets detected")
            return

        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢"
        }

        print(f"\n{'─'*65}")
        print(f"  SECRET SCAN RESULTS — {len(self.findings)} findings")
        print(f"{'─'*65}")

        for f in self.findings:
            icon = severity_icons.get(f["severity"], "⚪")
            print(f"\n  {icon} [{f['severity']}] {f['name']}")
            print(f"     File    : {f['file']}:{f['line']}")
            print(f"     Issue   : {f['description']}")
            print(f"     Snippet : {f['snippet'][:80]}...")

        print(f"\n{'─'*65}")

        # Summary by severity
        from collections import Counter
        counts = Counter(f["severity"] for f in self.findings)
        print(f"  Summary: ", end="")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[sev]:
                print(f"{severity_icons[sev]} {sev}: {counts[sev]}  ", end="")
        print(f"\n{'─'*65}")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner  = SecretScanner(scan_path=path)
    findings = scanner.scan()
    scanner.print_findings()
    print(f"\n{'═'*65}")
    print(f"  Total secrets found: {len(findings)}")
    print(f"{'═'*65}")
