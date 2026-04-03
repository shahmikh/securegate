import os
import json
import subprocess
from pathlib import Path


class SASTScanner:
    def __init__(self, scan_path: str = "."):
        self.scan_path = scan_path
        self.findings  = []

    def run_bandit(self) -> list:
        """Runs Bandit SAST scanner and returns findings."""
        print(f"\n🔍 SAST Scanner (Bandit) — scanning {self.scan_path}")

        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-r",               # recursive
                    self.scan_path,
                    "-f", "json",       # JSON output
                    "-ll",              # low severity and above
                    "--exclude",
                    "./.git,./venv,./node_modules,./securegate/secret_scanner.py"
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            # Bandit returns exit code 1 when issues found — that's fine
            output = result.stdout.strip()
            if not output:
                print("  ⚠️  Bandit returned no output")
                return []

            data     = json.loads(output)
            results  = data.get("results", [])
            print(f"   Issues found: {len(results)}")
            return self._parse_bandit(results)

        except subprocess.TimeoutExpired:
            print("  ❌ Bandit timed out")
            return []
        except json.JSONDecodeError as e:
            print(f"  ❌ Failed to parse Bandit output: {e}")
            return []
        except FileNotFoundError:
            print("  ❌ Bandit not installed — run: pip install bandit")
            return []

    def _parse_bandit(self, results: list) -> list:
        """Converts Bandit results to our standard finding format."""
        severity_map = {
            "HIGH":   "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW":    "LOW"
        }

        findings = []
        for r in results:
            findings.append({
                "type":        "SAST",
                "name":        r.get("test_id", "Unknown") + " — " +
                               r.get("test_name", "Unknown"),
                "severity":    severity_map.get(
                               r.get("issue_severity", "LOW"), "LOW"),
                "description": r.get("issue_text", ""),
                "file":        r.get("filename", ""),
                "line":        r.get("line_number", 0),
                "snippet":     r.get("code", "").strip()[:200],
                "cwe":         r.get("issue_cwe", {}).get("id", ""),
                "confidence":  r.get("issue_confidence", ""),
            })

        return findings

    def scan(self) -> list:
        self.findings = self.run_bandit()
        return self.findings

    def print_findings(self):
        if not self.findings:
            print("  ✅ No SAST issues detected")
            return

        severity_icons = {
            "HIGH":   "🔴",
            "MEDIUM": "🟠",
            "LOW":    "🟡"
        }

        print(f"\n{'─'*65}")
        print(f"  SAST RESULTS — {len(self.findings)} issues")
        print(f"{'─'*65}")

        for f in self.findings:
            icon = severity_icons.get(f["severity"], "⚪")
            cwe  = f"CWE-{f['cwe']}" if f["cwe"] else ""
            print(f"\n  {icon} [{f['severity']}] {f['name']} {cwe}")
            print(f"     File    : {f['file']}:{f['line']}")
            print(f"     Issue   : {f['description']}")
            if f["snippet"]:
                snippet = f["snippet"].splitlines()[0][:70]
                print(f"     Code    : {snippet}")

        print(f"\n{'─'*65}")

        from collections import Counter
        counts = Counter(f["severity"] for f in self.findings)
        print(f"  Summary: ", end="")
        for sev, icon in [("HIGH","🔴"),("MEDIUM","🟠"),("LOW","🟡")]:
            if counts[sev]:
                print(f"{icon} {sev}: {counts[sev]}  ", end="")
        print(f"\n{'─'*65}")


if __name__ == "__main__":
    import sys
    path    = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = SASTScanner(scan_path=path)
    scanner.scan()
    scanner.print_findings()
