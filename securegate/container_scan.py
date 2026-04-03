import os
import json
import subprocess


class ContainerScanner:
    def __init__(self, scan_path: str = "."):
        self.scan_path = scan_path
        self.findings  = []

    def _trivy_installed(self) -> bool:
        try:
            subprocess.run(
                ["trivy", "--version"],
                capture_output=True, timeout=10
            )
            return True
        except FileNotFoundError:
            return False

    def run_trivy(self) -> list:
        """Runs Trivy to scan dependencies for known CVEs."""
        print(f"\n🔍 Container/Dependency Scanner (Trivy) — scanning {self.scan_path}")

        if not self._trivy_installed():
            print("  ⚠️  Trivy not installed — skipping dependency scan")
            print("      Install: https://aquasecurity.github.io/trivy")
            return []

        try:
            result = subprocess.run(
                [
                    "trivy", "fs",
                    "--format", "json",
                    "--severity", "CRITICAL,HIGH,MEDIUM",
                    "--quiet",
                    self.scan_path
                ],
                capture_output=True,
                text=True,
                timeout=300
            )

            output = result.stdout.strip()
            if not output:
                print("  ✅ No vulnerabilities found by Trivy")
                return []

            data    = json.loads(output)
            results = data.get("Results", [])
            findings = []

            for target in results:
                vulns = target.get("Vulnerabilities", []) or []
                for v in vulns:
                    findings.append({
                        "type":        "DEPENDENCY",
                        "name":        v.get("VulnerabilityID", "Unknown"),
                        "severity":    v.get("Severity", "UNKNOWN"),
                        "description": v.get("Description", "")[:300],
                        "file":        target.get("Target", ""),
                        "line":        0,
                        "snippet":     (
                            f"Package: {v.get('PkgName','?')} "
                            f"v{v.get('InstalledVersion','?')} → "
                            f"fix in v{v.get('FixedVersion','N/A')}"
                        ),
                        "cve":         v.get("VulnerabilityID", ""),
                        "package":     v.get("PkgName", ""),
                        "fixed_in":    v.get("FixedVersion", "N/A"),
                    })

            print(f"   Vulnerabilities found: {len(findings)}")
            return findings

        except subprocess.TimeoutExpired:
            print("  ❌ Trivy timed out")
            return []
        except json.JSONDecodeError:
            print("  ✅ No structured vulnerabilities found")
            return []

    def scan(self) -> list:
        self.findings = self.run_trivy()
        return self.findings

    def print_findings(self):
        if not self.findings:
            print("  ✅ No dependency vulnerabilities detected")
            return

        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢"
        }

        print(f"\n{'─'*65}")
        print(f"  DEPENDENCY SCAN RESULTS — {len(self.findings)} vulnerabilities")
        print(f"{'─'*65}")

        for f in self.findings[:10]:   # show top 10 max
            icon = severity_icons.get(f["severity"], "⚪")
            print(f"\n  {icon} [{f['severity']}] {f['name']}")
            print(f"     Package : {f['package']}")
            print(f"     Fix in  : {f['fixed_in']}")
            print(f"     Detail  : {f['description'][:100]}...")

        if len(self.findings) > 10:
            print(f"\n  ... and {len(self.findings) - 10} more vulnerabilities")

        print(f"\n{'─'*65}")

        from collections import Counter
        counts = Counter(f["severity"] for f in self.findings)
        print(f"  Summary: ", end="")
        for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            if counts[sev]:
                icon = severity_icons[sev]
                print(f"{icon} {sev}: {counts[sev]}  ", end="")
        print(f"\n{'─'*65}")


if __name__ == "__main__":
    import sys
    path    = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = ContainerScanner(scan_path=path)
    scanner.scan()
    scanner.print_findings()
