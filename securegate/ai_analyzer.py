import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL  = "llama-3.3-70b-versatile"


class AIAnalyzer:
    def __init__(self):
        self.analysis = {}

    def _build_prompt(self, all_findings: list, repo_name: str = "") -> str:
        """Builds the security analysis prompt from all findings."""

        # Group findings by type
        secrets     = [f for f in all_findings if f["type"] == "SECRET"]
        sast        = [f for f in all_findings if f["type"] == "SAST"]
        deps        = [f for f in all_findings if f["type"] == "DEPENDENCY"]

        # Format secrets section
        secrets_text = ""
        if secrets:
            secrets_text = "\nSECRETS DETECTED:\n"
            for i, s in enumerate(secrets[:5], 1):   # max 5
                secrets_text += (
                    f"{i}. [{s['severity']}] {s['name']}\n"
                    f"   File: {s['file']} line {s['line']}\n"
                    f"   Detail: {s['description']}\n"
                    f"   Snippet: {s['snippet'][:100]}\n\n"
                )

        # Format SAST section
        sast_text = ""
        if sast:
            sast_text = "\nSTATIC ANALYSIS ISSUES (Bandit):\n"
            for i, s in enumerate(sast[:8], 1):   # max 8
                sast_text += (
                    f"{i}. [{s['severity']}] {s['name']}\n"
                    f"   File: {s['file']} line {s['line']}\n"
                    f"   Issue: {s['description']}\n"
                    f"   Code: {s['snippet'][:100]}\n\n"
                )

        # Format dependency section
        deps_text = ""
        if deps:
            deps_text = "\nVULNERABLE DEPENDENCIES (Trivy):\n"
            for i, d in enumerate(deps[:5], 1):   # max 5
                deps_text += (
                    f"{i}. [{d['severity']}] {d['name']}\n"
                    f"   Package: {d.get('package','?')} → "
                    f"fix in {d.get('fixed_in','N/A')}\n"
                    f"   Detail: {d['description'][:150]}\n\n"
                )

        total   = len(all_findings)
        crit    = len([f for f in all_findings if f["severity"] == "CRITICAL"])
        high    = len([f for f in all_findings if f["severity"] == "HIGH"])
        medium  = len([f for f in all_findings if f["severity"] == "MEDIUM"])

        prompt = f"""You are an expert application security engineer (AppSec) reviewing a Pull Request.

REPOSITORY: {repo_name or "unknown"}
TOTAL FINDINGS: {total} ({crit} CRITICAL, {high} HIGH, {medium} MEDIUM)
{secrets_text}{sast_text}{deps_text}

Provide a security review in this EXACT format:

OVERALL_RISK: [CRITICAL / HIGH / MEDIUM / LOW / SAFE]

EXECUTIVE_SUMMARY:
[2-3 sentences summarizing the security posture of this PR. Be direct and specific.]

TOP_ISSUES:
1. [Most critical issue and why it matters]
2. [Second most critical issue]
3. [Third most critical issue]

FIXES:
1. [Exact fix for issue 1 — include code example if relevant]
2. [Exact fix for issue 2]
3. [Exact fix for issue 3]

MERGE_RECOMMENDATION: [BLOCK / APPROVE_WITH_WARNINGS / APPROVE]
MERGE_REASON: [One sentence explaining the merge recommendation]"""

        return prompt

    def analyze(self, all_findings: list,
                repo_name: str = "") -> dict:
        """
        Sends all scanner findings to Groq LLM.
        Returns structured analysis dict.
        """
        if not all_findings:
            return {
                "overall_risk":        "SAFE",
                "executive_summary":   "No security issues detected in this PR.",
                "top_issues":          [],
                "fixes":               [],
                "merge_recommendation":"APPROVE",
                "merge_reason":        "No security findings detected.",
                "raw":                 ""
            }

        print(f"\n🤖 Sending {len(all_findings)} findings to Groq LLM...")

        prompt   = self._build_prompt(all_findings, repo_name)
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=1000
        )

        raw = response.choices[0].message.content.strip()
        return self._parse_response(raw)

    def _parse_response(self, raw: str) -> dict:
        """Parses the LLM response into a structured dict."""
        result = {
            "overall_risk":         "UNKNOWN",
            "executive_summary":    "",
            "top_issues":           [],
            "fixes":                [],
            "merge_recommendation": "BLOCK",
            "merge_reason":         "",
            "raw":                  raw
        }

        current_section = None

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("OVERALL_RISK:"):
                result["overall_risk"] = line.replace(
                    "OVERALL_RISK:", "").strip()

            elif line.startswith("EXECUTIVE_SUMMARY:"):
                current_section = "summary"
                text = line.replace("EXECUTIVE_SUMMARY:", "").strip()
                if text:
                    result["executive_summary"] = text

            elif line.startswith("TOP_ISSUES:"):
                current_section = "issues"

            elif line.startswith("FIXES:"):
                current_section = "fixes"

            elif line.startswith("MERGE_RECOMMENDATION:"):
                result["merge_recommendation"] = line.replace(
                    "MERGE_RECOMMENDATION:", "").strip()
                current_section = None

            elif line.startswith("MERGE_REASON:"):
                result["merge_reason"] = line.replace(
                    "MERGE_REASON:", "").strip()

            elif current_section == "summary" and line:
                result["executive_summary"] += " " + line

            elif current_section == "issues":
                if line and line[0].isdigit() and len(line) > 1 \
                        and line[1] in ".)":
                    result["top_issues"].append(line[2:].strip())

            elif current_section == "fixes":
                if line and line[0].isdigit() and len(line) > 1 \
                        and line[1] in ".)":
                    result["fixes"].append(line[2:].strip())

        result["executive_summary"] = result["executive_summary"].strip()
        return result

    def print_analysis(self, analysis: dict):
        """Pretty-prints the AI analysis."""
        risk_icons = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
            "SAFE":     "✅",
            "UNKNOWN":  "⚪"
        }

        merge_icons = {
            "BLOCK":                "❌",
            "APPROVE_WITH_WARNINGS":"⚠️",
            "APPROVE":              "✅"
        }

        risk    = analysis["overall_risk"]
        merge   = analysis["merge_recommendation"]
        r_icon  = risk_icons.get(risk, "⚪")
        m_icon  = merge_icons.get(merge, "⚪")

        print(f"\n{'▓'*65}")
        print(f"  🤖 AI SECURITY ANALYSIS")
        print(f"{'▓'*65}")
        print(f"\n  Overall Risk  : {r_icon} {risk}")
        print(f"  Merge Decision: {m_icon} {merge}")
        print(f"\n  EXECUTIVE SUMMARY:")
        print(f"  {analysis['executive_summary']}")

        if analysis["top_issues"]:
            print(f"\n  TOP SECURITY ISSUES:")
            for i, issue in enumerate(analysis["top_issues"], 1):
                print(f"  {i}. {issue}")

        if analysis["fixes"]:
            print(f"\n  RECOMMENDED FIXES:")
            for i, fix in enumerate(analysis["fixes"], 1):
                print(f"  {i}. {fix}")

        print(f"\n  MERGE REASON: {analysis['merge_reason']}")
        print(f"\n{'▓'*65}")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))

    from securegate.secret_scanner import SecretScanner
    from securegate.sast           import SASTScanner
    from securegate.container_scan import ContainerScanner

    path = sys.argv[1] if len(sys.argv) > 1 else "."

    print("🔐 SecureGate — AI Security Analyzer Test\n")

    # Run all 3 scanners
    print("Running all scanners...")
    secret_findings = SecretScanner(scan_path=path).scan()
    sast_findings   = SASTScanner(scan_path=path).scan()
    trivy_findings  = ContainerScanner(scan_path=path).scan()

    all_findings = secret_findings + sast_findings + trivy_findings
    print(f"\n📊 Total findings: {len(all_findings)}")
    print(f"   Secrets : {len(secret_findings)}")
    print(f"   SAST    : {len(sast_findings)}")
    print(f"   Deps    : {len(trivy_findings)}")

    # Send to Groq
    analyzer = AIAnalyzer()
    analysis = analyzer.analyze(all_findings, repo_name="shahmikh/securegate")
    analyzer.print_analysis(analysis)
