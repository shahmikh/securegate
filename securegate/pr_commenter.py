import os
from github import Github
from dotenv import load_dotenv

load_dotenv()


class PRCommenter:
    def __init__(self):
        token     = os.getenv("GITHUB_TOKEN")
        self.repo_name = os.getenv("GITHUB_REPOSITORY", "")
        self.pr_number = os.getenv("PR_NUMBER", "")

        if token:
            self.gh   = Github(token)
            self.repo = self.gh.get_repo(self.repo_name)
            print(f"  ✅ GitHub connected: {self.repo_name}")
        else:
            self.gh   = None
            self.repo = None
            print("  ⚠️  No GitHub token — comment will be printed only")

    def _build_comment(self, score_result: dict,
                       analysis: dict,
                       all_findings: list) -> str:
        """Builds the full markdown PR comment."""

        score     = score_result["score"]
        risk      = score_result["risk_level"]
        block     = score_result["should_block"]
        breakdown = score_result["breakdown"]

        secrets = [f for f in all_findings if f["type"] == "SECRET"]
        sast    = [f for f in all_findings if f["type"] == "SAST"]
        deps    = [f for f in all_findings if f["type"] == "DEPENDENCY"]

        risk_emojis = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
            "SAFE":     "✅"
        }
        risk_emoji = risk_emojis.get(risk, "⚪")

        merge_badge = (
            "![BLOCKED](https://img.shields.io/badge/MERGE-BLOCKED-red)"
            if block else
            "![APPROVED](https://img.shields.io/badge/MERGE-APPROVED-green)"
        )

        # Score bar
        filled   = int(score / 5)
        bar      = "🟥" * min(filled, 10) + "⬜" * (10 - min(filled, 10))

        # Top issues section
        issues_md = ""
        if analysis.get("top_issues"):
            issues_md = "\n### 🎯 Top Security Issues\n"
            for i, issue in enumerate(analysis["top_issues"], 1):
                issues_md += f"{i}. {issue}\n"

        # Fixes section
        fixes_md = ""
        if analysis.get("fixes"):
            fixes_md = "\n### 🔧 Recommended Fixes\n"
            for i, fix in enumerate(analysis["fixes"], 1):
                fixes_md += f"{i}. {fix}\n"

        # Secrets table
        secrets_md = ""
        if secrets:
            secrets_md = "\n### 🔑 Secrets Detected\n"
            secrets_md += "| Severity | Type | File | Line |\n"
            secrets_md += "|---|---|---|---|\n"
            for s in secrets[:5]:
                secrets_md += (
                    f"| {risk_emojis.get(s['severity'],'')} "
                    f"{s['severity']} | {s['name']} | "
                    f"`{s['file']}` | {s['line']} |\n"
                )

        # SAST table
        sast_md = ""
        if sast:
            sast_md = "\n### 🔍 Static Analysis Issues\n"
            sast_md += "| Severity | Issue | File | Line |\n"
            sast_md += "|---|---|---|---|\n"
            for s in sast[:8]:
                sast_md += (
                    f"| {risk_emojis.get(s['severity'],'')} "
                    f"{s['severity']} | {s['name']} | "
                    f"`{s['file']}` | {s['line']} |\n"
                )

        # Deps table
        deps_md = ""
        if deps:
            deps_md = "\n### 📦 Vulnerable Dependencies\n"
            deps_md += "| Severity | CVE | Package | Fix |\n"
            deps_md += "|---|---|---|---|\n"
            for d in deps[:5]:
                deps_md += (
                    f"| {risk_emojis.get(d['severity'],'')} "
                    f"{d['severity']} | {d['name']} | "
                    f"`{d.get('package','?')}` | "
                    f"`{d.get('fixed_in','N/A')}` |\n"
                )

        # Summary breakdown
        breakdown_md = "\n### 📊 Scan Summary\n"
        breakdown_md += "| Scanner | Findings | Score |\n"
        breakdown_md += "|---|---|---|\n"
        for ftype, data in breakdown.items():
            sevs = ", ".join(
                f"{s}: {c}" for s, c in data["severities"].items()
            )
            breakdown_md += (
                f"| {ftype} | {data['count']} ({sevs}) "
                f"| {data['score']} |\n"
            )

        comment = f"""## 🤖 SecureGate Security Review

{merge_badge}

---

### {risk_emoji} Risk Score: {score}/100 — {risk}

{bar} `{score}/100`

> **{analysis.get('executive_summary', 'Security analysis complete.')}**

---
{issues_md}{fixes_md}{secrets_md}{sast_md}{deps_md}{breakdown_md}
---

### {'❌ This PR is BLOCKED from merging due to critical security issues.' if block else '✅ This PR is approved but please review the warnings above.'}

**Merge Reason:** {analysis.get('merge_reason', 'N/A')}

---
<sub>🤖 Powered by SecureGate · Groq LLaMA 3.3 70B · Bandit · Trivy</sub>
"""
        return comment

    def post_comment(self, score_result: dict,
                     analysis: dict,
                     all_findings: list) -> bool:
        """Posts the security review comment on the PR."""
        comment = self._build_comment(score_result, analysis, all_findings)

        # Always print to terminal
        print("\n" + "─"*65)
        print("  PR COMMENT PREVIEW")
        print("─"*65)
        print(comment[:1000] + "..." if len(comment) > 1000 else comment)
        print("─"*65)

        if not self.gh or not self.pr_number:
            print("  ℹ️  No PR number — comment printed only (not posted)")
            return True

        try:
            pr = self.repo.get_pull(int(self.pr_number))

            # Delete previous SecureGate comments to avoid spam
            for existing in pr.get_issue_comments():
                if "SecureGate Security Review" in existing.body:
                    existing.delete()

            pr.create_issue_comment(comment)
            print(f"  ✅ Comment posted on PR #{self.pr_number}")
            return True

        except Exception as e:
            print(f"  ❌ Failed to post comment: {e}")
            return False

    def set_pr_status(self, should_block: bool):
        """Exits with code 1 to fail the GitHub Actions check if blocked."""
        if should_block:
            print("\n  ❌ Blocking merge — risk score too high")
            raise SystemExit(1)
        else:
            print("\n  ✅ Merge approved by SecureGate")
            raise SystemExit(0)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __import__('os').path.dirname(
        __import__('os').path.dirname(__import__('os').path.abspath(__file__))
    ))
    from securegate.secret_scanner import SecretScanner
    from securegate.sast           import SASTScanner
    from securegate.container_scan import ContainerScanner
    from securegate.ai_analyzer    import AIAnalyzer
    from securegate.risk_scorer    import RiskScorer

    path     = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = (
        SecretScanner(scan_path=path).scan()  +
        SASTScanner(scan_path=path).scan()    +
        ContainerScanner(scan_path=path).scan()
    )

    scorer   = RiskScorer()
    result   = scorer.calculate(findings)
    scorer.print_score(result)

    analyzer = AIAnalyzer()
    analysis = analyzer.analyze(findings, repo_name="shahmikh/securegate")
    analyzer.print_analysis(analysis)

    commenter = PRCommenter()
    commenter.post_comment(result, analysis, findings)
