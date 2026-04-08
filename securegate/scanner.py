import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securegate.secret_scanner import SecretScanner
from securegate.sast           import SASTScanner
from securegate.container_scan import ContainerScanner
from securegate.ai_analyzer    import AIAnalyzer
from securegate.risk_scorer    import RiskScorer
from securegate.pr_commenter   import PRCommenter

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║          🔐 SecureGate — AI PR Security Reviewer            ║
║     Secrets · SAST · Dependencies · Groq LLM · GitHub       ║
╚══════════════════════════════════════════════════════════════╝
"""

def run(scan_path: str = "."):
    print(BANNER)

    repo = os.getenv("REPO_NAME", "shahmikh/securegate")
    pr   = os.getenv("PR_NUMBER", "")

    print(f"  Repository : {repo}")
    print(f"  PR Number  : #{pr or 'N/A (local run)'}")
    print(f"  Scan path  : {scan_path}\n")
    print("─"*65)

    # ── Phase 1: Run all scanners ─────────────────────────────────
    print("\n📡 Phase 1 — Running security scanners...\n")

    secret_findings = SecretScanner(scan_path=scan_path).scan()
    sast_findings   = SASTScanner(scan_path=scan_path).scan()
    trivy_findings  = ContainerScanner(scan_path=scan_path).scan()

    all_findings = secret_findings + sast_findings + trivy_findings

    print(f"\n  📊 Total findings : {len(all_findings)}")
    print(f"     🔑 Secrets      : {len(secret_findings)}")
    print(f"     🔍 SAST         : {len(sast_findings)}")
    print(f"     📦 Dependencies : {len(trivy_findings)}")

    # ── Phase 2: Calculate risk score ────────────────────────────
    print("\n📊 Phase 2 — Calculating risk score...\n")
    scorer      = RiskScorer()
    score_result = scorer.calculate(all_findings)
    scorer.print_score(score_result)

    # ── Phase 3: AI analysis ──────────────────────────────────────
    print("\n🤖 Phase 3 — AI security analysis with Groq...\n")
    analyzer = AIAnalyzer()
    analysis = analyzer.analyze(all_findings, repo_name=repo)
    analyzer.print_analysis(analysis)

    # ── Phase 4: Post PR comment ──────────────────────────────────
    print("\n💬 Phase 4 — Posting PR comment...\n")
    commenter = PRCommenter()
    commenter.post_comment(score_result, analysis, all_findings)

    # ── Phase 5: Save report JSON ─────────────────────────────────
    report = {
        "repo":          repo,
        "pr_number":     pr,
        "score":         score_result["score"],
        "risk_level":    score_result["risk_level"],
        "should_block":  score_result["should_block"],
        "total_findings": len(all_findings),
        "breakdown":     score_result["breakdown"],
        "analysis":      {
            k: v for k, v in analysis.items() if k != "raw"
        },
        "findings": [
            {
                "type":     f["type"],
                "severity": f["severity"],
                "name":     f["name"],
                "file":     f.get("file", ""),
                "line":     f.get("line", 0),
            }
            for f in all_findings
        ]
    }

    with open("securegate_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("  ✅ Report saved: securegate_report.json")

    # ── Phase 6: Block or approve ─────────────────────────────────
    print("\n" + "═"*65)
    if score_result["should_block"]:
        print(f"  ❌ MERGE BLOCKED — Risk score {score_result['score']}/100")
        print(f"     Fix all CRITICAL and HIGH issues before merging.")
        print("═"*65 + "\n")
        sys.exit(1)
    else:
        print(f"  ✅ MERGE APPROVED — Risk score {score_result['score']}/100")
        print("═"*65 + "\n")
        sys.exit(0)


if __name__ == "__main__":
    path = os.getenv("SCAN_PATH", sys.argv[1] if len(sys.argv) > 1 else ".")
    run(scan_path=path)
