from collections import Counter


# Severity weights for score calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    5,
    "LOW":       1,
}

# Finding type multipliers
TYPE_MULTIPLIERS = {
    "SECRET":     2.0,   # secrets are worst — double penalty
    "SAST":       1.5,   # code issues are serious
    "DEPENDENCY": 1.0,   # deps are important but less urgent
}

# Score thresholds
THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   40,
    "LOW":      20,
    "SAFE":      0,
}


class RiskScorer:
    def __init__(self):
        self.score       = 0
        self.risk_level  = "SAFE"
        self.breakdown   = {}

    def calculate(self, all_findings: list) -> dict:
        """
        Calculates a 0–100 risk score from all findings.
        Returns score, risk level, and breakdown.
        """
        if not all_findings:
            self.score      = 0
            self.risk_level = "SAFE"
            return self._build_result()

        raw_score = 0

        # Group by type for breakdown
        by_type = {}
        for f in all_findings:
            t = f.get("type", "UNKNOWN")
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(f)

        self.breakdown = {}

        for ftype, findings in by_type.items():
            multiplier  = TYPE_MULTIPLIERS.get(ftype, 1.0)
            type_score  = 0
            sev_counts  = Counter(f.get("severity","LOW") for f in findings)

            for severity, count in sev_counts.items():
                weight      = SEVERITY_WEIGHTS.get(severity, 1)
                type_score += weight * count

            type_score *= multiplier
            raw_score  += type_score

            self.breakdown[ftype] = {
                "count":      len(findings),
                "score":      round(type_score, 1),
                "severities": dict(sev_counts),
            }

        # Cap at 100
        self.score = min(100, round(raw_score))

        # Determine risk level
        self.risk_level = "SAFE"
        for level, threshold in THRESHOLDS.items():
            if self.score >= threshold:
                self.risk_level = level
                break

        return self._build_result()

    def _build_result(self) -> dict:
        return {
            "score":      self.score,
            "risk_level": self.risk_level,
            "breakdown":  self.breakdown,
            "should_block": self.score >= THRESHOLDS["CRITICAL"],
        }

    def print_score(self, result: dict):
        """Pretty-prints the risk score."""
        score      = result["score"]
        risk       = result["risk_level"]
        breakdown  = result["breakdown"]
        block      = result["should_block"]

        risk_icons = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
            "SAFE":     "✅"
        }
        icon = risk_icons.get(risk, "⚪")

        # Score bar
        filled = int(score / 5)
        bar    = "█" * filled + "░" * (20 - filled)

        print(f"\n{'─'*65}")
        print(f"  RISK SCORE")
        print(f"{'─'*65}")
        print(f"\n  {icon} {score}/100  [{bar}]  {risk}")
        print(f"\n  {'MERGE BLOCKED ❌' if block else 'MERGE ALLOWED ✅'}")

        if breakdown:
            print(f"\n  BREAKDOWN:")
            for ftype, data in breakdown.items():
                sevs = "  ".join(
                    f"{s}:{c}" for s, c in data["severities"].items()
                )
                print(f"  • {ftype:<12} {data['count']} findings  "
                      f"score: {data['score']}  [{sevs}]")

        print(f"\n{'─'*65}")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, __import__('os').path.dirname(
        __import__('os').path.dirname(__import__('os').path.abspath(__file__))
    ))
    from securegate.secret_scanner import SecretScanner
    from securegate.sast           import SASTScanner
    from securegate.container_scan import ContainerScanner

    path     = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = (
        SecretScanner(scan_path=path).scan()  +
        SASTScanner(scan_path=path).scan()    +
        ContainerScanner(scan_path=path).scan()
    )

    scorer = RiskScorer()
    result = scorer.calculate(findings)
    scorer.print_score(result)
    print(f"\n  Should block merge: {result['should_block']}")
