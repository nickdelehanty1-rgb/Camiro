"""
Camiro evaluation scorer.

Compares scanner output against ground-truth .expected.json labels and
computes per-case and aggregate precision / recall / calibration metrics.

Scanner output format expected (adapt normalise() if your API differs):
{
  "risk_tier": "prohibited" | "high_risk" | ...,
  "findings": [
    {"title": str, "description": str, "severity": "high"|"medium"|"low",
     "articles": ["AI Act 5(1)(b)", "GDPR 9", ...],
     "recommendation": str}
  ],
  "data_types": ["name", "email", ...]
}
"""
from __future__ import annotations
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------- normalise

def norm_article(a: str) -> str:
    """Normalise an article reference for comparison.
    'EU AI Act Article 5(1)(b)' -> 'aiact5(1)(b)'
    'GDPR Art. 9'               -> 'gdpr9'
    """
    s = a.lower()
    s = s.replace("eu ai act", "aiact").replace("ai act", "aiact")
    s = s.replace("gdpr", "gdpr")
    s = re.sub(r"\bart(?:icle)?s?\.?\s*", "", s)  # strip "Art.", "Article ", etc. including trailing space/dot
    s = re.sub(r"annex\s*iii", "annexiii", s)
    s = re.sub(r"[\s·,]+", "", s)
    # plain hyphen and en-dash ranges equivalent
    s = s.replace("\u2013", "-")
    return s


def articles_match(found: list[str], expected_group: list[str]) -> bool:
    """True if every article in expected_group appears among found (normalised,
    prefix-tolerant: 'aiact5' matches 'aiact5(1)(b)')."""
    nf = [norm_article(f) for f in found]
    for exp in expected_group:
        ne = norm_article(exp)
        if not any(f.startswith(ne) or ne.startswith(f) for f in nf):
            return False
    return True


def finding_text(f: dict) -> str:
    return " ".join(str(f.get(k, "")) for k in ("title", "description", "recommendation")).lower()


# ---------------------------------------------------------------- matching

@dataclass
class CaseResult:
    case_id: str
    tier_expected: str
    tier_found: str | None
    tier_correct: bool
    matched: list[str] = field(default_factory=list)      # must_find ids hit
    missed: list[str] = field(default_factory=list)       # must_find ids missed
    violations: list[str] = field(default_factory=list)   # must_not_find ids triggered
    unmatched_findings: int = 0                           # scanner findings not mapped to any expectation
    data_type_recall: float | None = None

    @property
    def passed(self) -> bool:
        return not self.missed and not self.violations and self.tier_correct


def match_must_find(expectation: dict, findings: list[dict]) -> bool:
    """A must_find expectation is satisfied if some finding matches its
    article groups (any_of) AND at least one keyword AND minimum severity."""
    kw = [k.lower() for k in expectation.get("keywords_any_of", [])]
    min_sev = SEVERITY_RANK.get(expectation.get("min_severity", "info"), 0)
    art_groups = expectation.get("articles_any_of", [[]])

    for f in findings:
        text = finding_text(f)
        sev = SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 0)
        if sev < min_sev:
            continue
        if kw and not any(k in text for k in kw):
            continue
        arts = f.get("articles", [])
        if art_groups and art_groups != [[]]:
            if not any(articles_match(arts, g) for g in art_groups):
                continue
        return True
    return False


def match_must_not_find(rule: dict, findings: list[dict]) -> bool:
    """Returns True if the forbidden pattern IS present (i.e. a violation)."""
    kw_all = [k.lower() for k in rule.get("keywords_all_of", [])]
    arts = rule.get("articles", [])
    sev_floor = SEVERITY_RANK.get(rule.get("severity_at_least", "info"), 0)

    for f in findings:
        text = finding_text(f)
        sev = SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 0)
        if sev < sev_floor:
            continue
        if kw_all and not all(k in text for k in kw_all):
            continue
        if arts and not articles_match(f.get("articles", []), arts):
            continue
        if kw_all or arts:
            return True
        # rule with only a severity floor (e.g. "any_high_severity")
        if sev_floor > 0:
            return True
    return False


TIER_EQUIV = {
    "clean": {"clean", "low", "minimal", "low_or_clean", "compliant"},
    "low_or_clean": {"clean", "low", "minimal", "low_or_clean", "compliant", "limited"},
    "gdpr_issues": {"gdpr_issues", "high", "high_risk", "serious", "non_compliant"},
    "high_risk": {"high_risk", "high", "high-risk"},
    "prohibited": {"prohibited", "unacceptable"},
}


def tier_matches(expected: str, found: str | None) -> bool:
    if found is None:
        return False
    return found.lower().replace("-", "_").replace(" ", "_") in TIER_EQUIV.get(expected, {expected})


def score_case(expected: dict, output: dict) -> CaseResult:
    findings = output.get("findings", [])
    tier_found = output.get("risk_tier")
    res = CaseResult(
        case_id=expected["case_id"],
        tier_expected=expected["risk_tier_expected"],
        tier_found=tier_found,
        tier_correct=tier_matches(expected["risk_tier_expected"], tier_found),
    )
    for exp in expected.get("must_find", []):
        (res.matched if match_must_find(exp, findings) else res.missed).append(exp["id"])
    for rule in expected.get("must_not_find", []):
        if match_must_not_find(rule, findings):
            res.violations.append(rule["id"])

    dt_expected = set(expected.get("data_types_expected", []))
    if dt_expected:
        dt_found = {d.lower() for d in output.get("data_types", [])}
        res.data_type_recall = len(dt_expected & dt_found) / len(dt_expected)
    return res


# ---------------------------------------------------------------- aggregate

def run(corpus_dir: Path, results_dir: Path) -> int:
    labels = sorted(corpus_dir.rglob("*.expected.json"))
    if not labels:
        print(f"No .expected.json labels found under {corpus_dir}", file=sys.stderr)
        return 2

    case_results: list[CaseResult] = []
    skipped = []
    for label_path in labels:
        expected = json.loads(label_path.read_text())
        out_path = results_dir / (expected["case_id"].replace("/", "__") + ".output.json")
        if not out_path.exists():
            skipped.append(expected["case_id"])
            continue
        output = json.loads(out_path.read_text())
        case_results.append(score_case(expected, output))

    total_must = sum(len(r.matched) + len(r.missed) for r in case_results)
    recall = sum(len(r.matched) for r in case_results) / total_must if total_must else 0.0
    total_forbidden_checks = sum(
        len(json.loads(p.read_text()).get("must_not_find", []))
        for p in labels
        if (results_dir / (json.loads(p.read_text())["case_id"].replace("/", "__") + ".output.json")).exists()
    )
    fp_count = sum(len(r.violations) for r in case_results)
    tier_acc = sum(r.tier_correct for r in case_results) / len(case_results) if case_results else 0.0

    print("=" * 62)
    print("CAMIRO EVALUATION REPORT")
    print("=" * 62)
    for r in case_results:
        flag = "PASS" if r.passed else "FAIL"
        print(f"\n[{flag}] {r.case_id}")
        print(f"      tier: expected={r.tier_expected}  found={r.tier_found}  "
              f"{'ok' if r.tier_correct else 'WRONG'}")
        if r.matched:
            print(f"      found: {', '.join(r.matched)}")
        if r.missed:
            print(f"      MISSED (false negatives): {', '.join(r.missed)}")
        if r.violations:
            print(f"      FALSE POSITIVES: {', '.join(r.violations)}")
        if r.data_type_recall is not None:
            print(f"      data-type recall: {r.data_type_recall:.0%}")
    print("\n" + "-" * 62)
    print(f"Cases scored:          {len(case_results)}  "
          f"({sum(r.passed for r in case_results)} pass / "
          f"{sum(not r.passed for r in case_results)} fail)")
    if skipped:
        print(f"Cases skipped (no scanner output yet): {len(skipped)}")
        for s in skipped:
            print(f"  - {s}")
    print(f"Finding recall:        {recall:.1%}   (must-find expectations satisfied)")
    print(f"False-positive checks: {fp_count} triggered of {total_forbidden_checks} traps")
    print(f"Tier accuracy:         {tier_acc:.1%}")
    print("-" * 62)

    return 0 if all(r.passed for r in case_results) and case_results else 1


if __name__ == "__main__":
    base = Path(__file__).parent
    sys.exit(run(base / "corpus", base / "results"))
