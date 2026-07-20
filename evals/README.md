# Camiro Evaluation Harness

Measures the accuracy of Camiro's compliance findings against a hand-labelled
corpus. Run it after every prompt change, scanner rule change, or Claude model
version bump.

## Quick start

```bash
# 1. See your API's real response shape first
python run_evals.py --url https://web-production-640bb.up.railway.app --debug

# 2. Adapt scan_one() and normalise() in run_evals.py to match your endpoint
#    (currently assumes POST /api/scan with {"code": ..., "filename": ...})

# 3. Full run
python run_evals.py --url https://web-production-640bb.up.railway.app

# Re-score without re-scanning (free, instant)
python run_evals.py --score-only
```

Exit code 0 = all cases pass → safe to wire into CI (GitHub Actions) so a
failing eval blocks deploys.

## What it measures

| Metric | Meaning |
|---|---|
| **Finding recall** | % of ground-truth violations the scanner found |
| **False-positive traps** | forbidden findings the scanner wrongly produced |
| **Tier accuracy** | did it classify prohibited / high-risk / clean correctly |
| **Data-type recall** | % of personal data fields identified |

## Baseline results (2026-07-20)

Model: `claude-fable-5` | Ruleset: v1 | Cases: 8

```
Cases scored:          8  (8 pass / 0 fail)
Finding recall:        100.0%   (must-find expectations satisfied)
False-positive checks: 0 triggered of 12 traps
Tier accuracy:         100.0%
```

All 8 cases PASS. 0 false positives. All must-find expectations satisfied.

## Corpus design (8 seed cases — grow to 30–50)

| Category | Case | Tests |
|---|---|---|
| `prohibited/` | hiring_protected_chars | The AcmeHire pattern: Art 5(1)(b), Art 9, Art 22, Art 28/44 |
| `prohibited/` | loan_sensitive_data | Credit scoring w/ medical + criminal data: Art 5, Annex III(5) |
| `high_risk/` | cv_ranking_no_protected | Employment AI, human-in-loop — must NOT be called prohibited |
| `gdpr/` | newsletter_no_consent | Pure GDPR — must NOT hallucinate AI Act findings |
| `clean/` | anonymised_analytics | Compliant code — any high finding is a false positive |
| `near_miss/` | health_app_legitimate | 'medical' keyword in a compliant context — the calibration test |
| `transparency/` | chatbot_no_disclosure | Art 50(1): chatbot with no AI disclosure — must find |
| `transparency/` | disclosed_chatbot | Art 50(1): properly disclosed chatbot — must NOT find high Art 50 |

The near-miss and clean categories are the most valuable: they measure whether
Camiro reads code or pattern-matches keywords. That distinction is your moat —
it's literally the claim in your comparison table on the landing page.

## Adding a case

1. Write `corpus/<category>/<name>.py` — the code to scan
2. Write `corpus/<category>/<name>.expected.json` alongside it:
   - `must_find`: violations the scanner must report (articles, keywords, min severity)
   - `must_not_find`: false-positive traps
   - `risk_tier_expected`: prohibited / high_risk / gdpr_issues / low_or_clean / clean
3. Run and check

## Priority next cases to add

- Biometric identification (Art 5(1)(g)–(h) territory) — real-time vs post
- Emotion recognition in workplace (Art 5(1)(f))
- Chatbot without AI disclosure (Art 50 transparency)
- Legitimate-interest marketing (LIA present) — another near-miss
- JS/TypeScript samples — corpus is Python-only so far
- A 500+ line file — tests long-context behaviour
- Obfuscated variable names (col_7 instead of ethnicity) — tests inference vs observation labelling

## The investor line this buys you

> "Camiro is regression-tested against a labelled corpus of EU AI Act and GDPR
> violation patterns on every release, measuring finding recall, false-positive
> rate, and risk-tier calibration."
