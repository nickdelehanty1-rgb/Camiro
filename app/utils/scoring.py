"""Compliance score calculator — see SCORING.md for the algorithm."""

_DEDUCTIONS = {"high": 18, "medium": 8, "low": 3, "info": 1}
_CAPS = {"high": 54, "medium": 32, "low": 12, "info": 5}

_BAND_THRESHOLDS = [
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (10, "E"),
    (0,  "F"),
]

_PROHIBITED_HINT = (
    "Remove or redesign the prohibited practice before any other improvement."
)


def _band(score: int) -> str:
    for floor, letter in _BAND_THRESHOLDS:
        if score >= floor:
            return letter
    return "F"


def compute_compliance_score(llm_result: dict) -> dict:
    """Return compliance_score (0-100), risk_band (A-F), and score_hint.

    Reads risk_level and findings[] from the LLM result dict.
    """
    risk_level = (llm_result.get("risk_level") or "").lower()
    findings = llm_result.get("findings") or []

    # Step 1 — prohibited floor
    if risk_level == "prohibited":
        hint = _prohibited_hint_from(findings)
        return {"compliance_score": 5, "risk_band": "F", "score_hint": hint}

    # Step 2 — base
    score = 100

    # Step 3 — deductions per severity, capped per level
    sev_totals: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        sev_totals[sev] = sev_totals.get(sev, 0) + _DEDUCTIONS.get(sev, 1)

    for sev, total in sev_totals.items():
        score -= min(total, _CAPS.get(sev, total))

    # Step 4 — contextual adjustments
    scanner_summary = llm_result.get("_scanner_summary", {})
    has_automated = llm_result.get("automated_decisions", False)
    finding_titles = " ".join(
        (f.get("title", "") + " " + f.get("description", "")).lower()
        for f in findings
    )

    if has_automated and "human oversight" not in finding_titles and "human review" not in finding_titles:
        score -= 10

    has_special = any(
        "special category" in (f.get("description", "") + f.get("title", "")).lower()
        for f in findings
    )
    if has_special and "explicit consent" not in finding_titles:
        score -= 8

    has_transfer = any(
        "transfer" in (f.get("title", "") + f.get("description", "")).lower()
        for f in findings
    )
    has_dpa = any(
        "dpa" in (f.get("title", "") + f.get("description", "")).lower()
        for f in findings
    )
    if has_transfer and not has_dpa:
        score -= 5

    # Step 5 — cap for high-risk tier
    if risk_level == "high":
        score = min(score, 54)

    score = max(0, min(100, score))
    band = _band(score)
    hint = _score_hint(findings)

    return {"compliance_score": score, "risk_band": band, "score_hint": hint}


def _prohibited_hint_from(findings: list[dict]) -> str:
    for f in findings:
        if f.get("severity", "").lower() == "high" and f.get("recommendation"):
            rec = f["recommendation"]
            return rec[:120] + ("..." if len(rec) > 120 else "")
    return _PROHIBITED_HINT


def _score_hint(findings: list[dict]) -> str:
    if not findings:
        return "No issues detected — maintain controls and re-scan after code changes."
    for sev in ("high", "medium", "low", "info"):
        for f in findings:
            if f.get("severity", "").lower() == sev and f.get("recommendation"):
                rec = f["recommendation"]
                return rec[:120] + ("..." if len(rec) > 120 else "")
    return "Review findings with your legal and privacy team."
