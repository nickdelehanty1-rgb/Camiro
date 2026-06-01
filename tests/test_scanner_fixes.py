"""
Tests for AIUsageScanner generic-AI expansion, SpecialCategoryScanner
guardrail detection, and high-risk domain classification.
Run standalone: python3 tests/test_scanner_fixes.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scanners.ai_scanner import AIUsageScanner
from app.scanners.data_scanner import SpecialCategoryScanner, PersonalDataScanner

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def check(label, findings, expect_fire, required_types=None, forbidden_types=None):
    fired = len(findings) > 0
    ok = fired == expect_fire
    if ok and required_types:
        actual = {f.finding_type for f in findings}
        ok = all(t in actual for t in required_types)
    if ok and forbidden_types:
        actual = {f.finding_type for f in findings}
        ok = not any(t in actual for t in forbidden_types)
    status = PASS if ok else FAIL
    print(f"[{status}] {label}")
    for f in findings:
        print(f"       [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    if not findings:
        print("       (no findings)")
    print()
    return ok


# ─── AIUsageScanner ────────────────────────────────────────────────────────────

DATING_APP_CODE = """
class MockLlmClient:
    def complete(self, prompt, temperature=0.7, maxTokens=500):
        return {"text": "mock response"}

class ProfileModerationService:
    def __init__(self, llm_client):
        self.llm = llm_client

    def moderate(self, profile_text):
        result = self.llm.complete(
            prompt=f"Moderate this profile: {profile_text}",
            temperature=0.0,
        )
        return {
            "riskLevel": result.get("risk"),
            "recommendedAction": result.get("action"),
            "aiExplanation": result.get("explanation"),
        }

class MatchRecommendationService:
    system_message = "You are a dating app compatibility engine."

    def get_matches(self, user_id):
        response = self.llm.chat(
            messages=[{"role": "system", "content": self.system_message}]
        )
        return {"compatibilityScore": response["score"]}

class MessageSafetyService:
    def check_safety(self, message):
        return self.llm.run(message)
"""

LLM_SIGNATURE_CODE = """
response = model.complete(
    prompt=user_query,
    max_tokens=1024,
    temperature=0.3,
    system_prompt="You are a helpful assistant.",
)
"""

CLEAN_CODE = """
def calculate_tax(income: float, rate: float = 0.2) -> float:
    return income * rate

class ReportService:
    def generate(self, data):
        return {"total": sum(data)}
"""

# ─── SpecialCategoryScanner ───────────────────────────────────────────────────

# Should fire HIGH confidence — variable names and field context
ACMEHIRE_CODE = """
cur.execute(\"\"\"
    SELECT id, name, email, ethnicity, nationality,
           disability, accommodation_needs,
           criminal_record, credit_score
    FROM applicants WHERE id = %s
\"\"\", [applicant_id])
candidate = {
    "ethnicity": row[8],
    "disability": row[10],
    "criminal_record": row[17],
}
"""

# Should fire LOW confidence guardrail_reference — prohibition context in strings
GUARDRAIL_CODE = """
system_prompt = \"\"\"
You are a fair matching assistant.
Do not rank by race, religion, disability, income, or health status.
Avoid using criminal record or ethnic origin as scoring factors.
\"\"\"
"""

# Mixed: both a guardrail AND actual field usage — should fire both
MIXED_CODE = """
# Guardrail instruction
prompt_note = "Do not filter by religion or health conditions."

# Actual field processing
user_profile = {
    "religion": user_data.get("religion"),
    "health_conditions": user_data.get("health"),
}
"""

# Guardrail-only: "without regard to" form
GUARDRAIL_WITHOUT = """
instructions = "Evaluate candidates without regard to disability or health status."
"""


# Dating app: has LLM but employment/income only in guardrail string
DATING_APP_GUARDRAIL = """
class MatchRecommendationService:
    def get_matches(self, user_id):
        # Use LLM to find compatible profiles
        result = self.llm.complete(
            prompt=f"Find matches for user {user_id}",
            temperature=0.7,
            max_tokens=500,
            system_message="You are a dating compatibility engine. " +
                           "Do not rank by income, employment status, " +
                           "race, religion, or disability.",
        )
        return {"compatibilityScore": result.get("score")}
"""

# AcmeHire with candidate fields in code structure — should confirm employment domain
ACMEHIRE_DOMAIN = """
import openai

def score_candidate(candidate_id: int):
    candidate = db.query("SELECT candidate_id, name FROM candidates WHERE id = %s", [candidate_id])
    result = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Score: {candidate['cv_text']}"}]
    )
    return {"candidate_score": float(result.choices[0].message.content)}
"""


if __name__ == "__main__":
    results = []
    ai = AIUsageScanner()
    sc = SpecialCategoryScanner()
    pd = PersonalDataScanner()

    print("─── AIUsageScanner: generic AI patterns ─────────────────────")

    results.append(check(
        "a) MockLlmClient, llm.complete, ProfileModerationService — should detect Generic LLM Client",
        ai.scan(DATING_APP_CODE, "app.py"),
        expect_fire=True,
    ))

    results.append(check(
        "b) max_tokens, temperature, system_message — should detect LLM API Signature",
        ai.scan(LLM_SIGNATURE_CODE, "inference.py"),
        expect_fire=True,
    ))

    results.append(check(
        "c) ReportService with no AI patterns — should NOT fire",
        ai.scan(CLEAN_CODE, "report.py"),
        expect_fire=False,
    ))

    # AcmeHire still works
    acme_code = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples", "acmehire", "app.py"
    )).read()
    results.append(check(
        "d) AcmeHire sample — should still detect OpenAI",
        ai.scan(acme_code, "acmehire/app.py"),
        expect_fire=True,
    ))

    print("─── SpecialCategoryScanner: guardrail detection ─────────────")

    # AcmeHire SQL fields — HIGH confidence
    acme_findings = sc.scan(ACMEHIRE_CODE, "test.py")
    high_conf = [f for f in acme_findings if f.finding_type == "special_category_data"]
    results.append(check(
        "e) AcmeHire SQL fields — HIGH confidence special_category_data, NOT guardrail",
        acme_findings,
        expect_fire=True,
        required_types=["special_category_data"],
        forbidden_types=["guardrail_reference"],
    ))
    if high_conf:
        print(f"       High-confidence findings: {len(high_conf)}, confidences: "
              f"{[round(f.confidence,2) for f in high_conf]}")
    print()

    # Guardrail string — LOW confidence only
    g_findings = sc.scan(GUARDRAIL_CODE, "prompt.py")
    high_in_guardrail = [f for f in g_findings if f.finding_type == "special_category_data"]
    guardrail_refs = [f for f in g_findings if f.finding_type == "guardrail_reference"]
    results.append(check(
        "f) 'Do not rank by religion, disability, health' — guardrail_reference (low conf), NOT special_category_data",
        g_findings,
        expect_fire=True,
        required_types=["guardrail_reference"],
        forbidden_types=["special_category_data"],
    ))
    if guardrail_refs:
        print(f"       Guardrail references: {len(guardrail_refs)}, "
              f"confidences: {[round(f.confidence,2) for f in guardrail_refs]}")
    print()

    # Mixed code — both types should fire
    m_findings = sc.scan(MIXED_CODE, "mixed.py")
    results.append(check(
        "g) Mixed: guardrail + actual field — should fire BOTH types",
        m_findings,
        expect_fire=True,
        required_types=["guardrail_reference", "special_category_data"],
    ))

    # "without regard to" guardrail form
    results.append(check(
        "h) 'without regard to disability' — guardrail_reference, NOT special_category_data",
        sc.scan(GUARDRAIL_WITHOUT, "instructions.py"),
        expect_fire=True,
        required_types=["guardrail_reference"],
        forbidden_types=["special_category_data"],
    ))

    print("─── High-risk domain classification ────────────────────────")

    # Dating app: employment/income only in guardrail string → domain unclear, NOT employment AI
    dating_ai = ai.scan(DATING_APP_GUARDRAIL, "dating_app.py")
    results.append(check(
        "i) Dating app — AI detected but employment only in guardrail → ai_domain_unclear, NOT employment domain",
        dating_ai,
        expect_fire=True,
        required_types=["ai_domain_unclear"],
    ))
    # Also verify PersonalDataScanner: "employment" in guardrail → keyword_reference, NOT personal_data_detected
    dating_pd = pd.scan(DATING_APP_GUARDRAIL, "dating_app.py")
    employment_confirmed = [f for f in dating_pd if f.finding_type == "personal_data_detected"
                            and "employment" in f.metadata.get("data_category", "")]
    employment_guardrail = [f for f in dating_pd if f.finding_type == "keyword_reference"
                            and "employment" in f.metadata.get("data_category", "")]
    results.append(check(
        "j) Dating app PersonalDataScanner — 'employment' in guardrail → keyword_reference (0.35), NOT personal_data_detected",
        [f for f in dating_pd if "employment" in f.metadata.get("data_category", "")],
        expect_fire=True,
        required_types=["keyword_reference"],
        forbidden_types=["personal_data_detected"],
    ))

    # AcmeHire: candidate.score, FROM candidates → domain confirmed, NO ai_domain_unclear
    acmehire_ai = ai.scan(ACMEHIRE_DOMAIN, "acmehire.py")
    domain_unclear = [f for f in acmehire_ai if f.finding_type == "ai_domain_unclear"]
    results.append(check(
        "k) AcmeHire — code has candidate_ fields and FROM candidates → NO ai_domain_unclear",
        acmehire_ai,
        expect_fire=True,
        forbidden_types=["ai_domain_unclear"],
    ))
    print(f"       ai_domain_unclear findings: {len(domain_unclear)} (expected 0)")
    print()

    print("─── Existing tests still pass ───────────────────────────────")
    # Run existing test suites
    import subprocess
    for tf in ["test_data_flow_scanner.py", "test_evidence_intake_scanner.py", "test_agent_scanners.py"]:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), tf)
        r = subprocess.run(
            [sys.executable, path],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        passed = "passed" in r.stdout or r.returncode == 0
        status = PASS if passed else FAIL
        # Extract summary line
        summary = next((l for l in r.stdout.splitlines() if "passed" in l or "FAIL" in l), "")
        print(f"[{status}] {tf} — {summary or ('ok' if passed else 'FAILED')}")
        if not passed:
            print(r.stdout[-500:])
            print(r.stderr[-200:])
    print()

    passed = sum(results)
    total = len(results)
    print(f"\nNew tests: {passed}/{total} passed")
    print()
    # Before/after summary
    print("─── Before/after summary: dating app sample ──────────────────")
    print("BEFORE fix: employment term in guardrail → personal_data_detected (0.85)")
    print("            → LLM context includes employment_data → classified as employment AI")
    print()
    print("AFTER  fix:")
    dating_all = pd.scan(DATING_APP_GUARDRAIL, "dating_app.py") + ai.scan(DATING_APP_GUARDRAIL, "dating_app.py")
    for f in dating_all:
        tier = f.metadata.get("confidence_tier", "")
        tier_str = f" [{tier}]" if tier else ""
        print(f"  [{f.finding_type}] [{f.confidence:.2f}]{tier_str} {f.title}")
    if passed < total:
        sys.exit(1)
