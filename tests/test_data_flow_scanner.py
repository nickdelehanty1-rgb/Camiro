"""
Tests for DataFlowScanner v0.
Run standalone: python3 tests/test_data_flow_scanner.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scanners.data_flow_scanner import DataFlowScanner

scanner = DataFlowScanner()

# ---------------------------------------------------------------------------
# Test snippets
# ---------------------------------------------------------------------------

# a) POSITIVE: candidate_email passed directly to OpenAI — should fire
SNIPPET_A = '''
import openai

def screen_candidate(candidate_email, job_id):
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Review this applicant: {candidate_email}"}]
    )
    return response.choices[0].message.content
'''

# b) POSITIVE: health_data passed to logger — should fire
SNIPPET_B = '''
import logging
logger = logging.getLogger(__name__)

def process_patient(health_data):
    logger.info(f"Processing patient record: {health_data}")
    return True
'''

# c) NEGATIVE: candidate_email exists but never reaches any sink — should NOT fire
SNIPPET_C = '''
def validate_email(candidate_email):
    if "@" not in candidate_email:
        raise ValueError("Invalid email")
    local, domain = candidate_email.split("@", 1)
    return len(local) > 0 and "." in domain
'''

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def run_test(label: str, code: str, expect_fire: bool) -> bool:
    findings = scanner.scan(code, "test.py")
    fired = len(findings) > 0
    ok = fired == expect_fire
    status = PASS if ok else FAIL
    print(f"[{status}] {label}")
    if findings:
        for f in findings:
            print(f"       [{f.confidence:.2f}] {f.title}")
            print(f"              line {f.line_start}: {f.evidence_excerpt}")
    else:
        print(f"       (no findings)")
    print()
    return ok


def run_acmehire() -> int:
    acme_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples", "acmehire", "app.py"
    )
    with open(acme_path) as fh:
        code = fh.read()
    findings = scanner.scan(code, "acmehire/app.py")
    print(f"--- AcmeHire end-to-end: {len(findings)} data-flow finding(s) ---")
    for f in findings:
        print(f"  [{f.confidence:.2f}] {f.title}")
        print(f"         line {f.line_start}: {f.evidence_excerpt}")
        print(f"         flow_type={f.metadata.get('flow_type')}  "
              f"source_lines={f.metadata.get('source_lines')}")
        print()
    return len(findings)


if __name__ == "__main__":
    results = [
        run_test(
            "a) candidate_email → openai.chat.completions.create  (EXPECT: fire)",
            SNIPPET_A, expect_fire=True,
        ),
        run_test(
            "b) health_data → logger.info                          (EXPECT: fire)",
            SNIPPET_B, expect_fire=True,
        ),
        run_test(
            "c) candidate_email exists, no sink reached            (EXPECT: no fire)",
            SNIPPET_C, expect_fire=False,
        ),
    ]

    print("=" * 60)
    n_findings = run_acmehire()
    print("=" * 60)

    passed = sum(results)
    total = len(results)
    print(f"\nUnit tests: {passed}/{total} passed")
    print(f"AcmeHire findings: {n_findings}")

    if passed < total:
        sys.exit(1)
