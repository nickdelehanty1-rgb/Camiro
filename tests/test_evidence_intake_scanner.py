"""
Tests for EvidenceIntakeScanner v0.
Run standalone: python3 tests/test_evidence_intake_scanner.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scanners.evidence_intake_scanner import EvidenceIntakeScanner

# ---------------------------------------------------------------------------
# Test snippets
# ---------------------------------------------------------------------------

# a) POSITIVE: product spec with automated candidate ranking — should fire
SNIPPET_A = """
# Product Specification — CandidateRank AI

## Overview
CandidateRank automatically ranks and scores job applicants using an AI model.
The system generates a suitability score and produces an automated shortlist
of candidates for each role.

## Features
- Automated candidate scoring from 1 to 10
- Automated ranking of all applicants by suitability score
- Automated rejection of candidates below threshold score
- Batch processing of all pending applications
"""

# b) POSITIVE: privacy notice missing AI disclosure, code has AI use — should flag gap
SNIPPET_B = """
# Privacy Notice

We collect your name, email address and CV when you apply for a position.
We use your data to assess your suitability for the role and to contact you.
Legal basis: legitimate interests.
Retention: 12 months for unsuccessful applicants.
Your rights: access, erasure, objection. Contact privacy@example.com.
"""

# Code context for test b: code scan found AI use
CODE_SUMMARY_WITH_AI = {
    'ai_systems_detected': [{'name': 'OpenAI', 'finding_type': 'ai_provider_detected'}],
    'vendors_detected': ['OpenAI'],
    'has_automated_decisions': True,
    'has_special_category_data': False,
    'personal_data_categories': ['email', 'employment_data'],
}

# c) NEGATIVE: privacy notice clearly discloses AI use and vendor — should NOT flag gap
SNIPPET_C = """
# Privacy Notice

We collect your name, email address, phone number and CV when you apply.
We use your data to assess suitability for the role.

## Automated Processing
We use artificial intelligence to score and rank applications.
Our system uses OpenAI's API to analyse CV content and generate a suitability score.
Candidates may be automatically advanced or rejected based on this score.
You have the right to request human review of any automated decision.
You have the right to contest automated decisions. Contact privacy@example.com.

## Legal basis
Legitimate interests in efficient recruitment.
Retention: 12 months. Rights: access, erasure, objection, portability.
"""

# Code context for test c: same as b — code has AI use
CODE_SUMMARY_WITH_AI_C = CODE_SUMMARY_WITH_AI

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def findings_of_type(findings, finding_type):
    return [f for f in findings if f.finding_type == finding_type]


def run_test(label, scanner, code, filename, expect_fire, expect_types=None,
             must_not_contain=None):
    findings = scanner.scan(code, filename)
    fired = len(findings) > 0

    # For must_not_contain: check no finding of that type exists
    type_ok = True
    if expect_types:
        actual_types = {f.finding_type for f in findings}
        type_ok = all(t in actual_types for t in expect_types)
    if must_not_contain:
        forbidden = [f for f in findings if f.finding_type in must_not_contain]
        if forbidden:
            type_ok = False

    ok = (fired == expect_fire) and type_ok
    status = PASS if ok else FAIL
    print(f"[{status}] {label}")
    if findings:
        for f in findings:
            print(f"       [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    else:
        print(f"       (no findings)")
    if not ok and not fired and expect_fire:
        print(f"       EXPECTED findings but got none")
    if not ok and fired and not expect_fire:
        print(f"       EXPECTED no findings but got {len(findings)}")
    if not ok and expect_types:
        print(f"       EXPECTED types {expect_types}, got {[f.finding_type for f in findings]}")
    print()
    return ok


def run_sample_docs():
    print("--- Sample documents ---")
    docs_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples", "docs"
    )

    # Privacy notice — with code context
    pn_path = os.path.join(docs_dir, "candidate_privacy_notice.md")
    with open(pn_path) as f:
        pn_text = f.read()

    scanner = EvidenceIntakeScanner()
    scanner.set_code_summary(CODE_SUMMARY_WITH_AI)
    pn_findings = scanner.scan(pn_text, "candidate_privacy_notice.md")
    print(f"candidate_privacy_notice.md  ({len(pn_findings)} findings, "
          f"doc_type={scanner.last_doc_type})")
    for f in pn_findings:
        print(f"  [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    print()

    # DPIA — with code context
    dpia_path = os.path.join(docs_dir, "hr_ai_dpia.md")
    with open(dpia_path) as f:
        dpia_text = f.read()

    scanner2 = EvidenceIntakeScanner()
    scanner2.set_code_summary(CODE_SUMMARY_WITH_AI)
    dpia_findings = scanner2.scan(dpia_text, "hr_ai_dpia.md")
    print(f"hr_ai_dpia.md  ({len(dpia_findings)} findings, "
          f"doc_type={scanner2.last_doc_type})")
    for f in dpia_findings:
        print(f"  [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    print()

    # DPA excerpt — standalone
    dpa_path = os.path.join(docs_dir, "openai_dpa_excerpt.md")
    with open(dpa_path) as f:
        dpa_text = f.read()

    scanner3 = EvidenceIntakeScanner()
    dpa_findings = scanner3.scan(dpa_text, "openai_dpa_excerpt.md")
    print(f"openai_dpa_excerpt.md  ({len(dpa_findings)} findings, "
          f"doc_type={scanner3.last_doc_type})")
    for f in dpa_findings:
        print(f"  [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    print()


if __name__ == "__main__":
    # Test a
    scanner_a = EvidenceIntakeScanner()
    result_a = run_test(
        "a) product spec with automated ranking (EXPECT: fire, requires_review)",
        scanner_a, SNIPPET_A, "product_spec.md",
        expect_fire=True, expect_types=['requires_review'],
    )

    # Test b — inject code context BEFORE calling scan
    scanner_b = EvidenceIntakeScanner()
    scanner_b.set_code_summary(CODE_SUMMARY_WITH_AI)
    result_b = run_test(
        "b) privacy notice missing AI disclosure, code has AI use (EXPECT: fire, missing_evidence)",
        scanner_b, SNIPPET_B, "privacy_notice.md",
        expect_fire=True, expect_types=['missing_evidence'],
    )

    # Test c — privacy notice with AI disclosed, should NOT flag AI gap
    scanner_c = EvidenceIntakeScanner()
    scanner_c.set_code_summary(CODE_SUMMARY_WITH_AI_C)
    # We expect no MISSING_EVIDENCE finding specifically about AI disclosure gap
    # (other missing_evidence findings for other gaps are acceptable)
    findings_c = scanner_c.scan(SNIPPET_C, "privacy_notice.md")
    ai_gap_findings = [
        f for f in findings_c
        if f.finding_type == 'missing_evidence'
        and 'ai' in f.title.lower()
        and 'disclosure' in f.title.lower()
    ]
    c_ok = len(ai_gap_findings) == 0
    status_c = PASS if c_ok else FAIL
    print(f"[{status_c}] c) privacy notice with AI disclosed (EXPECT: NO ai_disclosure gap)")
    if findings_c:
        for f in findings_c:
            print(f"       [{f.finding_type}] {f.title}")
    else:
        print(f"       (no findings)")
    if not c_ok:
        print(f"       FAILED: AI gap was still flagged despite disclosure present")
    print()

    # Test d — standalone privacy notice, NO code context supplied
    # Should still produce findings: requires_review for AI, automated decisions,
    # special category; plus rights completeness gap.
    STANDALONE_NOTICE = """
# Privacy Notice

We collect your name, email address and CV when you apply for a position.
We use your data to assess your suitability for the role.
Legal basis: legitimate interests. Retention: 12 months.
Your rights: access only.
"""
    scanner_d = EvidenceIntakeScanner()  # no set_code_summary()
    findings_d = scanner_d.scan(STANDALONE_NOTICE, "privacy_notice.md")
    types_d = {f.finding_type for f in findings_d}
    # Must fire requires_review (standalone AI/automated/special-cat checks)
    # AND missing_evidence (rights completeness)
    d_ok = 'requires_review' in types_d and 'missing_evidence' in types_d and len(findings_d) > 0
    status_d = PASS if d_ok else FAIL
    print(f"[{status_d}] d) standalone privacy notice, no code context (EXPECT: fire, both requires_review and missing_evidence)")
    for f in findings_d:
        print(f"       [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    if not d_ok:
        print(f"       FAILED: types present={types_d}, expected both requires_review and missing_evidence")
    print()

    print("=" * 60)
    run_sample_docs()
    print("=" * 60)

    passed = sum([result_a, result_b, c_ok, d_ok])
    print(f"\nUnit tests: {passed}/4 passed")
    if passed < 4:
        sys.exit(1)
