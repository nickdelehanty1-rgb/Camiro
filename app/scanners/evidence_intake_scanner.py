"""
EvidenceIntakeScanner v0 — document evidence layer for GDPR / EU AI Act compliance.

Classifies plain-text / Markdown compliance documents, extracts structured fields,
and flags missing evidence, gaps, and contradictions relative to known obligations.
Optionally cross-checks against code scan findings when a code summary is injected.

Scope: plain text and Markdown only. Single-document, no cross-document linking.
Finding types: observed | missing_evidence | contradiction | requires_review
"""
import re
from typing import Optional
from .base import BaseScanner, ScannerFinding

# ---------------------------------------------------------------------------
# Document type classification
# ---------------------------------------------------------------------------

_DOC_SIGNALS: dict[str, list[str]] = {
    'privacy_notice': [
        r'privacy\s+(notice|policy|statement)',
        r'data\s+protection\s+notice',
        r'how\s+we\s+(use|process)\s+your\s+(data|information)',
        r'data\s+subject\s+rights',
        r'lawful\s+basis',
        r'right\s+to\s+(access|erasure|object)',
    ],
    'dpia': [
        r'data\s+protection\s+impact\s+assessment',
        r'\bDPIA\b',
        r'necessity\s+and\s+proportionality',
        r'risk\s+(assessment|register).*processing',
        r'processing.*risk\s+(assessment|register)',
    ],
    'ropa_record': [
        r'records?\s+of\s+processing\s+activities',
        r'\bRoPA\b|\bROPA\b',
        r'processing\s+activit.*register',
        r'art\.?\s*30',
    ],
    'dpa_or_vendor_contract': [
        r'data\s+processing\s+agreement',
        r'\bDPA\b',
        r'controller.*processor',
        r'processor.*controller',
        r'sub.?processor',
        r'on\s+behalf\s+of\s+the\s+controller',
        r'processor\s+obligations',
    ],
    'scc_or_transfer_document': [
        r'standard\s+contractual\s+clauses',
        r'\bSCCs?\b',
        r'transfer\s+impact\s+assessment',
        r'\bTIA\b',
        r'chapter\s+v\s+gdpr',
        r'adequacy\s+decision',
    ],
    'product_spec': [
        r'product\s+(specification|spec|requirements)',
        r'functional\s+(specification|requirements)',
        r'system\s+(design|overview|architecture)',
        r'feature\s+(description|specification)',
        r'product\s+overview',
    ],
    'ai_policy': [
        r'ai\s+(policy|governance|ethics|principles)',
        r'artificial\s+intelligence\s+policy',
        r'responsible\s+ai',
        r'ai\s+acceptable\s+use',
        r'ai\s+risk\s+framework',
    ],
    'model_card': [
        r'model\s+card',
        r'model\s+(description|details|overview)',
        r'intended\s+use',
        r'training\s+data',
        r'bias\s+(evaluation|assessment|analysis)',
        r'out.of.scope\s+use',
    ],
    'human_oversight_sop': [
        r'human\s+(oversight|review)\s+(procedure|policy|sop|process)',
        r'standard\s+operating\s+procedure.*review',
        r'manual\s+review\s+(process|procedure)',
        r'escalation\s+(procedure|process)',
        r'reviewer\s+(responsibilities|duties)',
    ],
    'security_policy': [
        r'information\s+security\s+policy',
        r'security\s+(policy|framework|standard)',
        r'iso\s*27001',
        r'access\s+control\s+policy',
        r'data\s+classification\s+policy',
    ],
}

_FILENAME_HINTS: dict[str, list[str]] = {
    'privacy_notice':        ['privacy', 'notice', 'policy'],
    'dpia':                  ['dpia', 'impact'],
    'ropa_record':           ['ropa', 'records', 'processing'],
    'dpa_or_vendor_contract': ['dpa', 'processor', 'contract', 'vendor'],
    'scc_or_transfer_document': ['scc', 'transfer', 'tia'],
    'product_spec':          ['spec', 'product', 'requirements', 'prd'],
    'ai_policy':             ['ai_policy', 'ai-policy', 'ai_governance'],
    'model_card':            ['model_card', 'model-card', 'modelcard'],
    'human_oversight_sop':   ['oversight', 'sop', 'review_procedure'],
    'security_policy':       ['security', 'infosec'],
}

# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _has(text: str, patterns: list[str]) -> bool:
    lower = text.lower()
    return any(re.search(p, lower) for p in patterns)

def _find_first(text: str, patterns: list[str]) -> Optional[str]:
    lower = text.lower()
    for p in patterns:
        m = re.search(p, lower)
        if m:
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 80)
            return text[start:end].strip()
    return None

def _find_line(text: str, patterns: list[str]) -> Optional[int]:
    for i, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        if any(re.search(p, lower) for p in patterns):
            return i
    return None

_KNOWN_VENDORS = [
    'openai', 'anthropic', 'google', 'microsoft', 'azure', 'aws', 'amazon',
    'hugging face', 'cohere', 'mistral', 'meta', 'nvidia', 'snowflake',
    'salesforce', 'stripe', 'twilio', 'sendgrid', 'segment', 'mixpanel',
]

def _extract_vendors(text: str) -> list[str]:
    lower = text.lower()
    return [v for v in _KNOWN_VENDORS if v in lower]

def _extract(text: str) -> dict:
    """Extract structured fields from document text."""
    lower = text.lower()
    return {
        'has_ai_disclosure': _has(text, [
            r'artificial intelligence', r'\bAI\b', r'machine learning',
            r'automated.*decision', r'algorithm.*score', r'automated.*scor',
            r'automated.*rank', r'openai', r'anthropic', r'llm',
            r'large language model', r'automated.*processing',
        ]),
        'has_automated_decision_disclosure': _has(text, [
            r'automated.*decision', r'solely automated', r'automated.*profil',
            r'profiling', r'automated.*scoring', r'automated.*ranking',
            r'art\.?\s*22', r'article\s+22',
        ]),
        'has_human_oversight_mention': _has(text, [
            r'human\s+(review|oversight|check|approval)',
            r'manual\s+review', r'reviewer', r'human\s+in\s+the\s+loop',
            r'right\s+to\s+(contest|challenge|object)',
            r'meaningful\s+human',
        ]),
        'has_special_category_mention': _has(text, [
            r'special\s+categor', r'art\.?\s*9', r'article\s+9',
            r'sensitive\s+(personal\s+)?data', r'health\s+data',
            r'ethnicit', r'disabilit', r'biometric',
        ]),
        'has_legal_basis': _has(text, [
            r'lawful\s+basis', r'legal\s+basis', r'legitimate\s+interest',
            r'consent', r'contractual\s+necessity', r'legal\s+obligation',
            r'vital\s+interests', r'public\s+task',
        ]),
        'has_retention_period': _has(text, [
            r'retention', r'kept?\s+for', r'stored?\s+for', r'deleted?\s+after',
            r'erasure', r'purge', r'\d+\s+(month|year|day)',
        ]),
        'has_data_subject_rights': _has(text, [
            r'right\s+to\s+(access|erasure|object|portab|restrict|correct|rectif)',
            r'data\s+subject\s+rights', r'subject\s+access',
            r'right\s+to\s+be\s+forgotten',
        ]),
        'has_risk_assessment': _has(text, [
            r'risk\s+(assessment|register|evaluat|analys)',
            r'likelihood', r'severity', r'impact.*risk', r'risk.*impact',
        ]),
        'has_mitigation_measures': _has(text, [
            r'mitigat', r'safeguard', r'control', r'remediat',
            r'measure.*risk', r'risk.*measure',
        ]),
        'has_international_transfer': _has(text, [
            r'transfer.*third\s+countr', r'international\s+transfer',
            r'outside\s+the\s+eea', r'non.eea', r'standard\s+contractual',
            r'\bsccs?\b', r'adequacy', r'chapter\s+v',
        ]),
        'has_sub_processor_list': _has(text, [
            r'sub.?processor', r'list\s+of.*processor',
            r'processor.*list', r'third.party.*processor',
        ]),
        'has_dpo_mention': _has(text, [
            r'\bdpo\b', r'data\s+protection\s+officer', r'dpo.*consult',
            r'consult.*dpo',
        ]),
        'has_transfer_mechanism': _has(text, [
            r'standard\s+contractual\s+clauses', r'\bsccs?\b',
            r'adequacy\s+decision', r'binding\s+corporate\s+rules',
            r'\bbcr\b', r'transfer\s+mechanism',
        ]),
        'has_security_measures': _has(text, [
            r'encrypt', r'pseudonymis', r'access\s+control',
            r'security\s+measure', r'technical.*organisational',
            r'appropriate\s+security',
        ]),
        'has_prohibited_uses': _has(text, [
            r'prohibited', r'must\s+not', r'shall\s+not',
            r'not\s+(be\s+)?used?\s+for', r'forbidden', r'out.of.scope',
        ]),
        'has_governance_process': _has(text, [
            r'governance', r'review\s+process', r'approval\s+process',
            r'oversight\s+(process|committee|board)',
            r'accountability', r'responsible.*ai',
        ]),
        'has_bias_assessment': _has(text, [
            r'bias\s+(assessment|evaluat|audit|test)',
            r'fairness', r'discriminat', r'disparate\s+impact',
        ]),
        'has_limitations_section': _has(text, [
            r'limitation', r'out.of.scope', r'known\s+(issue|risk|failure)',
            r'constraint', r'caveat',
        ]),
        'vendors_mentioned': _extract_vendors(text),
    }


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class EvidenceIntakeScanner(BaseScanner):
    """
    Document evidence layer. Classifies compliance documents, extracts structured
    fields, and flags missing evidence, gaps, and contradictions.
    Call set_code_summary() before scan() to enable cross-checking with code findings.
    """
    name = "evidence_intake"

    def __init__(self) -> None:
        self._code_summary: Optional[dict] = None
        self.last_doc_type: str = "unknown"

    def set_code_summary(self, summary: dict) -> None:
        """Inject orchestrator code-scan summary for cross-checking."""
        self._code_summary = summary

    def scan(self, text: str, filename: str = "") -> list[ScannerFinding]:
        if not self._is_document_file(filename):
            return []
        doc_type = self._classify(text, filename)
        self.last_doc_type = doc_type
        extracted = _extract(text)
        return self._check(text, filename, doc_type, extracted)

    # -- File type gate --

    def _is_document_file(self, filename: str) -> bool:
        if not filename:
            return False
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        return ext in ('md', 'txt', 'rst')

    # -- Classification --

    def _classify(self, text: str, filename: str) -> str:
        fname = filename.lower()
        scores: dict[str, int] = {}
        lower = text.lower()
        for doc_type, signals in _DOC_SIGNALS.items():
            score = sum(1 for p in signals if re.search(p, lower))
            for hint in _FILENAME_HINTS.get(doc_type, []):
                if hint in fname:
                    score += 2
            scores[doc_type] = score
        best = max(scores, key=lambda k: scores[k])
        return best if scores[best] > 0 else 'unknown'

    # -- Finding dispatch --

    def _check(self, text: str, filename: str, doc_type: str,
               ex: dict) -> list[ScannerFinding]:
        if doc_type == 'privacy_notice':
            return self._check_privacy_notice(text, filename, ex)
        if doc_type == 'dpia':
            return self._check_dpia(text, filename, ex)
        if doc_type in ('dpa_or_vendor_contract', 'scc_or_transfer_document'):
            return self._check_dpa(text, filename, ex)
        if doc_type in ('product_spec', 'ai_policy', 'model_card'):
            return self._check_ai_doc(text, filename, doc_type, ex)
        if doc_type == 'human_oversight_sop':
            return self._check_oversight_sop(text, filename, ex)
        return self._check_unknown(text, filename, ex)

    # -- Privacy notice checks --

    # Rights that must appear in every privacy notice under GDPR Art. 13(2)(b-d).
    _KEY_RIGHTS: dict[str, list[str]] = {
        'erasure / right to be forgotten': [r'\berasure\b', r'\bforgotten\b', r'\bdeletion\b'],
        'data portability':                [r'\bportab'],
        'rectification':                   [r'\brectif', r'\bcorrect'],
        'objection to processing':         [r'\bobject'],
    }

    def _check_privacy_notice(self, text: str, filename: str,
                               ex: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        cs = self._code_summary or {}
        ai_in_code = bool(cs.get('ai_systems_detected'))
        vendors_in_code: list[str] = [
            v.get('name', '').lower()
            for v in cs.get('ai_systems_detected', [])
        ]
        special_cat_in_code = cs.get('has_special_category_data', False)
        auto_decisions_in_code = cs.get('has_automated_decisions', False)

        # ── AI / automated processing disclosure ──────────────────────────────
        # Always-on: fire regardless of code context.
        # Confidence and finding_type upgrade when code context confirms AI is used.
        if not ex['has_ai_disclosure']:
            if ai_in_code:
                vendor_names = ', '.join(
                    v.get('name', '') for v in cs.get('ai_systems_detected', [])
                ) or 'AI systems'
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='Privacy notice does not disclose AI or automated processing',
                    description=(
                        f"Code analysis detected {vendor_names} but this privacy notice "
                        "contains no disclosure of AI use, automated processing, or algorithmic "
                        "decision-making. GDPR Art. 13-14 requires disclosure of the logic, "
                        "significance, and envisaged consequences of automated processing."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['missing_evidence', 'GDPR_ART13_14_TRANSPARENCY',
                          'AI_ACT_ART13_TRANSPARENCY'],
                    confidence=0.85,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'ai_disclosure',
                              'cross_checked': True, 'ai_systems_in_code': vendors_in_code},
                ))
            else:
                findings.append(self._make(
                    finding_type='requires_review',
                    title='Privacy notice does not disclose AI or automated processing',
                    description=(
                        "No reference to artificial intelligence, machine learning, or automated "
                        "processing was found. If your system uses AI or automated decision-making, "
                        "GDPR Art. 13(2)(f) requires disclosure of the logic involved and its "
                        "significance. Verify whether this disclosure is needed."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['requires_review', 'GDPR_ART13_14_TRANSPARENCY',
                          'AI_ACT_ART13_TRANSPARENCY'],
                    confidence=0.70,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'ai_disclosure',
                              'cross_checked': False},
                ))

        # ── Vendor naming (cross-check only, requires code context) ───────────
        if vendors_in_code and ex['has_ai_disclosure']:
            missing_vendors = [
                v for v in vendors_in_code
                if v and v not in ex['vendors_mentioned']
            ]
            if missing_vendors:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title=f"Privacy notice does not name AI processor(s): {', '.join(missing_vendors)}",
                    description=(
                        f"Code uses {', '.join(missing_vendors)} but the privacy notice "
                        "does not identify this processor by name. GDPR Art. 13(1)(e) requires "
                        "disclosure of recipients or categories of recipients."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['missing_evidence', 'GDPR_ART13_14_TRANSPARENCY', 'GDPR_ART28_PROCESSOR'],
                    confidence=0.80,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'vendor_not_named',
                              'missing_vendors': missing_vendors},
                ))

        # ── Automated decision-making disclosure ──────────────────────────────
        if not ex['has_automated_decision_disclosure']:
            if auto_decisions_in_code:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='Automated decision-making detected in code but not disclosed',
                    description=(
                        "Code analysis found automated decision-making patterns but this privacy "
                        "notice does not reference GDPR Art. 22 rights or the logic behind "
                        "automated decisions. Art. 13(2)(f) requires meaningful information about "
                        "the logic, significance, and envisaged consequences."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['missing_evidence', 'GDPR_ART22_AUTOMATED_DECISIONS',
                          'GDPR_ART13_14_TRANSPARENCY'],
                    confidence=0.85,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'automated_decision_disclosure',
                              'cross_checked': True},
                ))
            else:
                findings.append(self._make(
                    finding_type='requires_review',
                    title='Privacy notice does not address automated decision-making',
                    description=(
                        "No disclosure of automated decision-making or profiling was found. "
                        "If the system makes automated decisions with legal or similarly significant "
                        "effects, GDPR Art. 22 rights must be disclosed — including the right to "
                        "request human review and to contest decisions."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['requires_review', 'GDPR_ART22_AUTOMATED_DECISIONS',
                          'GDPR_ART13_14_TRANSPARENCY'],
                    confidence=0.68,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'automated_decision_disclosure',
                              'cross_checked': False},
                ))

        # ── Special category data (Art. 9) ────────────────────────────────────
        if not ex['has_special_category_mention']:
            if special_cat_in_code:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='Special category data processed in code but not disclosed',
                    description=(
                        "Code analysis detected special category data (health, ethnicity, "
                        "disability or similar) but this privacy notice does not reference "
                        "Art. 9 special category data or an explicit Art. 9(2) legal basis."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['missing_evidence', 'GDPR_ART9_SPECIAL_CATEGORY',
                          'GDPR_ART13_14_TRANSPARENCY'],
                    confidence=0.85,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'special_category_disclosure',
                              'cross_checked': True},
                ))
            else:
                findings.append(self._make(
                    finding_type='requires_review',
                    title='Privacy notice does not reference special category data',
                    description=(
                        "No reference to Art. 9 special category data (health, ethnicity, "
                        "disability, biometric, genetic, political, religious, or criminal data) "
                        "was found. If any such data is processed, a specific Art. 9(2) basis "
                        "must be identified and disclosed."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['requires_review', 'GDPR_ART9_SPECIAL_CATEGORY'],
                    confidence=0.65,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'special_category_disclosure',
                              'cross_checked': False},
                ))

        # ── Lawful basis ──────────────────────────────────────────────────────
        if not ex['has_legal_basis']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='Privacy notice does not state a lawful basis for processing',
                description=(
                    "No lawful basis for processing was identified. "
                    "GDPR Art. 13(1)(c) requires disclosure of the legal basis and, where "
                    "legitimate interests apply, the specific interests pursued."
                ),
                filename=filename, line_start=None, excerpt=None,
                tags=['missing_evidence', 'GDPR_ART6_LAWFUL_BASIS', 'GDPR_ART13_14_TRANSPARENCY'],
                confidence=0.85,
                metadata={'doc_type': 'privacy_notice', 'gap': 'lawful_basis'},
            ))

        # ── Retention period ──────────────────────────────────────────────────
        if not ex['has_retention_period']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='Privacy notice does not specify a retention period',
                description=(
                    "No data retention period or criteria for determining it was found. "
                    "GDPR Art. 13(2)(a) requires disclosure of the storage period or the "
                    "criteria used to determine it."
                ),
                filename=filename, line_start=None, excerpt=None,
                tags=['missing_evidence', 'GDPR_ART5_PRINCIPLES', 'GDPR_ART13_14_TRANSPARENCY'],
                confidence=0.80,
                metadata={'doc_type': 'privacy_notice', 'gap': 'retention_period'},
            ))

        # ── Data subject rights — existence and completeness ──────────────────
        has_rights_section = _has(text, [
            r'right\s+to\s+(access|erasure|object|portab|restrict|correct|rectif)',
            r'data\s+subject\s+rights',
            r'your\s+rights',
            r'you\s+have\s+the\s+(following\s+)?right',
            r'rights\s*:',
        ])

        if not has_rights_section:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='Privacy notice does not reference data subject rights',
                description=(
                    "No data subject rights section was found. GDPR Art. 13(2)(b-d) requires "
                    "disclosure of the rights of access, erasure, portability, rectification, "
                    "objection, and restriction of processing."
                ),
                filename=filename, line_start=None, excerpt=None,
                tags=['missing_evidence', 'GDPR_ART13_14_TRANSPARENCY'],
                confidence=0.85,
                metadata={'doc_type': 'privacy_notice', 'gap': 'data_subject_rights'},
            ))
        else:
            # Rights section exists — check completeness
            missing_rights = [
                name for name, patterns in self._KEY_RIGHTS.items()
                if not _has(text, patterns)
            ]
            if missing_rights:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title=f"Privacy notice rights section incomplete — missing: {', '.join(missing_rights)}",
                    description=(
                        f"A data subject rights section was found but appears to omit: "
                        f"{', '.join(missing_rights)}. GDPR Art. 13(2)(b-d) requires disclosure "
                        "of all applicable rights including erasure, portability, rectification, "
                        "and objection to processing."
                    ),
                    filename=filename, line_start=None, excerpt=None,
                    tags=['missing_evidence', 'GDPR_ART13_14_TRANSPARENCY'],
                    confidence=0.75,
                    metadata={'doc_type': 'privacy_notice', 'gap': 'rights_incomplete',
                              'missing_rights': missing_rights},
                ))

        return findings

    # -- DPIA checks --

    def _check_dpia(self, text: str, filename: str, ex: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        cs = self._code_summary or {}
        auto_decisions_in_code = cs.get('has_automated_decisions', False)
        ai_in_code = bool(cs.get('ai_systems_detected'))

        # Cross-check: automated decisions in code, DPIA doesn't mention them
        if auto_decisions_in_code and not ex['has_automated_decision_disclosure']:
            findings.append(self._make(
                finding_type='contradiction',
                title='Code has automated decisions but DPIA does not address automated processing',
                description=(
                    "Code analysis identified automated decision-making patterns, but this DPIA "
                    "does not appear to assess automated processing risks. GDPR Art. 35(3)(a) "
                    "specifically requires DPIAs for systematic and extensive profiling or automated "
                    "decisions with legal or similarly significant effects."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['contradiction', 'GDPR_ART35_DPIA', 'GDPR_ART22_AUTOMATED_DECISIONS'],
                confidence=0.80,
                metadata={'doc_type': 'dpia', 'contradiction': 'automated_decisions_not_assessed',
                          'code_has_automated_decisions': True},
            ))

        # Cross-check: AI in code but DPIA doesn't address AI risks
        if ai_in_code and not ex['has_ai_disclosure']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='DPIA does not address AI-specific risks detected in code',
                description=(
                    "Code analysis detected AI/ML systems but this DPIA does not appear to address "
                    "AI-specific risks such as algorithmic bias, model drift, or opaque decision logic. "
                    "AI Act Art. 9 requires risk management systems for high-risk AI. "
                    "GDPR Art. 35 DPIAs should address risks arising from the use of AI."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'GDPR_ART35_DPIA', 'AI_ACT_ART9_RISK_MANAGEMENT'],
                confidence=0.80,
                metadata={'doc_type': 'dpia', 'gap': 'ai_risk_not_assessed'},
            ))

        if not ex['has_risk_assessment']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='DPIA does not contain a risk assessment',
                description=(
                    "No risk assessment, risk register, or likelihood/severity analysis was detected. "
                    "GDPR Art. 35(7)(c) requires DPIAs to assess the risks to rights and freedoms of "
                    "data subjects, including their source, nature, and severity."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'GDPR_ART35_DPIA'],
                confidence=0.80,
                metadata={'doc_type': 'dpia', 'gap': 'risk_assessment'},
            ))

        if not ex['has_mitigation_measures']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='DPIA does not describe mitigation measures',
                description=(
                    "No mitigation measures, safeguards, or risk controls were identified. "
                    "GDPR Art. 35(7)(d) requires DPIAs to include measures to address risks, "
                    "with regard to the rights and legitimate interests of data subjects."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'GDPR_ART35_DPIA'],
                confidence=0.75,
                metadata={'doc_type': 'dpia', 'gap': 'mitigation_measures'},
            ))

        if not ex['has_human_oversight_mention'] and (ai_in_code or auto_decisions_in_code):
            findings.append(self._make(
                finding_type='missing_evidence',
                title='DPIA does not describe a human oversight mechanism',
                description=(
                    "No human review or oversight mechanism was described in this DPIA, despite "
                    "automated processing being present. AI Act Art. 14 and GDPR Art. 22 require "
                    "human oversight for automated decisions. The DPIA should document how oversight "
                    "is implemented and who has the authority to intervene."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'GDPR_ART35_DPIA', 'AI_ACT_ART14_HUMAN_OVERSIGHT'],
                confidence=0.80,
                metadata={'doc_type': 'dpia', 'gap': 'human_oversight'},
            ))

        if not ex['has_dpo_mention']:
            findings.append(self._make(
                finding_type='requires_review',
                title='No DPO consultation documented in DPIA',
                description=(
                    "No reference to DPO consultation was found. GDPR Art. 35(2) requires the "
                    "controller to seek advice from the DPO when carrying out a DPIA. "
                    "This should be evidenced in the DPIA document."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['requires_review', 'GDPR_ART35_DPIA'],
                confidence=0.70,
                metadata={'doc_type': 'dpia', 'gap': 'dpo_consultation'},
            ))

        return findings

    # -- DPA / SCC checks --

    def _check_dpa(self, text: str, filename: str, ex: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if not ex['has_sub_processor_list']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='DPA does not include or reference a sub-processor list',
                description=(
                    "No list of sub-processors or reference to a maintained sub-processor register "
                    "was found. GDPR Art. 28(2)-(3) requires the processor to obtain prior "
                    "authorisation for sub-processors and to inform the controller of any changes."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'GDPR_ART28_PROCESSOR'],
                confidence=0.75,
                metadata={'doc_type': 'dpa_or_vendor_contract', 'gap': 'sub_processor_list'},
            ))

        if not ex['has_transfer_mechanism']:
            findings.append(self._make(
                finding_type='missing_evidence',
                title='DPA does not specify a data transfer mechanism for international transfers',
                description=(
                    "No transfer mechanism (SCCs, adequacy decision, BCRs) was identified. "
                    "If the processor is outside the EEA, GDPR Art. 44-49 requires an appropriate "
                    "safeguard for the transfer of personal data to a third country."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'GDPR_ART44_49_TRANSFERS', 'GDPR_ART28_PROCESSOR'],
                confidence=0.80,
                metadata={'doc_type': 'dpa_or_vendor_contract', 'gap': 'transfer_mechanism'},
            ))

        if not ex['has_security_measures']:
            findings.append(self._make(
                finding_type='requires_review',
                title='DPA does not describe security measures',
                description=(
                    "No description of technical and organisational security measures was found. "
                    "GDPR Art. 28(3)(c) requires the DPA to set out processor security obligations "
                    "in accordance with Art. 32."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['requires_review', 'GDPR_ART28_PROCESSOR', 'GDPR_ART32_SECURITY'],
                confidence=0.70,
                metadata={'doc_type': 'dpa_or_vendor_contract', 'gap': 'security_measures'},
            ))

        return findings

    # -- AI document checks (product spec, AI policy, model card) --

    def _check_ai_doc(self, text: str, filename: str, doc_type: str,
                      ex: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if doc_type == 'product_spec':
            has_automated = _has(text, [
                r'automat.*rank', r'automat.*scor', r'automat.*screen',
                r'automat.*decision', r'automat.*select', r'AI.*rank',
                r'candidate.*rank', r'shortlist.*automat', r'automat.*shortlist',
            ])
            if has_automated and not ex['has_human_oversight_mention']:
                excerpt = _find_first(text, [
                    r'automat.*rank', r'automat.*scor', r'AI.*rank', r'candidate.*rank',
                ])
                findings.append(self._make(
                    finding_type='requires_review',
                    title='Product spec describes automated processing without human oversight',
                    description=(
                        "This product specification describes automated ranking, scoring, or "
                        "decision-making but does not mention a human oversight or review mechanism. "
                        "GDPR Art. 22 and AI Act Art. 14 require meaningful human oversight for "
                        "automated decisions with significant effects. This system likely requires a "
                        "DPIA and high-risk AI classification assessment."
                    ),
                    filename=filename,
                    line_start=_find_line(text, [r'automat.*rank', r'automat.*scor', r'AI.*rank']),
                    excerpt=(excerpt or '')[:200] or None,
                    tags=['requires_review', 'GDPR_ART22_AUTOMATED_DECISIONS',
                          'AI_ACT_ART14_HUMAN_OVERSIGHT', 'AI_ACT_ART6_HIGH_RISK'],
                    confidence=0.80,
                    metadata={'doc_type': 'product_spec', 'gap': 'human_oversight',
                              'has_automated_processing': True},
                ))

            if has_automated and not ex['has_legal_basis']:
                findings.append(self._make(
                    finding_type='requires_review',
                    title='Product spec describes automated processing but no legal basis documented',
                    description=(
                        "Automated processing is described but no lawful basis under GDPR Art. 6 "
                        "(and Art. 22 where applicable) is mentioned. Documenting the legal basis "
                        "in design documentation is a data protection by design requirement."
                    ),
                    filename=filename,
                    line_start=None,
                    excerpt=None,
                    tags=['requires_review', 'GDPR_ART6_LAWFUL_BASIS', 'GDPR_ART25_PRIVACY_BY_DESIGN'],
                    confidence=0.75,
                    metadata={'doc_type': 'product_spec', 'gap': 'legal_basis'},
                ))

        elif doc_type == 'ai_policy':
            if not ex['has_prohibited_uses']:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='AI policy does not define prohibited use cases',
                    description=(
                        "No prohibited use cases or out-of-scope uses were identified. An AI policy "
                        "should explicitly prohibit uses that would constitute prohibited AI practices "
                        "under AI Act Art. 5, or that would create unacceptable compliance risks."
                    ),
                    filename=filename,
                    line_start=None,
                    excerpt=None,
                    tags=['missing_evidence', 'AI_ACT_ART5_PROHIBITED'],
                    confidence=0.75,
                    metadata={'doc_type': 'ai_policy', 'gap': 'prohibited_uses'},
                ))

            if not ex['has_governance_process']:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='AI policy does not describe a governance or review process',
                    description=(
                        "No AI governance process, review board, or accountability mechanism was "
                        "identified. AI Act Art. 9 and 26 require documented oversight and governance "
                        "for high-risk AI systems."
                    ),
                    filename=filename,
                    line_start=None,
                    excerpt=None,
                    tags=['missing_evidence', 'AI_ACT_ART9_RISK_MANAGEMENT',
                          'AI_ACT_ART26_DEPLOYER'],
                    confidence=0.70,
                    metadata={'doc_type': 'ai_policy', 'gap': 'governance_process'},
                ))

        elif doc_type == 'model_card':
            if not ex['has_bias_assessment']:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='Model card does not include a bias evaluation',
                    description=(
                        "No bias assessment, fairness evaluation, or disparate impact analysis was "
                        "found. AI Act Art. 10 requires data governance practices including bias "
                        "examination for high-risk AI training data."
                    ),
                    filename=filename,
                    line_start=None,
                    excerpt=None,
                    tags=['missing_evidence', 'AI_ACT_ART10_DATA_GOVERNANCE'],
                    confidence=0.80,
                    metadata={'doc_type': 'model_card', 'gap': 'bias_assessment'},
                ))

            if not ex['has_limitations_section']:
                findings.append(self._make(
                    finding_type='missing_evidence',
                    title='Model card does not describe known limitations or out-of-scope uses',
                    description=(
                        "No limitations section or out-of-scope use cases were identified. "
                        "AI Act Art. 13 requires transparency documentation to include known risks "
                        "and limitations. This information should be communicated to deployers."
                    ),
                    filename=filename,
                    line_start=None,
                    excerpt=None,
                    tags=['missing_evidence', 'AI_ACT_ART13_TRANSPARENCY'],
                    confidence=0.75,
                    metadata={'doc_type': 'model_card', 'gap': 'limitations'},
                ))

        return findings

    # -- Human oversight SOP checks --

    def _check_oversight_sop(self, text: str, filename: str,
                              ex: dict) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if not _has(text, [r'authorit', r'responsibilit', r'role', r'who\s+(must|should|will)']):
            findings.append(self._make(
                finding_type='missing_evidence',
                title='Human oversight SOP does not define reviewer roles or authority',
                description=(
                    "No defined reviewer roles, responsibilities, or authority were found. "
                    "AI Act Art. 14 requires that oversight persons have the authority, knowledge "
                    "and tools to meaningfully assess AI output before acting on it."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'AI_ACT_ART14_HUMAN_OVERSIGHT'],
                confidence=0.75,
                metadata={'doc_type': 'human_oversight_sop', 'gap': 'reviewer_roles'},
            ))

        if not _has(text, [r'override', r'interven', r'stop', r'escalat', r'reject.*decision']):
            findings.append(self._make(
                finding_type='missing_evidence',
                title='Human oversight SOP does not describe override or intervention procedure',
                description=(
                    "No override, intervention, or escalation mechanism was described. "
                    "AI Act Art. 14(4)(d) requires that oversight persons be able to intervene "
                    "or interrupt the AI system. The SOP must document how this is done."
                ),
                filename=filename,
                line_start=None,
                excerpt=None,
                tags=['missing_evidence', 'AI_ACT_ART14_HUMAN_OVERSIGHT'],
                confidence=0.75,
                metadata={'doc_type': 'human_oversight_sop', 'gap': 'override_procedure'},
            ))

        return findings

    # -- Unknown document type --

    def _check_unknown(self, text: str, filename: str, ex: dict) -> list[ScannerFinding]:
        return [self._make(
            finding_type='requires_review',
            title='Document type could not be classified',
            description=(
                f"The document '{filename}' could not be classified into a known compliance "
                f"document type. Manual review is required to determine applicable obligations."
            ),
            filename=filename,
            line_start=None,
            excerpt=None,
            tags=['requires_review'],
            confidence=0.60,
            metadata={'doc_type': 'unknown'},
        )]

    # -- Finding factory --

    def _make(self, finding_type: str, title: str, description: str,
              filename: str, line_start: Optional[int], excerpt: Optional[str],
              tags: list[str], confidence: float, metadata: dict) -> ScannerFinding:
        return ScannerFinding(
            scanner_name=self.name,
            finding_type=finding_type,
            title=title,
            description=description,
            confidence=confidence,
            file_path=filename,
            line_start=line_start,
            line_end=None,
            evidence_excerpt=excerpt,
            tags=tags,
            suggested_node_type='document_evidence',
            metadata=metadata,
        )
