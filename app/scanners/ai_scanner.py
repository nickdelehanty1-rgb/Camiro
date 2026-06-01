import re
from .base import BaseScanner, ScannerFinding

# AI model and API patterns
AI_PROVIDER_PATTERNS = {
    "OpenAI": [
        r'openai\.chat\.completions',
        r'openai\.Completion',
        r'from openai import',
        r'import openai',
        r'OpenAI\(',
        r'ChatOpenAI\(',
        r'gpt-4|gpt-3\.5|gpt-4o',
    ],
    "Anthropic": [
        r'anthropic\.messages',
        r'from anthropic import',
        r'import anthropic',
        r'Anthropic\(',
        r'claude-',
        r'claude\.ai',
    ],
    "Google AI": [
        r'google\.generativeai',
        r'vertexai\.',
        r'gemini-pro|gemini-flash|gemini-ultra',
        r'from google\.cloud import aiplatform',
        r'PaLM|palm-2',
    ],
    "Azure OpenAI": [
        r'AzureOpenAI\(',
        r'azure\.openai',
        r'openai\.AzureOpenAI',
    ],
    "AWS Bedrock": [
        r'bedrock',
        r'boto3.*bedrock',
        r'aws.*ai|ai.*aws',
    ],
    "Hugging Face": [
        r'from transformers import',
        r'import transformers',
        r'HuggingFace|huggingface',
        r'pipeline\(',
        r'AutoModelFor',
        r'AutoTokenizer',
    ],
    "LangChain": [
        r'from langchain import',
        r'import langchain',
        r'LangChain|langchain',
        r'ChatOpenAI|ChatAnthropic|ChatGoogle',
    ],
    "LlamaIndex": [
        r'from llama_index import',
        r'import llama_index',
        r'LlamaIndex|llama_index',
    ],
    "sklearn": [
        r'from sklearn import',
        r'import sklearn',
        r'sklearn\.',
        r'RandomForest|LogisticRegression|SVM|GradientBoosting',
    ],
    "TensorFlow/Keras": [
        r'import tensorflow',
        r'from tensorflow import',
        r'import keras',
        r'tf\.keras',
    ],
    "PyTorch": [
        r'import torch',
        r'from torch import',
        r'torch\.nn',
    ],
    "XGBoost": [
        r'import xgboost',
        r'from xgboost import',
        r'XGBClassifier|XGBRegressor',
    ],
    # Generic LLM client interfaces — catches systems built on top of any model
    "Generic LLM Client": [
        r'\bllm\.complete\s*\(',
        r'\bllm\.chat\s*\(',
        r'\bllm\.generate\s*\(',
        r'\bllm\.run\s*\(',
        r'\bllm\.call\s*\(',
        r'\b(LlmClient|AIClient|ModelClient|MockLlmClient|BaseLLM)\b',
        r'\bllm_client\s*=',
        r'\bai_client\s*=',
        r'\bmodel_client\s*=',
    ],
    # LLM API call signatures — parameter names only possible in model API calls
    "LLM API Signature": [
        r'"role"\s*:\s*"system"',
        r"'role'\s*:\s*'system'",
        r'\bmax_tokens\s*=\s*\d',
        r'\bmaxTokens\s*[:=]\s*\d',
        r'\bprompt_tokens\b|\bpromptTokens\b',
        r'\btemperature\s*=\s*[01]\.',
        r'\bsystem_message\s*=\s*["\']',
        r'\bsystem_prompt\s*=\s*["\']',
    ],
    # AI service layer class names — moderation, recommendation, classification
    "AI Service Layer": [
        r'\bModerationService\b|\bProfileModerationService\b',
        r'\bRecommendationService\b|\bMatchRecommendationService\b',
        r'\bSafetyService\b|\bMessageSafetyService\b|\bContentSafetyService\b',
        r'\bClassificationService\b|\bRankingService\b|\bScoringService\b',
        r'\bCompatibilityService\b|\bMatchingService\b',
        r'\bAIService\b|\bMLService\b|\bModelService\b',
    ],
    # AI-named output variables — explicit "ai" or "llm" prefix in field names
    "AI-Named Output": [
        r'\bai[_]?(explanation|score|rating|recommendation|result|decision|label)\b',
        r'\baiExplanation\b|\baiScore\b|\baiRating\b|\baiDecision\b',
        r'\bcompatibilityScore\b|\bcompatibility_score\b',
        r'\brecommendedAction\b|\brecommended_action\b',
        r'\bllm[_]?(response|output|result|completion)\b',
    ],
}

class DomainContextClassifier:
    """
    Classifies the Annex III domain of an AI system from code-structure PURPOSE signals.

    Domain is determined by what the AI DECIDES — class names, function names, SQL
    table names, and output variables that describe the decision context. Data fields
    present as INPUTS (e.g. income in a housing app) do not trigger domain classification
    because the same data can be used across multiple decision types.

    Each domain has patterns that only match identifiers, class/function definitions,
    SQL, or URL paths — not plain words in string literals or comments.
    """

    DOMAINS: dict[str, dict] = {
        "employment/recruitment": {
            "description": "employment/recruitment",
            "annex_ref": "AI Act Annex III §4",
            "patterns": [
                r'\bcandidate[_\.](id|name|score|status|email|data|rank)\b',
                r'\bapplicant[_\.](id|name|score|status|data)\b',
                r'class\s+\w*(Candidate|Applicant|Hiring|Recruitment|Interview|Screening)\b',
                r'def\s+\w*(candidate|applicant|screen_candidate|hire_|recruit_|screen_applicant)\w*\s*\(',
                r'(?:FROM|JOIN|UPDATE|INSERT\s+INTO)\s+\w*(?:candidates|applicants|job_applications|job_seekers)\b',
                r'\b(hiring_decision|employment_decision|job_offer|job_rejection)\b',
                r'\b(cv_text|cv_score|resume_score|resume_text)\b',
                r'\b(workforce_decision|termination_decision|promotion_decision)\b',
            ],
        },
        "housing/property": {
            "description": "housing/access-to-services",
            "annex_ref": "AI Act Annex III §5",
            "patterns": [
                r'\btenant[_\.](id|name|score|status|application|data)\b',
                r'\brental[_\.](?:application|decision|approval|screening|score)\b',
                r'\brent[_\.](?:application|assessment|approval)\b',
                r'class\s+\w*(Tenant|Rental|Property|Landlord|Housing|Letting)\b',
                r'def\s+\w*(screen_tenant|assess_tenant|approve_rental|tenant_screen|rental_assess)\w*\s*\(',
                r'(?:FROM|JOIN|UPDATE)\s+\w*(?:tenants|rentals|properties|lettings|leases)\b',
                r'\b(rental_approved|rental_rejected|tenancy_granted|lease_approved|tenant_rejected)\b',
                r'\b(tenancy_score|rental_score|deposit_assessment|move_in_assessment)\b',
            ],
        },
        "credit/financial": {
            "description": "credit/financial services",
            "annex_ref": "AI Act Annex III §5b",
            "patterns": [
                # Require explicit credit/loan PURPOSE context — not bare credit_score which
                # appears as an input data field in employment, housing, and other systems.
                r'\bloan[_\.](?:application|approval|decision|assessment)\b',
                r'class\s+\w*(Credit|Loan|Mortgage|Lending|Insurance|Underwriting)\b',
                r'def\s+\w*(credit_score|loan_decision|underwrite|assess_credit|approve_loan)\w*\s*\(',
                r'(?:FROM|UPDATE)\s+\w*(?:loan_applications|credit_applications|mortgages)\b',
                r'\b(loan_approved|loan_rejected|credit_granted|mortgage_approved)\b',
                r'\b(debt_to_income|debt_ratio|affordability_score|underwriting_decision)\b',
                r'\bcredit[_\.](?:risk|limit|decision|application)\b',  # risk/limit/decision only — not bare credit_score
            ],
        },
        "healthcare": {
            "description": "healthcare",
            "annex_ref": "AI Act Annex III §5a",
            "patterns": [
                r'\bpatient[_\.](?:id|name|data|record|diagnosis|assessment)\b',
                r'\b(?:diagnosis|diagnostic)_\w+\b',
                r'class\s+\w*(Patient|Medical|Clinical|Diagnosis|Healthcare|Triage)\b',
                r'def\s+\w*(diagnose|triage_patient|medical_assess|clinical_decision|treatment_plan)\w*\s*\(',
                r'(?:FROM|UPDATE)\s+\w*(?:patients|medical_records|diagnoses|clinical_notes)\b',
                r'\b(treatment_recommendation|clinical_decision|medical_outcome|health_outcome)\b',
                r'\b(icd_code|diagnosis_code|triage_level|clinical_score)\b',
            ],
        },
        "education": {
            "description": "education",
            "annex_ref": "AI Act Annex III §3",
            "patterns": [
                r'\bstudent[_\.](?:id|name|score|grade|data|assessment)\b',
                r'\b(?:student_assessment|academic_score|enrollment_decision|admission_decision)\b',
                r'class\s+\w*(Student|Academic|Enrollment|Admission|Education)\b',
                r'def\s+\w*(assess_student|grade_student|admit_student|enroll_student)\w*\s*\(',
                r'(?:FROM|UPDATE)\s+\w*(?:students|academic_records|enrollments|admissions)\b',
                r'\b(exam_result|academic_outcome|grade_prediction|admission_score)\b',
            ],
        },
    }

    def classify(self, code: str) -> list[str]:
        """Return list of domain keys where code-structure purpose signals match."""
        return [
            domain_key
            for domain_key, info in self.DOMAINS.items()
            if any(re.search(p, code, re.IGNORECASE) for p in info["patterns"])
        ]


# Automated decision-making patterns
AUTOMATED_DECISION_PATTERNS = [
    (r'\b(auto_reject|auto_approve|auto_decline|auto_accept)\b', "Automated approval/rejection function", "critical"),
    (r'\bscore\s*[<>=!]+\s*\d+\b', "Score threshold comparison", "high"),
    (r'\b(reject|decline|deny)\s*\(', "Rejection function call", "high"),
    (r'\b(approve|accept|pass)\s*\(', "Approval function call", "high"),
    (r'\b(candidate_score|applicant_score|user_score|risk_score|credit_score|fraud_score)\b', "Risk/suitability scoring variable", "high"),
    (r'\b(shortlist|rank_candidate|rank_applicant|filter_candidates)\b', "Candidate ranking/filtering", "high"),
    (r'\b(eligibility|is_eligible|check_eligibility)\b', "Eligibility determination", "high"),
    (r'\b(blacklist|blocklist|deny_list)\b', "Blacklist/block function", "medium"),
    (r'status\s*=\s*["\']rejected["\']', "Setting rejected status", "critical"),
    (r'status\s*=\s*["\']approved["\']', "Setting approved status", "high"),
    (r'status\s*=\s*["\']declined["\']', "Setting declined status", "critical"),
    (r'\b(send_rejection|rejection_email|decline_email)\b', "Automated rejection notification", "critical"),
    (r'if\s+score\s*[<>=!]', "Score-based conditional decision", "high"),
    (r'\b(batch_reject|bulk_reject|mass_reject)\b', "Bulk automated rejection", "critical"),
]

# Human oversight absence patterns
HUMAN_OVERSIGHT_ABSENCE = [
    r'human_review\s*=\s*False',
    r'requires_review\s*=\s*False',
    r'auto_decision\s*=\s*True',
    r'skip_review\s*=\s*True',
    r'no_human_check',
]


class AIUsageScanner(BaseScanner):
    name = "ai_usage"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        detected_providers = {}

        for provider, patterns in AI_PROVIDER_PATTERNS.items():
            for pattern_str in patterns:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                matches = self._find_lines_matching(code, pattern)
                if matches and provider not in detected_providers:
                    line_num, line_text = matches[0]
                    detected_providers[provider] = (line_num, line_text)
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type="ai_provider_detected",
                        title=f"AI provider detected: {provider}",
                        description=(
                            f"Code uses {provider} — an AI model provider. "
                            f"Personal data sent to this provider may require a Data Processing Agreement "
                            f"under GDPR Art. 28 and transfer safeguards under Art. 44-49 if provider is outside EEA. "
                            f"The AI system may also require classification under the EU AI Act."
                        ),
                        confidence=0.95,
                        file_path=filename,
                        line_start=line_num,
                        evidence_excerpt=self._excerpt(line_text),
                        tags=["ai_system", "vendor", "GDPR_ART28", "AI_ACT_ART6", provider.lower().replace(" ", "_")],
                        suggested_node_type="ai_system",
                        metadata={"provider": provider}
                    ))

        # Domain classification: determine PRIMARY purpose from code-structure signals.
        # Domain is classified from WHAT THE AI DECIDES (class names, function names,
        # SQL tables, output variables) — NOT from which data fields are inputs.
        # Employment data (income, job_title) in a housing app does NOT trigger
        # employment classification; TenantScreeningService does.
        if detected_providers:
            classifier = DomainContextClassifier()
            matched_domains = classifier.classify(code)
            providers_list = list(detected_providers.keys())

            if not matched_domains:
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="ai_domain_unclear",
                    title="AI system detected — domain classification requires legal review",
                    description=(
                        "AI system detected. Domain classification requires legal review. "
                        "Current evidence does not confirm employment, credit, healthcare, "
                        "education, or housing context from code structure alone. "
                        "If this system is deployed in an AI Act Annex III context, "
                        "high-risk classification obligations apply. Human legal review required."
                    ),
                    confidence=0.75,
                    file_path=filename,
                    tags=["ai_system", "AI_ACT_ART6_HIGH_RISK", "requires_review"],
                    suggested_node_type="ai_system",
                    metadata={
                        "domain_confirmed": False,
                        "matched_domains": [],
                        "detected_providers": providers_list,
                    },
                ))
            elif len(matched_domains) == 1:
                domain_key = matched_domains[0]
                info = DomainContextClassifier.DOMAINS[domain_key]
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="ai_domain_confirmed",
                    title=(
                        f"AI system in {info['description']} context — "
                        f"AI Act high-risk review required ({info['annex_ref']})"
                    ),
                    description=(
                        f"Code-structure signals confirm this AI system operates in a "
                        f"{info['description']} context ({info['annex_ref']}). "
                        f"If it makes or influences decisions with legal or similarly "
                        f"significant effects on individuals, high-risk classification "
                        f"obligations under the AI Act may apply. "
                        f"Legal review required before deployment."
                    ),
                    confidence=0.80,
                    file_path=filename,
                    tags=["ai_system", "AI_ACT_ART6_HIGH_RISK", "requires_review",
                          domain_key.replace("/", "_").replace(" ", "_")],
                    suggested_node_type="ai_system",
                    metadata={
                        "domain_confirmed": True,
                        "matched_domains": matched_domains,
                        "detected_providers": providers_list,
                        "annex_ref": info["annex_ref"],
                    },
                ))
            else:
                # Multiple domains — list all and flag for review
                domain_labels = ", ".join(
                    DomainContextClassifier.DOMAINS[d]["description"]
                    for d in matched_domains
                )
                annex_refs = ", ".join(
                    DomainContextClassifier.DOMAINS[d]["annex_ref"]
                    for d in matched_domains
                )
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="ai_domain_multiple",
                    title=(
                        f"Multiple AI Act domain signals detected: {domain_labels}"
                    ),
                    description=(
                        f"Code-structure signals match multiple AI Act Annex III domains: "
                        f"{domain_labels} ({annex_refs}). "
                        f"Multiple domain signals detected. Legal review required for "
                        f"AI Act high-risk classification. Each applicable domain may "
                        f"carry independent high-risk obligations."
                    ),
                    confidence=0.78,
                    file_path=filename,
                    tags=["ai_system", "AI_ACT_ART6_HIGH_RISK", "requires_review"],
                    suggested_node_type="ai_system",
                    metadata={
                        "domain_confirmed": True,
                        "matched_domains": matched_domains,
                        "detected_providers": providers_list,
                        "annex_refs": annex_refs,
                    },
                ))

        return findings


class AutomatedDecisionScanner(BaseScanner):
    name = "automated_decision"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        found_types = set()

        for pattern_str, description, severity in AUTOMATED_DECISION_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            for line_num, line_text in matches:
                key = pattern_str
                if key not in found_types:
                    found_types.add(key)
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type="automated_decision_detected",
                        title=f"Automated decision indicator: {description}",
                        description=(
                            f"Code contains a pattern suggesting automated decision-making: '{description}'. "
                            f"If this decision has legal or similarly significant effects on individuals, "
                            f"GDPR Article 22 and AI Act Article 14 (human oversight) may apply. "
                            f"A human review mechanism is required."
                        ),
                        confidence=0.85,
                        file_path=filename,
                        line_start=line_num,
                        evidence_excerpt=self._excerpt(line_text),
                        tags=["automated_decision", "GDPR_ART22", "AI_ACT_ART14", severity],
                        suggested_node_type="processing_activity",
                        metadata={"decision_type": description, "severity": severity}
                    ))

        # Check for absence of human oversight
        has_human_review = bool(re.search(r'human_review|requires_review|manual_review|human_check', code, re.IGNORECASE))
        has_automated_decision = any(
            re.search(p, code, re.IGNORECASE)
            for p, _, _ in AUTOMATED_DECISION_PATTERNS[:5]
        )

        if has_automated_decision and not has_human_review:
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type="missing_human_oversight",
                title="No human review mechanism detected",
                description=(
                    "Code contains automated decision patterns but no human review mechanism "
                    "was detected. GDPR Article 22 requires human oversight for decisions with "
                    "legal or significant effects. AI Act Article 14 requires meaningful human "
                    "oversight for high-risk AI systems."
                ),
                confidence=0.8,
                file_path=filename,
                tags=["human_oversight_missing", "GDPR_ART22", "AI_ACT_ART14"],
                suggested_node_type="processing_activity",
                metadata={"oversight_gap": True}
            ))

        return findings
