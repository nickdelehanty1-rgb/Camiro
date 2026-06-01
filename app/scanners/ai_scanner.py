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

# Code-structure signals for AI Act Annex III high-risk domains.
# These patterns match identifiers, SQL, class/function definitions, and URL paths —
# NOT plain words in string literals or comments.
# An AI system is only classified as high-risk in a domain when BOTH an AI model
# AND at least one of these code-structure patterns are present.
_HR_DOMAIN_CODE_SIGNALS: list[str] = [
    # Employment / worker management (Annex III §4)
    r'\bcandidate[_\.](id|name|score|status|email|data|rank)\b',
    r'\bapplicant[_\.](id|name|score|status|data)\b',
    r'class\s+\w*(Candidate|Applicant|Hiring|Recruitment|Interview)\b',
    r'def\s+\w*(candidate|applicant|screen_|hire_|recruit)\w*\s*\(',
    r'(?:FROM|JOIN|UPDATE|INSERT\s+INTO)\s+\w*(?:candidates|applicants|applications|jobs)\b',
    r'[\'"/](?:candidates?|applicants?|applications?|recruitment|job_seekers)[\'"/]',
    # Credit / financial services (Annex III §5b)
    r'\bcredit[_\.](?:score|risk|limit|decision)\b',
    r'\bloan[_\.](?:application|approval|decision|assessment)\b',
    r'class\s+\w*(Credit|Loan|Insurance|Underwriting)\b',
    r'def\s+\w*(credit_score|loan_decision|underwrite|assess_credit)\w*\s*\(',
    # Healthcare / medical (Annex III §5a)
    r'\bpatient[_\.](?:id|name|data|record|diagnosis)\b',
    r'\b(?:diagnosis|diagnostic)_\w+\b',
    r'class\s+\w*(Patient|Medical|Clinical|Diagnosis)\b',
    r'(?:FROM|UPDATE)\s+\w*(?:patients|medical_records|diagnoses)\b',
    # Education / student assessment (Annex III §3)
    r'\bstudent[_\.](?:id|name|score|grade|data)\b',
    r'\b(?:student_assessment|academic_score|enrollment_decision)\b',
    r'class\s+\w*(Student|Academic|Enrollment)\b',
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

        # Domain-clarity check: if an AI system was detected, determine whether
        # code-structure signals confirm a high-risk Annex III domain.
        # Signals must appear in identifiers, SQL, class/function definitions, or
        # URL paths — NOT in string literals or guardrail instructions.
        if detected_providers:
            has_domain_signal = any(
                re.search(p, code, re.IGNORECASE)
                for p in _HR_DOMAIN_CODE_SIGNALS
            )
            if not has_domain_signal:
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="ai_domain_unclear",
                    title="AI system detected — domain context requires review",
                    description=(
                        "AI system detected. Domain context unclear — high-risk AI Act "
                        "classification requires legal review. Current evidence does not "
                        "confirm employment, credit, health, or education context from "
                        "code structure alone. If this system is used in an Annex III "
                        "context (employment, credit, healthcare, education), high-risk "
                        "classification obligations apply. Human legal review required."
                    ),
                    confidence=0.75,
                    file_path=filename,
                    tags=["ai_system", "AI_ACT_ART6_HIGH_RISK", "requires_review"],
                    suggested_node_type="ai_system",
                    metadata={
                        "domain_confirmed": False,
                        "detected_providers": list(detected_providers.keys()),
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
