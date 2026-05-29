from .base import ScannerFinding
from .secret_scanner import SecretRedactionScanner, redact_secrets
from .data_scanner import PersonalDataScanner, SpecialCategoryScanner
from .ai_scanner import AIUsageScanner, AutomatedDecisionScanner
from .vendor_scanner import VendorScanner, DataStorageScanner, RetentionDeletionScanner, LoggingScanner
from .security_scanner import CookieTrackingScanner, SecurityControlScanner
from .data_flow_scanner import DataFlowScanner


ALL_SCANNERS = [
    SecretRedactionScanner(),
    PersonalDataScanner(),
    SpecialCategoryScanner(),
    AIUsageScanner(),
    AutomatedDecisionScanner(),
    VendorScanner(),
    DataStorageScanner(),
    RetentionDeletionScanner(),
    LoggingScanner(),
    CookieTrackingScanner(),
    SecurityControlScanner(),
    DataFlowScanner(),
]


def run_all_scanners(code: str, filename: str = "") -> dict:
    """
    Run all deterministic scanners against the provided code.
    Returns structured results including redacted code and all findings.
    """
    # Step 1: redact secrets before anything else
    redacted_code, secrets_found = redact_secrets(code)

    # Step 2: run all scanners
    all_findings: list[ScannerFinding] = []
    for scanner in ALL_SCANNERS:
        try:
            findings = scanner.scan(redacted_code, filename)
            all_findings.extend(findings)
        except Exception as e:
            # Never let a scanner crash the whole pipeline
            all_findings.append(ScannerFinding(
                scanner_name=scanner.name,
                finding_type="scanner_error",
                title=f"Scanner error: {scanner.name}",
                description=f"Scanner encountered an error: {str(e)}",
                confidence=0.0,
                tags=["scanner_error"],
            ))

    # Step 3: collect summary data
    personal_data_categories = list({
        f.metadata.get("data_category") or f.metadata.get("special_category")
        for f in all_findings
        if f.finding_type in ("personal_data_detected", "special_category_data")
        and (f.metadata.get("data_category") or f.metadata.get("special_category"))
    })

    ai_systems = [
        {"name": f.metadata.get("provider", "Unknown"), "finding_type": f.finding_type}
        for f in all_findings
        if f.finding_type == "ai_provider_detected"
    ]

    vendors = list({
        f.metadata.get("vendor_name")
        for f in all_findings
        if f.finding_type == "third_party_vendor"
        and f.metadata.get("vendor_name")
    })

    has_automated_decisions = any(
        f.finding_type in ("automated_decision_detected", "missing_human_oversight")
        for f in all_findings
    )

    has_special_category = any(
        f.finding_type == "special_category_data"
        for f in all_findings
    )

    # Step 4: determine preliminary risk level from scanner findings
    def determine_risk(findings: list[ScannerFinding]) -> str:
        tags_all = {tag for f in findings for tag in f.tags}
        types_all = {f.finding_type for f in findings}

        if "AI_ACT_ART5" in tags_all or any(
            "prohibited" in t for t in types_all
        ):
            return "prohibited"

        high_severity = [f for f in findings if "critical" in f.tags or "high" in f.tags]
        if has_automated_decisions and has_special_category:
            return "high"
        if len(high_severity) >= 3:
            return "high"
        if len(findings) >= 4:
            return "limited"
        return "minimal"

    preliminary_risk = determine_risk(all_findings)

    return {
        "redacted_code": redacted_code,
        "secrets_found": secrets_found,
        "scanner_findings": [
            {
                "scanner_name": f.scanner_name,
                "finding_type": f.finding_type,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "function_name": f.function_name,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "evidence_excerpt": f.evidence_excerpt,
                "tags": f.tags,
                "suggested_node_type": f.suggested_node_type,
                "metadata": f.metadata,
            }
            for f in all_findings
        ],
        "summary": {
            "total_scanner_findings": len(all_findings),
            "personal_data_categories": personal_data_categories,
            "ai_systems_detected": ai_systems,
            "vendors_detected": vendors,
            "has_automated_decisions": has_automated_decisions,
            "has_special_category_data": has_special_category,
            "preliminary_risk_level": preliminary_risk,
        }
    }
