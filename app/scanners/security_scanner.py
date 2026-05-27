import re
from .base import BaseScanner, ScannerFinding

# Cookie and tracking patterns
TRACKING_PATTERNS = [
    (r'document\.cookie', "Cookie read/write in JavaScript"),
    (r'localStorage\.|sessionStorage\.', "Browser storage (localStorage/sessionStorage)"),
    (r'gtag\(|ga\(|google-analytics', "Google Analytics"),
    (r'fbq\(|facebook\.net/en_US/fbevents', "Meta/Facebook Pixel"),
    (r'analytics\.track|analytics\.identify|analytics\.page', "Analytics tracking call"),
    (r'mixpanel\.track|mixpanel\.identify', "Mixpanel tracking"),
    (r'amplitude\.track|amplitude\.identify', "Amplitude tracking"),
    (r'intercom\(|Intercom\(', "Intercom tracking"),
    (r'Set-Cookie|response\.set_cookie|resp\.set_cookie', "Cookie being set server-side"),
    (r'HttpOnly|SameSite|Secure.*cookie', "Cookie security attribute"),
    (r'consent.*cookie|cookie.*consent', "Cookie consent reference"),
    (r'tracking.*before.*consent|consent.*before.*track', "Tracking before consent check"),
]

# Security control patterns
SECURITY_PRESENT = [
    (r'@require_auth|@login_required|@authenticate|requires_auth', "Authentication decorator"),
    (r'jwt\.|JWT\.|jsonwebtoken', "JWT authentication"),
    (r'bcrypt\.|hashlib\.|werkzeug\.security', "Password hashing"),
    (r'encrypt\(|AES\.|RSA\.|fernet', "Encryption"),
    (r'rbac|role_required|permission_required|has_permission', "Role-based access control"),
    (r'rate_limit|RateLimit|throttle', "Rate limiting"),
    (r'validate_input|sanitize|escape\(|bleach\.', "Input validation/sanitisation"),
    (r'audit_log|audit\.log|write_audit', "Audit logging"),
    (r'mfa|two_factor|totp|2fa', "Multi-factor authentication"),
]

SECURITY_MISSING_SIGNALS = [
    (r'@app\.route.*methods.*POST.*(?!.*auth)', "POST endpoint may lack authentication"),
    (r'def\s+\w+(admin|delete|update|create)\w*\s*\((?!.*auth)', "Admin/sensitive function may lack auth"),
]


class CookieTrackingScanner(BaseScanner):
    name = "cookie_tracking"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        found_types = set()

        for pattern_str, description in TRACKING_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            for line_num, line_text in matches:
                if description not in found_types:
                    found_types.add(description)

                    is_consent_related = "consent" in description.lower()
                    severity_tags = ["eprivacy", "GDPR_ART6"] if not is_consent_related else ["consent_mechanism"]

                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type="cookie_tracking_detected",
                        title=f"Tracking/cookie pattern: {description}",
                        description=(
                            f"Code contains: {description.lower()}. "
                            f"Under the Irish ePrivacy Regulations and GDPR, non-essential cookies "
                            f"and tracking require prior informed consent. "
                            f"Consent must be obtained before tracking code fires."
                        ),
                        confidence=0.85,
                        file_path=filename,
                        line_start=line_num,
                        evidence_excerpt=self._excerpt(line_text),
                        tags=severity_tags,
                        suggested_node_type="processing_activity",
                        metadata={"tracking_type": description}
                    ))

        # Check if tracking exists without consent check
        has_tracking = any(
            re.search(p, code, re.IGNORECASE)
            for p, _ in TRACKING_PATTERNS
            if "consent" not in p.lower()
        )
        has_consent_check = bool(re.search(r'consent|cookie_consent|opt_in|hasConsent', code, re.IGNORECASE))

        if has_tracking and not has_consent_check:
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type="tracking_without_consent",
                title="Tracking detected without consent mechanism",
                description=(
                    "Code contains tracking or analytics calls but no consent check was found. "
                    "Irish ePrivacy Regulations (S.I. 336/2011) and GDPR require consent before "
                    "non-essential cookies or tracking technologies fire."
                ),
                confidence=0.75,
                tags=["tracking_no_consent", "eprivacy", "GDPR_ART6", "GDPR_ART7"],
                suggested_node_type="processing_activity",
                metadata={"consent_missing": True}
            ))

        return findings


class SecurityControlScanner(BaseScanner):
    name = "security_controls"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        controls_found = []

        for pattern_str, description in SECURITY_PRESENT:
            if re.search(pattern_str, code, re.IGNORECASE):
                controls_found.append(description)

        # If no auth found at all — flag it
        has_auth = any(
            re.search(p, code, re.IGNORECASE)
            for p, _ in SECURITY_PRESENT[:4]
        )

        has_endpoints = bool(re.search(
            r'@app\.route|@router\.|app\.post|app\.get|app\.put|app\.delete|def\s+\w+\(request',
            code, re.IGNORECASE
        ))

        if has_endpoints and not has_auth:
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type="missing_authentication",
                title="No authentication mechanism detected",
                description=(
                    "Code defines API endpoints or routes but no authentication mechanism "
                    "was detected. Unauthenticated endpoints processing personal data violate "
                    "GDPR Art. 32 (security of processing)."
                ),
                confidence=0.7,
                tags=["auth_missing", "GDPR_ART32", "security"],
                suggested_node_type="security_measure",
                metadata={"controls_found": controls_found}
            ))

        # Check for hardcoded credentials separate from secret scanner
        if re.search(r'password\s*=\s*["\'][^"\']{4,}["\']', code, re.IGNORECASE):
            line_num = self._find_line(code, "password")
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type="hardcoded_credential",
                title="Hardcoded credential detected",
                description=(
                    "A hardcoded credential or password was found in the code. "
                    "Credentials must be stored in environment variables or a secrets manager. "
                    "Hardcoded credentials create serious security risk under GDPR Art. 32."
                ),
                confidence=0.85,
                file_path=None,
                line_start=line_num,
                tags=["hardcoded_credential", "GDPR_ART32", "security"],
                suggested_node_type="security_measure",
                metadata={}
            ))

        return findings
