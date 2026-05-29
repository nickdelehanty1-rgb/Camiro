import re
from .base import BaseScanner, ScannerFinding


# Patterns that identify secrets
SECRET_PATTERNS = [
    (r'sk-ant-[a-zA-Z0-9\-_]{20,}', "Anthropic API key"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'[a-z0-9]{32}-us[0-9]{1,2}', "Mailchimp API key"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe live public key"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe live secret key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', "Slack Bot Token"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private key"),
    (r'(password\s*=\s*)["\'][^"\']{6,}["\']', "Hardcoded password"),
    (r'(passwd\s*=\s*)["\'][^"\']{6,}["\']', "Hardcoded password"),
    (r'(secret\s*=\s*)["\'][^"\']{6,}["\']', "Hardcoded secret"),
    (r'postgresql://[^:]+:[^@]+@', "Database connection string with credentials"),
    (r'mysql://[^:]+:[^@]+@', "Database connection string with credentials"),
    (r'mongodb(\+srv)?://[^:]+:[^@]+@', "MongoDB connection string with credentials"),
    (r'redis://:[^@]+@', "Redis connection string with credentials"),
    (r'Authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*', "Bearer token"),
    (r'(api_key\s*=\s*)["\'][a-zA-Z0-9\-_]{16,}["\']', "Hardcoded API key"),
    (r'(token\s*=\s*)["\'][a-zA-Z0-9\-_]{16,}["\']', "Hardcoded token"),
]

REDACTION_PLACEHOLDER = "[REDACTED]"


def redact_secrets(code: str) -> tuple[str, list[str]]:
    """Redact secrets from code before sending to LLM. Returns (redacted_code, list_of_findings)."""
    redacted = code
    found = []
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, redacted, re.IGNORECASE)
        if matches:
            found.append(label)
            # Patterns with a capture group preserve the key name (e.g. api_key = [REDACTED])
            # so downstream AST parsers don't see broken attribute chains like `obj.[REDACTED]`.
            replacement = (r'\1' + REDACTION_PLACEHOLDER) if '(' in pattern else REDACTION_PLACEHOLDER
            redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
    return redacted, found


class SecretRedactionScanner(BaseScanner):
    name = "secret_redaction"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        for pattern_str, label in SECRET_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            for line_num, line_text in matches:
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="secret_exposed",
                    title=f"Potential secret in code: {label}",
                    description=(
                        f"A potential {label} was detected in the code. "
                        f"Secrets should never appear in source code. "
                        f"Use environment variables or a secrets manager."
                    ),
                    confidence=0.9,
                    file_path=filename,
                    line_start=line_num,
                    evidence_excerpt=self._redact_line(line_text),
                    tags=["secret", "security", "GDPR_ART32"],
                    suggested_node_type="security_measure",
                    metadata={"secret_type": label}
                ))
        return findings

    def _redact_line(self, line: str) -> str:
        redacted, _ = redact_secrets(line)
        return redacted
