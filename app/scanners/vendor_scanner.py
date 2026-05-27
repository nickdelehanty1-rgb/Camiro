import re
from .base import BaseScanner, ScannerFinding

# Third-party vendor patterns
VENDOR_PATTERNS = {
    "OpenAI": [r'openai\.com', r'api\.openai\.com', r'import openai', r'from openai'],
    "Anthropic": [r'anthropic\.com', r'api\.anthropic\.com', r'import anthropic', r'from anthropic'],
    "Google": [r'googleapis\.com', r'google\.com/api', r'vertexai', r'generativeai'],
    "Meta/Facebook": [r'graph\.facebook\.com', r'connect\.facebook', r'fbpixel', r'facebook\.net'],
    "Microsoft/Azure": [r'azure\.com', r'microsoft\.com', r'outlook\.com/api', r'graph\.microsoft'],
    "AWS": [r'amazonaws\.com', r'boto3', r'aws_access_key', r'aws_secret'],
    "Stripe": [r'stripe\.com', r'import stripe', r'from stripe', r'stripe\.api_key'],
    "Twilio": [r'twilio\.com', r'from twilio', r'import twilio'],
    "SendGrid": [r'sendgrid\.com', r'from sendgrid', r'import sendgrid'],
    "Mailchimp": [r'mailchimp\.com', r'mailchimpapi'],
    "HubSpot": [r'hubspot\.com', r'hubspot_api'],
    "Salesforce": [r'salesforce\.com', r'simple_salesforce', r'salesforceapi'],
    "Intercom": [r'intercom\.com', r'intercom\.io', r'from intercom'],
    "Zendesk": [r'zendesk\.com', r'from zendesk'],
    "Segment": [r'segment\.com', r'analytics\.track', r'analytics\.identify'],
    "Mixpanel": [r'mixpanel\.com', r'import mixpanel', r'mp\.track'],
    "Amplitude": [r'amplitude\.com', r'from amplitude'],
    "Google Analytics": [r'google-analytics\.com', r'gtag\(', r'ga\(', r'analytics\.js', r'GTM-'],
    "Meta Pixel": [r'connect\.facebook\.net', r'fbq\(', r'facebook_pixel'],
    "Sentry": [r'sentry\.io', r'import sentry_sdk', r'sentry_sdk\.init'],
    "Datadog": [r'datadoghq\.com', r'from datadog', r'import datadog'],
    "Snowflake": [r'snowflake\.com', r'import snowflake', r'snowflake\.connector'],
    "BigQuery": [r'bigquery\.googleapis\.com', r'from google\.cloud import bigquery'],
    "Supabase": [r'supabase\.co', r'from supabase', r'import supabase'],
    "Firebase": [r'firebase\.com', r'firebaseapp\.com', r'import firebase', r'from firebase'],
    "Auth0": [r'auth0\.com', r'from auth0', r'import auth0'],
    "Clerk": [r'clerk\.dev', r'clerk\.com', r'from clerk'],
    "Okta": [r'okta\.com', r'from okta', r'import okta'],
    "Plaid": [r'plaid\.com', r'from plaid', r'import plaid'],
}

# Non-EEA regions / countries that trigger transfer obligations
NON_EEA_PATTERNS = [
    r'us-east-[12]|us-west-[12]|us-central',
    r'region.*us-|us.*region',
    r'amazonaws\.com(?!.*eu)',
    r'northamerica|southamerica|asia|australia',
    r'ap-southeast|ap-northeast|ap-south',
    r'ca-central',
    r'sa-east',
]

# Data storage patterns
STORAGE_PATTERNS = [
    (r'\bdb\.execute\b|\bcur\.execute\b|\bsession\.add\b', "Database write operation"),
    (r'\.save\(\)|\.commit\(\)|\.insert\(|\.create\(', "Database save/insert"),
    (r's3\.put_object|s3\.upload_file|boto3.*s3', "S3 object storage write"),
    (r'open\([^)]+,\s*["\']w|open\([^)]+,\s*["\']a', "File write operation"),
    (r'logging\.|logger\.|log\.', "Logging call"),
    (r'analytics\.track|amplitude\.track|mixpanel\.track', "Analytics event tracking"),
    (r'cache\.set|redis\.set|memcache\.set', "Cache write"),
    (r'kafka\.produce|queue\.send|celery\.send', "Queue/message write"),
]

# Retention and deletion patterns
DELETION_ABSENCE_SIGNALS = [
    r'retain_forever|keep_forever|never_delete|permanent_storage',
    r'archive\s*=\s*True',
    r'deleted_at.*NULL.*permanent',
]

DELETION_PRESENT_SIGNALS = [
    r'delete\(|\.delete\b|DELETE FROM|DROP TABLE',
    r'retention_period|retention_days|expires_at|expiry',
    r'scheduled_deletion|auto_delete|purge',
    r'soft_delete|is_deleted|deleted_at',
]

# Logging of personal data patterns
SENSITIVE_LOG_PATTERNS = [
    (r'(logger|logging|log)\.(info|debug|warning|error).*email', "Email logged"),
    (r'(logger|logging|log)\.(info|debug|warning|error).*password', "Password logged"),
    (r'(logger|logging|log)\.(info|debug|warning|error).*token', "Token logged"),
    (r'(logger|logging|log)\.(info|debug|warning|error).*user_id', "User ID logged"),
    (r'print\(.*email|print\(.*password|print\(.*token', "Sensitive data printed to stdout"),
    (r'(logger|logging|log).*prompt', "AI prompt logged — may contain personal data"),
    (r'(logger|logging|log).*response.*content', "AI response logged — may contain personal data"),
]


class VendorScanner(BaseScanner):
    name = "vendor"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        detected = {}

        for vendor, patterns in VENDOR_PATTERNS.items():
            for pattern_str in patterns:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                matches = self._find_lines_matching(code, pattern)
                if matches and vendor not in detected:
                    line_num, line_text = matches[0]
                    detected[vendor] = True
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type="third_party_vendor",
                        title=f"Third-party vendor detected: {vendor}",
                        description=(
                            f"{vendor} detected in code. If personal data is sent to this vendor, "
                            f"a Data Processing Agreement is required under GDPR Art. 28. "
                            f"If vendor is outside EEA, transfer safeguards required under Art. 44-49."
                        ),
                        confidence=0.9,
                        file_path=filename,
                        line_start=line_num,
                        evidence_excerpt=self._excerpt(line_text),
                        tags=["vendor", "third_party", "GDPR_ART28", "GDPR_ART44"],
                        suggested_node_type="vendor",
                        metadata={"vendor_name": vendor}
                    ))

        # Check for non-EEA transfer signals
        for pattern_str in NON_EEA_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            if matches:
                line_num, line_text = matches[0]
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="non_eea_transfer",
                    title="Possible non-EEA data transfer",
                    description=(
                        "Code references a region or service that may be outside the EEA. "
                        "Transfers of personal data to non-EEA countries require appropriate "
                        "safeguards under GDPR Chapter V (SCCs, adequacy decision, etc.)."
                    ),
                    confidence=0.75,
                    file_path=filename,
                    line_start=line_num,
                    evidence_excerpt=self._excerpt(line_text),
                    tags=["transfer", "non_eea", "GDPR_ART44"],
                    suggested_node_type="third_party_transfer",
                    metadata={}
                ))
                break

        return findings


class DataStorageScanner(BaseScanner):
    name = "data_storage"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        found_types = set()

        for pattern_str, description in STORAGE_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            for line_num, line_text in matches:
                if description not in found_types:
                    found_types.add(description)
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type="data_storage_detected",
                        title=f"Data storage operation: {description}",
                        description=(
                            f"Code contains a {description.lower()}. "
                            f"If personal data is stored, retention schedules and deletion "
                            f"mechanisms are required under GDPR Art. 5(1)(e)."
                        ),
                        confidence=0.8,
                        file_path=filename,
                        line_start=line_num,
                        evidence_excerpt=self._excerpt(line_text),
                        tags=["data_storage", "GDPR_ART5"],
                        suggested_node_type="data_store",
                        metadata={"storage_type": description}
                    ))

        return findings


class RetentionDeletionScanner(BaseScanner):
    name = "retention_deletion"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []

        has_deletion = any(
            re.search(p, code, re.IGNORECASE)
            for p in DELETION_PRESENT_SIGNALS
        )

        has_storage = any(
            re.search(p[0], code, re.IGNORECASE)
            for p in STORAGE_PATTERNS
        )

        # Flag if storage exists but no deletion logic
        if has_storage and not has_deletion:
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type="missing_retention_deletion",
                title="No data retention or deletion mechanism detected",
                description=(
                    "Code stores data but no retention period or deletion mechanism was found. "
                    "GDPR Art. 5(1)(e) (storage limitation) requires personal data to be kept "
                    "no longer than necessary. A retention schedule and deletion process is required."
                ),
                confidence=0.8,
                tags=["retention_missing", "GDPR_ART5"],
                suggested_node_type="retention_policy",
                metadata={"has_storage": True, "has_deletion": False}
            ))

        # Flag explicit permanent retention
        for pattern_str in DELETION_ABSENCE_SIGNALS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            if matches:
                line_num, line_text = matches[0]
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type="permanent_retention_flag",
                    title="Permanent data retention pattern detected",
                    description=(
                        "Code contains a pattern suggesting data is retained permanently. "
                        "GDPR Art. 5(1)(e) prohibits indefinite retention of personal data."
                    ),
                    confidence=0.9,
                    file_path=None,
                    line_start=line_num,
                    evidence_excerpt=self._excerpt(line_text),
                    tags=["permanent_retention", "GDPR_ART5"],
                    suggested_node_type="retention_policy",
                    metadata={}
                ))

        return findings


class LoggingScanner(BaseScanner):
    name = "logging"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        found_types = set()

        for pattern_str, description in SENSITIVE_LOG_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            matches = self._find_lines_matching(code, pattern)
            for line_num, line_text in matches:
                if description not in found_types:
                    found_types.add(description)
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type="sensitive_data_logged",
                        title=f"Sensitive data in logs: {description}",
                        description=(
                            f"Code logs sensitive data: {description.lower()}. "
                            f"Logging personal data creates security and compliance risks. "
                            f"Log files may be accessible to unauthorised parties. "
                            f"GDPR Art. 32 requires appropriate security measures."
                        ),
                        confidence=0.85,
                        file_path=filename,
                        line_start=line_num,
                        evidence_excerpt=self._excerpt(line_text),
                        tags=["logging_risk", "GDPR_ART32", "security"],
                        suggested_node_type="log_sink",
                        metadata={"log_type": description}
                    ))

        return findings
