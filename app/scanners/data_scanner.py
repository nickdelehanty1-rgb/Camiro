import re
from .base import BaseScanner, ScannerFinding

# Phrases that indicate a prohibition/guardrail instruction rather than actual processing.
# Checked within an 80-character window around the special-category term match.
_GUARDRAIL_RE = re.compile(
    r'\b(do\s+not|avoid|prohibited|not\s+use|not\s+rank|not\s+filter|not\s+include|'
    r'exclude|never|must\s+not|should\s+not|don\'t|cannot|refuse|forbidden|'
    r'prevent|disallow|ignore|rather\s+than|instead\s+of|without\s+regard\s+to)\b',
    re.IGNORECASE
)

# Personal data field patterns — variable names, schema columns, JSON keys
PERSONAL_DATA_PATTERNS = {
    "name": [r'\b(full_name|first_name|last_name|surname|forename|given_name|user_name|username)\b'],
    "email": [r'\b(email|email_address|e_mail|mail)\b'],
    "phone": [r'\b(phone|phone_number|mobile|telephone|tel|cell)\b'],
    "address": [r'\b(address|street|postcode|zip_code|city|county|country)\b'],
    "date_of_birth": [r'\b(dob|date_of_birth|birth_date|birthdate|born)\b'],
    "age": [r'\bage\b'],
    "gender": [r'\b(gender|sex)\b'],
    "nationality": [r'\b(nationality|citizenship|country_of_origin)\b'],
    "location": [r'\b(location|latitude|longitude|lat|lng|geo|coordinates|gps)\b'],
    "ip_address": [r'\b(ip_address|ip_addr|ip|remote_addr|x_forwarded_for)\b'],
    "device_id": [r'\b(device_id|device_identifier|udid|imei|mac_address)\b'],
    "cookie_id": [r'\b(cookie_id|cookie|session_id|session_token)\b'],
    "user_id": [r'\b(user_id|userid|account_id|customer_id|client_id|member_id)\b'],
    "payment_data": [r'\b(card_number|credit_card|cvv|iban|bank_account|sort_code|payment_method)\b'],
    "health_data": [r'\b(health|medical|diagnosis|medication|prescription|condition|disability|treatment|clinical)\b'],
    "biometric_data": [r'\b(biometric|fingerprint|face_id|facial|retina|iris_scan|voice_print)\b'],
    "genetic_data": [r'\b(genetic|dna|genome|ancestry)\b'],
    "criminal_data": [r'\b(criminal|offence|conviction|arrest|sentence|prison|caution)\b'],
    "employment_data": [r'\b(cv|resume|candidate|applicant|salary|employment|job_title|employer)\b'],
    "education_data": [r'\b(education|degree|qualification|school|university|grade)\b'],
    "financial_data": [r'\b(income|credit_score|loan|debt|asset|net_worth|tax|financial_history)\b'],
    "children_data": [r'\b(child|minor|age_under|dob.*under|parental_consent)\b'],
    "behavioural_data": [r'\b(behaviour|behavior|activity|tracking|browsing|purchase_history|profile)\b'],
}

# Special category data — GDPR Article 9
SPECIAL_CATEGORY_PATTERNS = {
    "health": [r'\b(health|medical|diagnosis|medication|prescription|condition|disability|treatment|clinical|illness|disease)\b'],
    "ethnicity": [r'\b(ethnicity|ethnic_origin|race|racial)\b'],
    "political_opinion": [r'\b(political|political_opinion|political_view|party_membership)\b'],
    "religion": [r'\b(religion|religious|faith|belief|denomination)\b'],
    "trade_union": [r'\b(union|trade_union|union_membership)\b'],
    "genetic": [r'\b(genetic|dna|genome)\b'],
    "biometric": [r'\b(biometric|fingerprint|face_id|facial_recognition|retina|iris)\b'],
    "sexual_orientation": [r'\b(sexual_orientation|sexuality|lgbtq)\b'],
    "criminal": [r'\b(criminal_record|offence|conviction|arrest_record)\b'],
}


class PersonalDataScanner(BaseScanner):
    name = "personal_data"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        found_categories = set()

        for category, patterns in PERSONAL_DATA_PATTERNS.items():
            for pattern_str in patterns:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                matches = self._find_lines_matching(code, pattern)
                for line_num, line_text in matches:
                    if category not in found_categories:
                        found_categories.add(category)
                        findings.append(ScannerFinding(
                            scanner_name=self.name,
                            finding_type="personal_data_detected",
                            title=f"Personal data category detected: {category.replace('_', ' ').title()}",
                            description=(
                                f"Code contains references to {category.replace('_', ' ')} data. "
                                f"This is personal data under GDPR and requires a lawful basis, "
                                f"transparency notice, and appropriate security measures."
                            ),
                            confidence=0.85,
                            file_path=filename,
                            line_start=line_num,
                            evidence_excerpt=self._excerpt(line_text),
                            tags=["personal_data", "GDPR_ART5", "GDPR_ART6", category],
                            suggested_node_type="data_element",
                            metadata={"data_category": category}
                        ))
                    break

        return findings


class SpecialCategoryScanner(BaseScanner):
    name = "special_category"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        found_categories = set()
        found_guardrails = set()

        for category, patterns in SPECIAL_CATEGORY_PATTERNS.items():
            for pattern_str in patterns:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                matches = self._find_lines_matching(code, pattern)
                for line_num, line_text in matches:
                    # Check guardrail context: is the term in a prohibition/instruction string?
                    m = pattern.search(line_text)
                    match_pos = m.start() if m else 0
                    window_start = max(0, match_pos - 80)
                    window_end = min(len(line_text), match_pos + 80)
                    in_guardrail = bool(_GUARDRAIL_RE.search(line_text[window_start:window_end]))

                    if in_guardrail:
                        # Low-confidence guardrail reference — record but keep scanning
                        # for a genuine processing match later in the file.
                        if category not in found_guardrails:
                            found_guardrails.add(category)
                            findings.append(ScannerFinding(
                                scanner_name=self.name,
                                finding_type="guardrail_reference",
                                title=f"Prompt guardrail references {category.replace('_', ' ')} — not data processing",
                                description=(
                                    f"The term '{category.replace('_', ' ')}' appears in a prohibition or "
                                    f"instruction context (e.g. 'do not use', 'avoid', 'excluded'). "
                                    f"This is likely a prompt guardrail or policy instruction, not "
                                    f"evidence that the system processes {category.replace('_', ' ')} data. "
                                    f"Verify whether actual data of this category is processed elsewhere."
                                ),
                                confidence=0.40,
                                file_path=filename,
                                line_start=line_num,
                                evidence_excerpt=self._excerpt(line_text),
                                tags=["guardrail_reference", "requires_review", category],
                                suggested_node_type="data_element",
                                metadata={"special_category": category, "context": "guardrail"}
                            ))
                        # Do NOT break — continue scanning for non-guardrail matches
                        continue

                    # High-confidence: term in variable, field, query, or assignment context
                    if category not in found_categories:
                        found_categories.add(category)
                        is_criminal = category == "criminal"
                        if is_criminal:
                            title = f"GDPR Article 10 criminal-offence data: {category.replace('_', ' ').title()}"
                            description = (
                                f"Code contains references to {category.replace('_', ' ')} data. "
                                f"Criminal convictions and offence data are governed by GDPR Article 10 "
                                f"(distinct from Art. 9 special categories). Processing is permitted only "
                                f"under official authority or where Union or Member State law authorises it. "
                                f"A DPIA is required before processing."
                            )
                            tags = ["special_category", "GDPR_ART10", "GDPR_ART35", category]
                        else:
                            title = f"GDPR Article 9 special category data: {category.replace('_', ' ').title()}"
                            description = (
                                f"Code contains references to {category.replace('_', ' ')} data — "
                                f"a special category under GDPR Article 9. Processing is prohibited "
                                f"unless a specific exception under Art. 9(2) applies. "
                                f"A DPIA is likely required before processing."
                            )
                            tags = ["special_category", "GDPR_ART9", "GDPR_ART35", category]
                        findings.append(ScannerFinding(
                            scanner_name=self.name,
                            finding_type="special_category_data",
                            title=title,
                            description=description,
                            confidence=0.9,
                            file_path=filename,
                            line_start=line_num,
                            evidence_excerpt=self._excerpt(line_text),
                            tags=tags,
                            suggested_node_type="data_element",
                            metadata={"special_category": category}
                        ))
                    break  # Found a definitive processing match; stop scanning this category

        return findings
