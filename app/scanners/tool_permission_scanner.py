"""
ToolPermissionScanner — maps tool/function names to data categories
and GDPR/AI Act obligations, and flags missing human approval gates.
"""
import re
from .base import BaseScanner, ScannerFinding

# ---------------------------------------------------------------------------
# Tool classification tables
# (pattern, category_label, obligation_label, finding_type, confidence, tags)
# ---------------------------------------------------------------------------

_PERSONAL_DATA_TOOLS: list[tuple] = [
    (r'\bget_candidate\b', 'candidate personal data', 'GDPR Art. 5/6',
     'tool_personal_data_access', 0.85,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART6_LAWFUL_BASIS']),
    (r'\bfetch_user\b', 'user personal data', 'GDPR Art. 5/6',
     'tool_personal_data_access', 0.85,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART6_LAWFUL_BASIS']),
    (r'\bread_profile\b|\bget_profile\b', 'user profile data', 'GDPR Art. 5/6',
     'tool_personal_data_access', 0.85,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART6_LAWFUL_BASIS']),
    (r'\bget_employee\b|\bfetch_employee\b', 'employee personal data', 'GDPR Art. 5/6',
     'tool_personal_data_access', 0.85,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART6_LAWFUL_BASIS']),
    (r'\bquery_candidates\b|\bsearch_applicants\b|\blist_candidates\b', 'candidate dataset', 'GDPR Art. 5/6',
     'tool_personal_data_access', 0.80,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART6_LAWFUL_BASIS']),
    (r'\bget_customer\b|\bfetch_customer\b', 'customer personal data', 'GDPR Art. 5/6',
     'tool_personal_data_access', 0.80,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART6_LAWFUL_BASIS']),
]

_SPECIAL_CATEGORY_TOOLS: list[tuple] = [
    (r'\bget_health\b|\bread_medical\b|\bget_medical\b', 'health data (Art. 9)', 'GDPR Art. 9',
     'tool_special_category_access', 0.90,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART9_SPECIAL_CATEGORY', 'critical']),
    (r'\bfetch_disability\b|\bget_disability\b|\bget_accommodation\b', 'disability data (Art. 9)', 'GDPR Art. 9',
     'tool_special_category_access', 0.90,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART9_SPECIAL_CATEGORY', 'critical']),
    (r'\bget_ethnicity\b|\bfetch_ethnicity\b|\bread_ethnicity\b', 'ethnic origin data (Art. 9)', 'GDPR Art. 9',
     'tool_special_category_access', 0.90,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART9_SPECIAL_CATEGORY', 'critical']),
    (r'\bget_criminal_record\b|\bfetch_criminal\b|\bread_criminal\b', 'criminal record (Art. 10)', 'GDPR Art. 10',
     'tool_special_category_access', 0.90,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART9_SPECIAL_CATEGORY', 'critical']),
    (r'\bread_mental_health\b|\bget_mental_health\b', 'mental health data (Art. 9)', 'GDPR Art. 9',
     'tool_special_category_access', 0.90,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART9_SPECIAL_CATEGORY', 'critical']),
    (r'\bget_biometric\b|\bfetch_biometric\b', 'biometric data (Art. 9)', 'GDPR Art. 9',
     'tool_special_category_access', 0.90,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART9_SPECIAL_CATEGORY', 'critical']),
]

_COMMUNICATION_TOOLS: list[tuple] = [
    (r'\bsend_email\b|\bsend_mail\b', 'automated email action', 'GDPR Art. 22 / AI Act Art. 14',
     'tool_automated_action', 0.85,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART22_AUTOMATED_DECISIONS']),
    (r'\bsend_rejection\b|\bsend_rejection_email\b', 'automated rejection email', 'GDPR Art. 22 / AI Act Art. 14',
     'tool_automated_action', 0.90,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART22_AUTOMATED_DECISIONS', 'critical']),
    (r'\bnotify_candidate\b|\bnotify_applicant\b', 'automated candidate notification', 'GDPR Art. 22',
     'tool_automated_action', 0.85,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART22_AUTOMATED_DECISIONS']),
    (r'\bsend_message\b|\bpost_to_slack\b|\bsend_sms\b', 'automated outbound message', 'GDPR Art. 6',
     'tool_automated_action', 0.80,
     ['tool_permissions', 'agentic_ai', 'automated_action']),
]

_DECISION_WRITE_TOOLS: list[tuple] = [
    (r'\bupdate_status\b|\bset_status\b', 'automated status update', 'GDPR Art. 22 / AI Act Art. 14',
     'tool_automated_decision', 0.85,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART22_AUTOMATED_DECISIONS']),
    (r'\bset_rejected\b|\breject_candidate\b|\bapprove_application\b', 'automated approval/rejection', 'GDPR Art. 22 / AI Act Art. 14',
     'tool_automated_decision', 0.90,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART22_AUTOMATED_DECISIONS', 'critical']),
    (r'\bwrite_decision\b|\brecord_decision\b|\bstore_decision\b', 'automated decision record', 'GDPR Art. 22',
     'tool_automated_decision', 0.85,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART22_AUTOMATED_DECISIONS']),
    (r'\bupdate_candidate\b|\bupdate_applicant\b', 'automated candidate record update', 'GDPR Art. 5',
     'tool_automated_decision', 0.80,
     ['tool_permissions', 'agentic_ai', 'automated_action', 'GDPR_ART5_PRINCIPLES']),
    (r'\bcreate_record\b|\binsert_record\b|\bwrite_record\b', 'automated record creation', 'GDPR Art. 5/6',
     'tool_automated_decision', 0.80,
     ['tool_permissions', 'agentic_ai', 'automated_action']),
]

_EXECUTION_TOOLS: list[tuple] = [
    (r'\bexecute_code\b|\brun_code\b', 'code execution', 'GDPR Art. 32 / Security',
     'tool_code_execution', 0.90,
     ['tool_permissions', 'agentic_ai', 'security', 'GDPR_ART32_SECURITY', 'critical']),
    (r'\brun_query\b|\bexecute_sql\b|\brun_sql\b', 'SQL execution', 'GDPR Art. 5/32',
     'tool_code_execution', 0.85,
     ['tool_permissions', 'agentic_ai', 'security', 'GDPR_ART5_PRINCIPLES']),
    (r'\brun_command\b|\bexecute_shell\b|\bexecute_bash\b', 'shell command execution', 'GDPR Art. 32',
     'tool_code_execution', 0.90,
     ['tool_permissions', 'agentic_ai', 'security', 'GDPR_ART32_SECURITY', 'critical']),
    (r'\bcall_api\b|\bexternal_api_call\b', 'external API call', 'GDPR Art. 28/44',
     'tool_external_api', 0.80,
     ['tool_permissions', 'agentic_ai', 'GDPR_ART28_PROCESSOR']),
]

_ALL_TOOL_GROUPS = (
    _PERSONAL_DATA_TOOLS + _SPECIAL_CATEGORY_TOOLS +
    _COMMUNICATION_TOOLS + _DECISION_WRITE_TOOLS + _EXECUTION_TOOLS
)

# Human approval context window (lines to search around tool definition)
_APPROVAL_WINDOW = 25

_HUMAN_APPROVAL_CONTEXT_PATTERNS: list[str] = [
    r'human_approval', r'requires_approval', r'confirm_before',
    r'\bhitl\b', r'human_in_the_loop', r'user_confirmation',
    r'approval_required', r'manual_review', r'requires_human',
    r'pause_for_review', r'interrupt', r'ask_human', r'checkpoint',
]

_FUNCTION_DEF_PREFIX = re.compile(
    r'(def\s+\w+\s*\(|"name"\s*:\s*"[^"]+"|\'name\'\s*:\s*\'[^\']+\')',
    re.IGNORECASE,
)


def _has_approval_in_context(lines: list[str], line_idx: int, window: int) -> bool:
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window)
    context = '\n'.join(lines[start:end])
    return any(re.search(p, context, re.IGNORECASE) for p in _HUMAN_APPROVAL_CONTEXT_PATTERNS)


class ToolPermissionScanner(BaseScanner):
    """
    Maps tool and function names to implied data categories and
    GDPR/AI Act obligations. Flags missing human approval gates
    around consequential tool calls.
    """
    name = "tool_permissions"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        lines = code.splitlines()
        seen_types: set[str] = set()

        for pattern, category, obligation, finding_type, confidence, tags in _ALL_TOOL_GROUPS:
            if finding_type in seen_types:
                continue

            for m in re.finditer(pattern, code, re.IGNORECASE):
                ln = code[:m.start()].count('\n') + 1
                excerpt = lines[ln - 1].strip() if ln <= len(lines) else m.group()

                has_approval = _has_approval_in_context(lines, ln - 1, _APPROVAL_WINDOW)

                description = self._build_description(
                    m.group(), category, obligation, has_approval, finding_type
                )

                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type=finding_type,
                    title=f"Tool '{m.group()}' — {category}",
                    description=description,
                    confidence=confidence if not has_approval else max(0.5, confidence - 0.15),
                    file_path=filename,
                    function_name=m.group(),
                    line_start=ln,
                    evidence_excerpt=self._excerpt(excerpt),
                    tags=tags,
                    suggested_node_type='processing_activity',
                    metadata={
                        'tool_name': m.group(),
                        'data_category': category,
                        'obligation': obligation,
                        'human_approval_observed': has_approval,
                    },
                ))
                seen_types.add(finding_type)
                break  # one finding per type

        return findings

    def _build_description(self, tool_name: str, category: str, obligation: str,
                           has_approval: bool, finding_type: str) -> str:
        base = (
            f"Tool '{tool_name}' detected. This tool implies access to or action on "
            f"{category}. {obligation} may apply."
        )
        if finding_type in ('tool_automated_action', 'tool_automated_decision'):
            base += (
                " This tool takes an automated action that may have legal or significant "
                "effects on individuals."
            )
        if has_approval:
            base += (
                " A human approval or review mechanism was observed near this tool — "
                "verify it applies before every invocation."
            )
        else:
            base += (
                " No human approval gate was observed near this tool definition. "
                "If invoked autonomously, GDPR Art. 22 and AI Act Art. 14 human "
                "oversight requirements may apply."
            )
        return base
