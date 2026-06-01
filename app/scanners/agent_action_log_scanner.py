"""
AgentActionLogScanner — reads agent action logs (JSON Lines or Python log format)
and surfaces compliance signals: PII in model inputs, actions without human approval,
bulk automated decisions, and missing audit trails.
"""
import json
import re
from datetime import datetime, timezone
from typing import Optional
from .base import BaseScanner, ScannerFinding

# ---------------------------------------------------------------------------
# File-type gate
# ---------------------------------------------------------------------------

_LOG_EXTENSIONS = frozenset({'.json', '.jsonl', '.log', '.ndjson'})

# ---------------------------------------------------------------------------
# PII detection in log text
# ---------------------------------------------------------------------------

_PII_FIELD_PATTERNS: list[str] = [
    r'\bemail\s*[=:]\s*\S+@\S+',
    r'\bname\s*[=:]\s*[A-Z][a-z]+\s+[A-Z][a-z]+',
    r'\bphone\s*[=:]\s*[\d\s\+\-\(\)]{7,}',
    r'\bethnicity\s*[=:]',
    r'\bdisability\s*[=:]',
    r'\bcriminal_record\s*[=:]',
    r'\baccommodation_needs\s*[=:]',
    r'\bhealth\s*[=:]',
    r'\bcv_text\s*[=:]',
    r'\bcandidate\s*[=:]\s*\{',
    r'\bapplicant\s*[=:]\s*\{',
    r'name\s*:\s*[A-Z][a-z]',  # "Name: Sarah" in prompt
    r'ethnicity\s*:\s*\w',
    r'disability\s*:\s*\w',
    r'criminal\s+record\s*:\s*\w',
]

_EMAIL_RE = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')

_SPECIAL_CATEGORY_PATTERNS: list[str] = [
    r'\bethnicity\b', r'\bdisability\b', r'\bcriminal_record\b',
    r'\bcriminal record\b', r'\baccommodation_needs\b',
    r'\bmental_health\b', r'\bhealth_data\b', r'\bbiometric\b',
    r'\breligion\b', r'\bpolitical\b', r'\bsexual_orientation\b',
]

# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------

_CONSEQUENTIAL_EVENT_TYPES: frozenset = frozenset({
    'send_email', 'send_rejection_email', 'send_mail', 'send_sms',
    'update_status', 'set_status', 'update_candidate_status',
    'reject_candidate', 'approve_application', 'write_decision',
    'delete_record', 'update_candidate', 'tool_call',
})

_CONSEQUENTIAL_TOOL_NAMES: frozenset = frozenset({
    'send_rejection_email', 'send_email', 'send_mail',
    'update_candidate_status', 'update_status', 'set_rejected',
    'approve_application', 'write_decision', 'reject_candidate',
    'delete_record', 'create_record',
})

_HUMAN_EVENT_TYPES: frozenset = frozenset({
    'human_approval', 'human_review', 'human_feedback',
    'user_confirmation', 'manual_review', 'approval_granted',
    'human_interrupt', 'checkpoint_passed', 'hitl',
})

_MODEL_CALL_TYPES: frozenset = frozenset({
    'model_call', 'llm_call', 'inference', 'completion',
    'chat_completion', 'api_call',
})

# Bulk decision threshold: N decisions within T seconds
_BULK_DECISION_COUNT = 3
_BULK_DECISION_WINDOW_SECONDS = 120

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_pii(text: str) -> bool:
    if not text:
        return False
    if _EMAIL_RE.search(text):
        return True
    return any(re.search(p, text, re.IGNORECASE) for p in _PII_FIELD_PATTERNS)


def _has_special_category(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in _SPECIAL_CATEGORY_PATTERNS)


def _event_text(event: dict) -> str:
    """Flatten event to a searchable string."""
    parts = []
    for key in ('input', 'prompt', 'content', 'message', 'input_preview',
                'result_preview', 'reasoning', 'output', 'text'):
        v = event.get(key)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (dict, list)):
            parts.append(json.dumps(v))
    return ' '.join(parts)


def _parse_timestamp(ts: str) -> Optional[float]:
    """Return unix timestamp or None."""
    if not ts:
        return None
    formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d %H:%M:%S',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def _parse_events(content: str) -> list[dict]:
    """Parse JSON array, JSONL, or return [] if not parseable."""
    content = content.strip()
    if not content:
        return []

    # Try JSON array
    if content.startswith('['):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

    # Try JSONL
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def _is_consequential_event(event: dict) -> bool:
    etype = str(event.get('event_type', event.get('type', ''))).lower()
    tool = str(event.get('tool', event.get('action', ''))).lower()
    if etype in _CONSEQUENTIAL_EVENT_TYPES:
        return True
    if etype == 'tool_call' and tool in _CONSEQUENTIAL_TOOL_NAMES:
        return True
    return False


def _is_model_call(event: dict) -> bool:
    etype = str(event.get('event_type', event.get('type', ''))).lower()
    return etype in _MODEL_CALL_TYPES


def _is_human_event(event: dict) -> bool:
    etype = str(event.get('event_type', event.get('type', ''))).lower()
    return etype in _HUMAN_EVENT_TYPES


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AgentActionLogScanner(BaseScanner):
    """
    Analyses agent action logs for compliance signals:
    PII in model inputs, actions without human approval, bulk automated
    decisions, special-category data exposure, and missing audit trails.
    """
    name = "agent_logs"

    def scan(self, content: str, filename: str = "") -> list[ScannerFinding]:
        # Only activate on log file extensions or detectable JSON log content
        ext = ('.' + filename.rsplit('.', 1)[-1].lower()) if '.' in filename else ''
        if ext not in _LOG_EXTENSIONS and not self._looks_like_log(content):
            return []

        events = _parse_events(content)
        if not events:
            return self._scan_text_log(content, filename)

        return self._scan_structured_log(events, filename, content)

    # -- Structured (JSON) log analysis --

    def _scan_structured_log(self, events: list[dict], filename: str,
                              raw: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        has_human_events = any(_is_human_event(e) for e in events)
        has_consequential = any(_is_consequential_event(e) for e in events)
        pii_model_call_fired = False
        special_cat_fired = False

        for i, event in enumerate(events):
            # PII in model call input
            if not pii_model_call_fired and _is_model_call(event):
                text = _event_text(event)
                if _has_pii(text):
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type='agent_log_pii_in_model_input',
                        title="Model call with personal data in input — no consent/approval event found",
                        description=(
                            "A model API call was detected with what appears to be personal data "
                            "in the input (name, email, or other identifiers). "
                            "GDPR Art. 6 requires a documented lawful basis for this processing. "
                            "Verify whether consent or another basis was obtained before the call."
                        ),
                        confidence=0.85,
                        file_path=filename,
                        line_start=i + 1,
                        evidence_excerpt=self._excerpt(_event_text(event)[:120]),
                        tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                              'GDPR_ART6_LAWFUL_BASIS'],
                        suggested_node_type='evidence_item',
                        metadata={'event_index': i, 'event_type': event.get('event_type', '')},
                    ))
                    pii_model_call_fired = True

            # Special category data in log
            if not special_cat_fired:
                text = _event_text(event) + json.dumps(event)
                if _has_special_category(text):
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type='agent_log_special_category_exposed',
                        title="Special-category data appears in agent log entry",
                        description=(
                            "An agent log entry contains what appears to be special-category "
                            "personal data (ethnicity, disability, criminal record, health data). "
                            "GDPR Art. 9 imposes strict controls on such data. "
                            "Log entries containing Art. 9 data require enhanced security "
                            "and should be minimised or pseudonymised."
                        ),
                        confidence=0.85,
                        file_path=filename,
                        line_start=i + 1,
                        evidence_excerpt=self._excerpt(json.dumps(event)[:150]),
                        tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                              'GDPR_ART9_SPECIAL_CATEGORY', 'critical'],
                        suggested_node_type='evidence_item',
                        metadata={'event_index': i},
                    ))
                    special_cat_fired = True

        # Actions without preceding human approval
        if has_consequential and not has_human_events:
            # Find line of first consequential event
            first_idx = next(
                (i for i, e in enumerate(events) if _is_consequential_event(e)), 0
            )
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='agent_log_action_without_approval',
                title="Rejection or decision action taken without human review event in log",
                description=(
                    "Consequential actions (email, status update, rejection) were found in "
                    "the agent log but no human_approval, human_review, or equivalent event "
                    "was found anywhere in the log. This suggests fully automated operation "
                    "with no human oversight. GDPR Art. 22 requires a human review path "
                    "for automated decisions with legal or significant effects."
                ),
                confidence=0.88,
                file_path=filename,
                line_start=first_idx + 1,
                tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                      'GDPR_ART22_AUTOMATED_DECISIONS', 'AI_ACT_ART14_HUMAN_OVERSIGHT',
                      'critical'],
                suggested_node_type='processing_activity',
                metadata={
                    'has_human_events': False,
                    'consequential_event_count': sum(1 for e in events if _is_consequential_event(e)),
                },
            ))

        # Bulk automated decisions
        bulk_finding = self._check_bulk_decisions(events, filename)
        if bulk_finding:
            findings.append(bulk_finding)

        # No audit trail at all (consequential events, zero human events)
        if has_consequential and not has_human_events and len(events) >= 5:
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='agent_log_no_audit_trail',
                title="No human oversight events in agent log — missing audit trail",
                description=(
                    f"The log contains {len(events)} events with consequential automated actions "
                    f"but zero human oversight events. AI Act Art. 12 requires logging "
                    f"sufficient to enable post-hoc review. An audit trail must include "
                    f"who authorised each significant decision."
                ),
                confidence=0.82,
                file_path=filename,
                tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                      'AI_ACT_ART12_LOGGING', 'GDPR_ART5_PRINCIPLES'],
                suggested_node_type='processing_activity',
                metadata={
                    'total_events': len(events),
                    'human_events': 0,
                    'consequential_events': sum(1 for e in events if _is_consequential_event(e)),
                },
            ))

        return findings

    def _check_bulk_decisions(self, events: list[dict],
                              filename: str) -> Optional[ScannerFinding]:
        """Detect N consequential decisions within T seconds with no human events."""
        timestamped: list[tuple[float, int]] = []
        for i, e in enumerate(events):
            if _is_consequential_event(e):
                ts = _parse_timestamp(str(e.get('timestamp', '')))
                if ts is not None:
                    timestamped.append((ts, i))

        if len(timestamped) < _BULK_DECISION_COUNT:
            return None

        # Sliding window
        for start in range(len(timestamped) - _BULK_DECISION_COUNT + 1):
            window = timestamped[start: start + _BULK_DECISION_COUNT]
            span = window[-1][0] - window[0][0]
            if span <= _BULK_DECISION_WINDOW_SECONDS:
                # Check no human event in that window
                first_idx, last_idx = window[0][1], window[-1][1]
                window_events = events[max(0, first_idx - 1): last_idx + 2]
                if not any(_is_human_event(e) for e in window_events):
                    return ScannerFinding(
                        scanner_name=self.name,
                        finding_type='agent_log_bulk_automated_decisions',
                        title=(
                            f"Bulk automated decisions detected — {_BULK_DECISION_COUNT} "
                            f"actions in {int(span)}s with no human events"
                        ),
                        description=(
                            f"{_BULK_DECISION_COUNT} consequential automated actions occurred "
                            f"within {int(span)} seconds with no human oversight events. "
                            f"Bulk automated decisions affecting individuals require particular "
                            f"scrutiny under GDPR Art. 22 and AI Act Art. 14. "
                            f"Verify whether these actions were individually reviewed."
                        ),
                        confidence=0.88,
                        file_path=filename,
                        line_start=first_idx + 1,
                        tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                              'GDPR_ART22_AUTOMATED_DECISIONS', 'AI_ACT_ART14_HUMAN_OVERSIGHT',
                              'critical'],
                        suggested_node_type='processing_activity',
                        metadata={
                            'decision_count': _BULK_DECISION_COUNT,
                            'window_seconds': int(span),
                        },
                    )
        return None

    # -- Text log fallback --

    def _scan_text_log(self, content: str, filename: str) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []

        if _has_pii(content):
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='agent_log_pii_in_model_input',
                title="Personal data found in log file",
                description=(
                    "The log file appears to contain personal data (names, emails, or other "
                    "identifiers). Log files containing personal data must be secured, have "
                    "defined retention periods, and access controls under GDPR Art. 32."
                ),
                confidence=0.75,
                file_path=filename,
                tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                      'GDPR_ART32_SECURITY'],
                suggested_node_type='evidence_item',
                metadata={},
            ))

        if _has_special_category(content):
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='agent_log_special_category_exposed',
                title="Special-category data detected in log file",
                description=(
                    "The log file appears to contain special-category personal data. "
                    "GDPR Art. 9 requires enhanced protections for such data including "
                    "strict access controls and security measures."
                ),
                confidence=0.75,
                file_path=filename,
                tags=['agent_logs', 'runtime_evidence', 'agentic_ai',
                      'GDPR_ART9_SPECIAL_CATEGORY', 'critical'],
                suggested_node_type='evidence_item',
                metadata={},
            ))

        return findings

    # -- Utility --

    def _looks_like_log(self, content: str) -> bool:
        """Heuristic: does this look like a JSON log even without a matching extension?"""
        stripped = content.strip()
        if stripped.startswith('[') and '"event_type"' in stripped[:200]:
            return True
        first_line = stripped.split('\n', 1)[0].strip()
        if first_line.startswith('{') and '"event_type"' in first_line:
            return True
        return False
