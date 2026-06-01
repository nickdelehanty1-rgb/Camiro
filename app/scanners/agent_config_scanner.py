"""
AgentConfigScanner — builds an inventory of AI agent capabilities
and flags missing governance controls.

Detects agent frameworks, tools, connected systems, and whether
human oversight / approval gates are present.
"""
import re
from typing import Optional
from .base import BaseScanner, ScannerFinding

# ---------------------------------------------------------------------------
# Framework detection patterns
# ---------------------------------------------------------------------------

_FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "LangGraph": [
        r'from langgraph', r'import langgraph',
        r'StateGraph\s*\(', r'CompiledGraph', r'langgraph\.graph',
    ],
    "LangChain Agents": [
        r'AgentExecutor', r'create_react_agent',
        r'create_openai_tools_agent', r'initialize_agent',
        r'from langchain.*agent',
    ],
    "CrewAI": [
        r'from crewai\b', r'import crewai\b',
        r'Crew\s*\(', r'CrewBase', r'@agent\b',
    ],
    "AutoGen": [
        r'from autogen\b', r'import autogen\b',
        r'AssistantAgent\s*\(', r'UserProxyAgent\s*\(',
        r'GroupChat\s*\(',
    ],
    "OpenAI Assistants": [
        r'openai\.beta\.assistants',
        r'client\.beta\.assistants',
        r'beta\.threads',
        r'threads\.runs',
    ],
    "Anthropic Tool Use": [
        r'tools\s*=\s*\[',
        r'"type"\s*:\s*"tool_use"',
        r'ToolUseBlock',
        r'tool_choice\s*=',
        r'stop_reason.*tool_use',
    ],
    "MCP": [
        r'from mcp\b', r'import mcp\b',
        r'"mcp_servers"', r'ModelContextProtocol',
        r'mcp_config', r'\.mcp\.json',
    ],
    "Generic Agent": [
        r'agent\.yaml', r'tools\.json',
        r'ToolDef\s*\(', r'@tool\b',
        r'BaseTool\b', r'class.*Tool\s*\(',
    ],
}

# ---------------------------------------------------------------------------
# Human oversight / approval gate patterns
# ---------------------------------------------------------------------------

_HUMAN_APPROVAL_PATTERNS: list[str] = [
    r'human_approval', r'requires_approval', r'confirm_before',
    r'\bhitl\b', r'human_in_the_loop', r'user_confirmation',
    r'human_review\s*=\s*True', r'approval_required',
    r'manual_review', r'requires_human', r'pause_for_review',
    r'interrupt_before', r'ask_human', r'human_feedback',
    r'needs_human', r'await_approval', r'checkpoint',
]

# ---------------------------------------------------------------------------
# Consequential tool patterns (actions that affect individuals)
# ---------------------------------------------------------------------------

_CONSEQUENTIAL_TOOL_PATTERNS: list[str] = [
    # email / comms — allow longer names like send_rejection_email
    r'send_email', r'send_rejection', r'send_mail', r'send_sms',
    r'notify_candidate', r'send_message', r'post_to_slack',
    # decisions / writes
    r'update_status', r'set_status', r'approve_application',
    r'reject_application', r'update_candidate', r'write_decision',
    r'execute_sql', r'run_command', r'delete_record', r'create_record',
]

# ---------------------------------------------------------------------------
# Capability-level findings
# (capability_name, confidence, patterns, extra_tags, finding_type)
# ---------------------------------------------------------------------------

_CAPABILITY_CHECKS: list[tuple] = [
    (
        'email / communication send', 0.85,
        [r'send_email', r'send_rejection', r'send_mail', r'send_sms',
         r'notify.*candidate', r'post_to_slack', r'send_message'],
        ['GDPR_ART22_AUTOMATED_DECISIONS'],
        'agent_email_capability',
        (
            "The agent has a tool or function for sending email or other communications. "
            "Automated communications affecting individuals (e.g. rejection emails) "
            "may constitute automated decisions under GDPR Art. 22 and require "
            "human oversight under AI Act Art. 14."
        ),
    ),
    (
        'code / shell execution', 0.90,
        [r'execute_code\b', r'run_command\b', r'execute_shell\b',
         r'run_script\b', r'subprocess\.', r'\bexec\s*\('],
        ['security'],
        'agent_code_execution',
        (
            "The agent has code or shell execution capability. "
            "Autonomous code execution without human oversight creates significant "
            "security and accountability risks under GDPR Art. 32 and AI Act Art. 14."
        ),
    ),
    (
        'file system write', 0.80,
        [r'write_file\b', r'delete_file\b', r'create_file\b',
         r'file_write\b', r'open\s*\([^)]*["\']w["\']'],
        [],
        'agent_filesystem_access',
        (
            "The agent has file system write capability. "
            "Agents that can create or delete files containing personal data "
            "require audit trails and access controls under GDPR Art. 32."
        ),
    ),
    (
        'database write', 0.80,
        [r'update_status', r'update_candidate_status', r'insert_record',
         r'db_write', r'execute_sql', r'run_query', r'write_database'],
        ['GDPR_ART5_PRINCIPLES'],
        'agent_db_write_capability',
        (
            "The agent has database write capability. "
            "Autonomous database modifications to personal data records require "
            "a documented lawful basis (GDPR Art. 6) and audit trail."
        ),
    ),
    (
        'external API call', 0.75,
        [r'call_api\b', r'http_request\b', r'requests\.post\b',
         r'httpx\.post\b', r'external_api\b'],
        ['GDPR_ART28_PROCESSOR'],
        'agent_external_api_capability',
        (
            "The agent makes external API calls. If personal data is included "
            "in these calls, a Data Processing Agreement may be required "
            "under GDPR Art. 28 and transfer safeguards under Art. 44-49."
        ),
    ),
]

_SPECIAL_CATEGORY_TOOL_PATTERNS: list[str] = [
    r'get_health\b', r'read_medical\b', r'fetch_disability\b',
    r'get_accommodation\b', r'get_ethnicity\b', r'get_criminal_record\b',
    r'read_mental_health\b', r'fetch_biometric\b', r'get_genetic\b',
    r'read_religion\b', r'get_political\b',
]


def _line_of_match(code: str, match: re.Match) -> int:
    return code[:match.start()].count('\n') + 1


class AgentConfigScanner(BaseScanner):
    """
    Detects AI agent frameworks and flags agentic capabilities
    that may trigger GDPR Art. 22 / AI Act Art. 14 obligations.
    """
    name = "agent_config"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        # Only activate when agent patterns are present
        detected_frameworks = self._detect_frameworks(code)
        if not detected_frameworks:
            return []

        findings: list[ScannerFinding] = []

        # 1. Log each detected framework
        for fw in detected_frameworks:
            p = _FRAMEWORK_PATTERNS[fw][0]
            m = re.search(p, code, re.IGNORECASE)
            line_num = _line_of_match(code, m) if m else None
            excerpt = code.splitlines()[line_num - 1].strip() if line_num else fw
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='agent_framework_detected',
                title=f"AI agent framework detected: {fw}",
                description=(
                    f"Code uses {fw} — an agentic AI framework that enables autonomous "
                    f"tool use and multi-step decision making. If this agent processes "
                    f"personal data or takes consequential actions, GDPR Art. 22 and "
                    f"AI Act Art. 14 human oversight obligations may apply."
                ),
                confidence=0.90,
                file_path=filename,
                line_start=line_num,
                evidence_excerpt=self._excerpt(excerpt),
                tags=['agentic_ai', 'agent_config', 'AI_ACT_ART14_HUMAN_OVERSIGHT'],
                suggested_node_type='ai_system',
                metadata={'framework': fw},
            ))

        # 2. Human approval gate check
        has_human_approval = any(
            re.search(p, code, re.IGNORECASE) for p in _HUMAN_APPROVAL_PATTERNS
        )
        has_consequential = any(
            re.search(p, code, re.IGNORECASE) for p in _CONSEQUENTIAL_TOOL_PATTERNS
        )

        if has_consequential and not has_human_approval:
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='agent_no_human_approval',
                title="Agent with consequential tools has no human approval gate",
                description=(
                    "This agent can take consequential actions (send emails, update records, "
                    "make decisions) but no human approval or review mechanism was detected. "
                    "AI Act Art. 14 requires that high-risk AI systems be designed with "
                    "human oversight. GDPR Art. 22 requires a human review path for automated "
                    "decisions with legal or similarly significant effects on individuals."
                ),
                confidence=0.85,
                file_path=filename,
                tags=['agentic_ai', 'agent_config', 'AI_ACT_ART14_HUMAN_OVERSIGHT',
                      'GDPR_ART22_AUTOMATED_DECISIONS', 'critical'],
                suggested_node_type='processing_activity',
                metadata={
                    'has_human_approval': False,
                    'frameworks': detected_frameworks,
                },
            ))

        # 3. Per-capability findings
        for cap_name, confidence, patterns, extra_tags, finding_type, description in _CAPABILITY_CHECKS:
            for p in patterns:
                m = re.search(p, code, re.IGNORECASE)
                if m:
                    ln = _line_of_match(code, m)
                    findings.append(ScannerFinding(
                        scanner_name=self.name,
                        finding_type=finding_type,
                        title=f"Agent has {cap_name} capability",
                        description=description,
                        confidence=confidence,
                        file_path=filename,
                        line_start=ln,
                        evidence_excerpt=self._excerpt(code.splitlines()[ln - 1]),
                        tags=['agentic_ai', 'agent_config', 'tool_permissions'] + extra_tags,
                        suggested_node_type='processing_activity',
                        metadata={'capability': cap_name},
                    ))
                    break

        # 4. Special-category data tools
        for p in _SPECIAL_CATEGORY_TOOL_PATTERNS:
            m = re.search(p, code, re.IGNORECASE)
            if m:
                ln = _line_of_match(code, m)
                findings.append(ScannerFinding(
                    scanner_name=self.name,
                    finding_type='agent_special_category_tool',
                    title="Agent tool accessing special-category data detected",
                    description=(
                        f"A tool or function '{m.group()}' suggests the agent can access "
                        f"special-category personal data (GDPR Art. 9: health, ethnicity, "
                        f"disability, criminal record, etc.). Agents accessing such data "
                        f"require an explicit Art. 9(2) basis, a DPIA, and enhanced security."
                    ),
                    confidence=0.85,
                    file_path=filename,
                    line_start=ln,
                    evidence_excerpt=self._excerpt(code.splitlines()[ln - 1]),
                    tags=['agentic_ai', 'agent_config', 'special_category',
                          'GDPR_ART9_SPECIAL_CATEGORY', 'GDPR_ART35_DPIA', 'critical'],
                    suggested_node_type='data_element',
                    metadata={'tool_pattern': m.group()},
                ))
                break

        return findings

    def _detect_frameworks(self, code: str) -> list[str]:
        detected = []
        for fw, patterns in _FRAMEWORK_PATTERNS.items():
            if any(re.search(p, code, re.IGNORECASE) for p in patterns):
                detected.append(fw)
        return detected
