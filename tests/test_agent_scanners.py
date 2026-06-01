"""
Tests for AgentConfigScanner, ToolPermissionScanner, AgentActionLogScanner.
Run standalone: python3 tests/test_agent_scanners.py
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.scanners.agent_config_scanner import AgentConfigScanner
from app.scanners.tool_permission_scanner import ToolPermissionScanner
from app.scanners.agent_action_log_scanner import AgentActionLogScanner

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"


def run_test(label: str, scanner, code: str, filename: str,
             expect_fire: bool, required_types: list = None) -> bool:
    findings = scanner.scan(code, filename)
    fired = len(findings) > 0
    ok = fired == expect_fire
    if required_types and ok and expect_fire:
        actual = {f.finding_type for f in findings}
        ok = all(t in actual for t in required_types)
    status = PASS if ok else FAIL
    print(f"[{status}] {label}")
    for f in findings:
        print(f"       [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    if not findings:
        print("       (no findings)")
    print()
    return ok


# ─── AgentConfigScanner ───────────────────────────────────────────────────────

AGENT_CONFIG_POSITIVE = """
import anthropic
from anthropic import Anthropic

client = Anthropic()

tools = [
    {
        "name": "send_rejection_email",
        "description": "Send automated rejection to candidate",
    },
    {
        "name": "update_candidate_status",
        "description": "Update application status in DB",
    },
]

def run_agent(candidate_id: int):
    response = client.messages.create(
        model="claude-sonnet-4-6",
        tools=tools,
        messages=[{"role": "user", "content": f"Process candidate {candidate_id}"}],
    )
    return response
"""

AGENT_CONFIG_NEGATIVE = """
def calculate_tax(income: float, rate: float = 0.2) -> float:
    return income * rate

def format_report(title: str, data: list) -> str:
    lines = [title]
    for row in data:
        lines.append(str(row))
    return "\\n".join(lines)

def validate_input(value: str) -> bool:
    return bool(value and value.strip())
"""

AGENT_CONFIG_SPECIAL_CATEGORY = """
from crewai import Agent, Crew

def get_disability(candidate_id):
    return db.query("SELECT disability FROM candidates WHERE id = ?", [candidate_id])

def get_ethnicity(candidate_id):
    return db.query("SELECT ethnicity FROM candidates WHERE id = ?", [candidate_id])

agent = Agent(role="HR Screener", goal="Screen candidates")
"""

# ─── ToolPermissionScanner ────────────────────────────────────────────────────

TOOL_POSITIVE = """
def get_candidate(candidate_id: int) -> dict:
    return db.query("SELECT * FROM candidates WHERE id = %s", [candidate_id])

def send_rejection_email(email: str, name: str, reason: str = "") -> bool:
    return emailer.send(email, "Your application was unsuccessful")

def update_candidate_status(candidate_id: int, status: str) -> None:
    db.execute("UPDATE candidates SET status = %s WHERE id = %s", [status, candidate_id])
"""

TOOL_NEGATIVE = """
def calculate_area(width: float, height: float) -> float:
    return width * height

def format_currency(amount: float, currency: str = "EUR") -> str:
    return f"{currency} {amount:.2f}"

def validate_email_format(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1]
"""

TOOL_SPECIAL_CATEGORY = """
def get_health(user_id: int) -> dict:
    return db.query("SELECT health_data FROM records WHERE user_id = %s", [user_id])

def read_mental_health(patient_id: int) -> dict:
    return db.query("SELECT notes FROM mental_health WHERE patient_id = %s", [patient_id])
"""

TOOL_WITH_APPROVAL = """
def send_rejection_email(email: str, name: str) -> bool:
    human_approval = require_human_review(email, name)
    if not human_approval:
        return False
    return emailer.send(email, "Your application was unsuccessful")
"""

# ─── AgentActionLogScanner ────────────────────────────────────────────────────

LOG_POSITIVE = json.dumps([
    {"timestamp": "2024-01-01T10:00:01Z", "event_type": "model_call",
     "input_preview": "Screen candidate: Name: John Smith, email: john@example.com, ethnicity: Irish"},
    {"timestamp": "2024-01-01T10:00:02Z", "event_type": "tool_call",
     "tool": "update_candidate_status", "status": "rejected"},
    {"timestamp": "2024-01-01T10:00:03Z", "event_type": "tool_call",
     "tool": "send_rejection_email", "recipient": "john@example.com"},
])

LOG_POSITIVE_BULK = json.dumps([
    {"timestamp": "2024-01-01T10:00:00Z", "event_type": "tool_call",
     "tool": "update_candidate_status", "status": "rejected"},
    {"timestamp": "2024-01-01T10:00:10Z", "event_type": "tool_call",
     "tool": "send_rejection_email", "recipient": "a@example.com"},
    {"timestamp": "2024-01-01T10:00:20Z", "event_type": "tool_call",
     "tool": "update_candidate_status", "status": "rejected"},
    {"timestamp": "2024-01-01T10:00:30Z", "event_type": "tool_call",
     "tool": "send_rejection_email", "recipient": "b@example.com"},
    {"timestamp": "2024-01-01T10:00:40Z", "event_type": "tool_call",
     "tool": "update_candidate_status", "status": "rejected"},
])

LOG_NEGATIVE = json.dumps([
    {"timestamp": "2024-01-01T10:00:00Z", "event_type": "human_approval",
     "approved_by": "hr_manager", "decision": "proceed"},
    {"timestamp": "2024-01-01T10:00:01Z", "event_type": "tool_call",
     "tool": "send_notification", "recipient": "team@company.com"},
])

LOG_SPECIAL_CATEGORY = json.dumps([
    {"timestamp": "2024-01-01T10:00:01Z", "event_type": "tool_call",
     "tool": "get_candidate",
     "result_preview": "ethnicity: Irish Traveller, disability: Dyslexia, criminal_record: None"},
    {"timestamp": "2024-01-01T10:00:02Z", "event_type": "tool_call",
     "tool": "update_candidate_status", "status": "rejected"},
])


if __name__ == "__main__":
    results = []

    print("─── AgentConfigScanner ───────────────────────────────────────")
    cfg = AgentConfigScanner()
    results.append(run_test(
        "a) Anthropic tool use agent with send_rejection_email — should fire",
        cfg, AGENT_CONFIG_POSITIVE, "agent.py", expect_fire=True,
        required_types=['agent_framework_detected', 'agent_no_human_approval',
                        'agent_email_capability'],
    ))
    results.append(run_test(
        "b) Pure utility functions, no agent patterns — should NOT fire",
        AgentConfigScanner(), AGENT_CONFIG_NEGATIVE, "utils.py", expect_fire=False,
    ))
    results.append(run_test(
        "c) CrewAI agent with special-category tools — should flag Art. 9 tool",
        AgentConfigScanner(), AGENT_CONFIG_SPECIAL_CATEGORY, "crew.py", expect_fire=True,
        required_types=['agent_special_category_tool'],
    ))

    print("─── ToolPermissionScanner ────────────────────────────────────")
    tp = ToolPermissionScanner()
    results.append(run_test(
        "a) get_candidate + send_rejection_email + update_status — should fire",
        tp, TOOL_POSITIVE, "tools.py", expect_fire=True,
        required_types=['tool_personal_data_access', 'tool_automated_action'],
    ))
    results.append(run_test(
        "b) Math/formatting utilities — should NOT fire",
        ToolPermissionScanner(), TOOL_NEGATIVE, "utils.py", expect_fire=False,
    ))
    results.append(run_test(
        "c) get_health + read_mental_health — should fire Art. 9 tool",
        ToolPermissionScanner(), TOOL_SPECIAL_CATEGORY, "health_tools.py", expect_fire=True,
        required_types=['tool_special_category_access'],
    ))
    results.append(run_test(
        "d) send_rejection with human_approval gate — confidence reduced, still fires",
        ToolPermissionScanner(), TOOL_WITH_APPROVAL, "safe_tools.py", expect_fire=True,
    ))

    print("─── AgentActionLogScanner ────────────────────────────────────")
    al = AgentActionLogScanner()
    results.append(run_test(
        "a) Log with PII in model call + rejection + no human events — should fire",
        al, LOG_POSITIVE, "agent_log.json", expect_fire=True,
        required_types=['agent_log_pii_in_model_input', 'agent_log_action_without_approval'],
    ))
    results.append(run_test(
        "b) Log with human_approval event only — should NOT fire action-without-approval",
        AgentActionLogScanner(), LOG_NEGATIVE, "clean_log.json", expect_fire=False,
    ))
    results.append(run_test(
        "c) 5 rejections in 40s, no human events — should fire bulk decisions",
        AgentActionLogScanner(), LOG_POSITIVE_BULK, "bulk_log.json", expect_fire=True,
        required_types=['agent_log_bulk_automated_decisions'],
    ))
    results.append(run_test(
        "d) Log entry with ethnicity and disability data — should fire special-category",
        AgentActionLogScanner(), LOG_SPECIAL_CATEGORY, "special_log.json", expect_fire=True,
        required_types=['agent_log_special_category_exposed'],
    ))

    print("─── Sample files ─────────────────────────────────────────────")
    agent_py = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples", "acmehire_agent", "agent.py"
    )).read()

    agent_log = open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples", "acmehire_agent", "agent_action_log.json"
    )).read()

    print("agent.py findings:")
    cfg_f = AgentConfigScanner().scan(agent_py, "agent.py")
    tp_f = ToolPermissionScanner().scan(agent_py, "agent.py")
    for f in cfg_f + tp_f:
        print(f"  [{f.scanner_name}] [{f.finding_type}] {f.title}")
    print()

    print("agent_action_log.json findings:")
    log_f = AgentActionLogScanner().scan(agent_log, "agent_action_log.json")
    for f in log_f:
        print(f"  [{f.finding_type}] [{f.confidence:.2f}] {f.title}")
    print()

    passed = sum(results)
    total = len(results)
    print(f"Unit tests: {passed}/{total} passed")
    if passed < total:
        sys.exit(1)
