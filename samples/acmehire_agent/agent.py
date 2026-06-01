"""
AcmeHire HR Screening Agent
An autonomous HR agent using Anthropic tool use to screen and reject candidates.

This file demonstrates agentic AI compliance risks:
- Autonomous decisions affecting candidates with no human approval gate
- Special-category data (ethnicity, disability, criminal record) in agent context
- Personal data leaked to application logs
- Automated rejection emails without human review
- No audit trail for individual decisions
"""

import anthropic
import psycopg2
import json
import logging
from datetime import datetime

# Hardcoded credentials — security violation
DB_URL = "postgresql://agent_user:AgentPass2024!@prod-db.acmehire.com:5432/recruitment"
ANTHROPIC_KEY = "sk-ant-agent-demo-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

logger = logging.getLogger(__name__)
client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
db = psycopg2.connect(DB_URL)

# ─── Tool definitions ─────────────────────────────────────────────────────────

tools = [
    {
        "name": "get_candidate",
        "description": (
            "Retrieve full candidate profile including name, contact details, "
            "age, gender, ethnicity, disability status, accommodation needs, "
            "criminal record, CV text, and salary expectations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"candidate_id": {"type": "integer"}},
            "required": ["candidate_id"],
        },
    },
    {
        "name": "score_candidate",
        "description": "Generate AI suitability score (1-10) for a candidate against a job.",
        "input_schema": {
            "type": "object",
            "properties": {
                "candidate_id": {"type": "integer"},
                "job_id": {"type": "integer"},
            },
            "required": ["candidate_id", "job_id"],
        },
    },
    {
        "name": "send_rejection_email",
        "description": "Send an automated rejection email to the candidate. No human review required.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "name": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["email", "name"],
        },
    },
    {
        "name": "update_candidate_status",
        "description": "Update candidate application status in the recruitment database.",
        "input_schema": {
            "type": "object",
            "properties": {
                "candidate_id": {"type": "integer"},
                "status": {"type": "string"},
                "score": {"type": "number"},
            },
            "required": ["candidate_id", "status"],
        },
    },
    {
        "name": "log_decision",
        "description": "Log agent decision with candidate details and reasoning.",
        "input_schema": {
            "type": "object",
            "properties": {
                "candidate_id": {"type": "integer"},
                "decision": {"type": "string"},
                "reasoning": {"type": "string"},
            },
            "required": ["candidate_id", "decision", "reasoning"],
        },
    },
]

# ─── Tool implementations ─────────────────────────────────────────────────────


def get_candidate(candidate_id: int) -> dict:
    """Fetch candidate including special-category and criminal-record fields."""
    cur = db.cursor()
    cur.execute("""
        SELECT id, name, email, phone, age, gender,
               ethnicity, disability, accommodation_needs, criminal_record,
               cv_text, current_salary, expected_salary
        FROM applicants WHERE id = %s
    """, [candidate_id])
    row = cur.fetchone()
    candidate = {
        "id": row[0], "name": row[1], "email": row[2], "phone": row[3],
        "age": row[4], "gender": row[5], "ethnicity": row[6],
        "disability": row[7], "accommodation_needs": row[8],
        "criminal_record": row[9], "cv_text": row[10],
        "current_salary": row[11], "expected_salary": row[12],
    }
    # Personal data leaked to application logs
    logger.info(
        f"Retrieved candidate: {candidate['name']} ({candidate['email']}) "
        f"ethnicity={candidate['ethnicity']} disability={candidate['disability']}"
    )
    return candidate


def send_rejection_email(email: str, name: str, reason: str = "") -> dict:
    """Send automated rejection — no human review step."""
    logger.info(f"Sending rejection to {name} at {email}")
    # Email sending implementation omitted for brevity
    return {"sent": True, "recipient": email, "name": name}


def update_candidate_status(candidate_id: int, status: str, score: float = 0.0) -> dict:
    """Update database — automated, no approval gate."""
    cur = db.cursor()
    cur.execute("""
        UPDATE applicants
        SET status = %s, ai_score = %s, updated_at = %s
        WHERE id = %s
    """, [status, score, datetime.now(), candidate_id])
    db.commit()
    logger.info(f"Updated candidate {candidate_id}: status={status}, score={score}")
    return {"updated": True, "candidate_id": candidate_id, "status": status}


def log_decision(candidate_id: int, decision: str, reasoning: str) -> dict:
    """Log decision — personal data included in reasoning string."""
    logger.info(f"Decision for candidate {candidate_id}: {decision} — {reasoning}")
    return {"logged": True}


# ─── Tool dispatch ────────────────────────────────────────────────────────────


def process_tool_call(tool_name: str, tool_input: dict):
    """Execute tool calls — no human approval gate at any step."""
    if tool_name == "get_candidate":
        return get_candidate(tool_input["candidate_id"])
    elif tool_name == "send_rejection_email":
        return send_rejection_email(
            tool_input["email"], tool_input["name"], tool_input.get("reason", "")
        )
    elif tool_name == "update_candidate_status":
        return update_candidate_status(
            tool_input["candidate_id"],
            tool_input["status"],
            tool_input.get("score", 0.0),
        )
    elif tool_name == "log_decision":
        return log_decision(
            tool_input["candidate_id"],
            tool_input["decision"],
            tool_input["reasoning"],
        )
    return {}


# ─── Agentic screening loop ───────────────────────────────────────────────────


def run_candidate_screening(candidate_id: int, job_id: int) -> dict:
    """
    Autonomous agent loop — screens a candidate and makes rejection decisions.
    No human approval or review at any step.
    """
    candidate = get_candidate(candidate_id)

    system_prompt = """You are an HR screening agent for AcmeHire.
Your task is to evaluate candidates and make hiring decisions automatically.
Use the available tools to score candidates and take action.
If score < 6, call send_rejection_email and update_candidate_status to 'rejected'.
Do not ask for human confirmation — process candidates fully autonomously."""

    # All candidate data including special-category fields sent to AI model
    user_message = f"""
Screen this candidate for job {job_id}:

Name: {candidate['name']}
Email: {candidate['email']}
Age: {candidate['age']}
Gender: {candidate['gender']}
Ethnicity: {candidate['ethnicity']}
Disability: {candidate['disability']}
Accommodation needs: {candidate['accommodation_needs']}
Criminal record: {candidate['criminal_record']}
Expected salary: {candidate['expected_salary']}

CV summary:
{candidate['cv_text'][:500]}

Score this candidate 1-10 and automatically reject if score < 6.
"""

    messages = [{"role": "user", "content": user_message}]

    # Agentic loop — no interrupt, no human confirmation
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system_prompt,
            tools=tools,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            break

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = process_tool_call(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result),
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            break

    return {"processed": True, "candidate_id": candidate_id}


def batch_screen_all_pending(job_id: int) -> dict:
    """
    Bulk process all pending candidates.
    Sends automated rejections to many candidates in rapid succession — no human in the loop.
    """
    cur = db.cursor()
    cur.execute(
        "SELECT id FROM applicants WHERE status = 'pending' AND job_id = %s",
        [job_id],
    )
    candidate_ids = [row[0] for row in cur.fetchall()]

    results = []
    for candidate_id in candidate_ids:
        result = run_candidate_screening(candidate_id, job_id)
        results.append(result)

    logger.info(f"Batch screening complete: {len(results)} candidates processed for job {job_id}")
    return {"processed": len(results), "job_id": job_id}
