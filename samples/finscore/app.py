"""
FinScore AI Credit Assessment System
Sample file for Camiro compliance demo.

This code is intentionally non-compliant for demonstration purposes.
"""

import anthropic
import sqlite3
import logging
from datetime import datetime

DB = sqlite3.connect("finscore_prod.db")
logger = logging.getLogger(__name__)

client = anthropic.Anthropic(api_key="sk-ant-finscore-prod-xxxxxxxxxxxx")


def assess_loan_application(application_id: int) -> dict:
    """
    Fully automated loan assessment using AI.
    No human review. Immediate decision.
    """
    cur = DB.cursor()
    cur.execute("""
        SELECT 
            id, name, email, date_of_birth, age, address,
            national_id, income, employment_status, employer,
            medical_history, disability_status,
            criminal_record, bankruptcy_history,
            credit_score, debt_to_income_ratio,
            loan_amount, loan_purpose,
            social_media_score, spending_behaviour
        FROM applications WHERE id = ?
    """, [application_id])

    app = cur.fetchone()

    logger.info(f"Processing application: {app[1]} email={app[2]} national_id={app[6]}")

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=50,
        messages=[{
            "role": "user",
            "content": f"""Assess this loan application. Return APPROVE or DECLINE only.

Applicant: {app[1]}
Age: {app[4]}
Income: {app[7]}
Employment: {app[8]}
Medical history: {app[11]}
Disability: {app[11]}
Criminal record: {app[12]}
Bankruptcy history: {app[13]}
Credit score: {app[14]}
Debt to income: {app[15]}
Loan amount: {app[16]}
Purpose: {app[17]}
Social media score: {app[18]}
Spending behaviour: {app[19]}"""
        }]
    )

    decision = message.content[0].text.strip()

    logger.info(f"Decision for {app[1]}: {decision}")

    # Immediate automated decision - no human review
    cur.execute("""
        INSERT INTO decisions 
        (application_id, decision, model, prompt, response, timestamp, automated)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [
        application_id, decision, "claude-sonnet",
        f"Full prompt with all data",
        decision,
        datetime.now().isoformat(),
        True  # fully automated
    ])
    DB.commit()

    if decision == "DECLINE":
        send_decline_letter(app[1], app[2])
    elif decision == "APPROVE":
        auto_disburse_funds(application_id, app[16])

    return {"application_id": application_id, "decision": decision, "automated": True}


def send_decline_letter(name: str, email: str):
    pass


def auto_disburse_funds(application_id: int, amount: float):
    """Automatically disburse funds with no human check."""
    cur = DB.cursor()
    cur.execute("""
        UPDATE applications SET status = 'funded', funded_at = ? WHERE id = ?
    """, [datetime.now().isoformat(), application_id])
    DB.commit()


def batch_process_queue():
    """Process all pending applications automatically."""
    cur = DB.cursor()
    cur.execute("SELECT id FROM applications WHERE status = 'pending'")
    for (app_id,) in cur.fetchall():
        assess_loan_application(app_id)
