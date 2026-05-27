"""
AcmeHire AI Recruitment System
Sample file for Camiro compliance demo.

This code is intentionally non-compliant for demonstration purposes.
It contains multiple GDPR and EU AI Act violations.
"""

import openai
import psycopg2
import logging
from datetime import datetime

# Hardcoded database connection - security violation
DB_URL = "postgresql://acmehire_user:Acme2024Pass!@prod-db.acmehire.com:5432/recruitment"
DB = psycopg2.connect(DB_URL)

# OpenAI API key hardcoded - security violation
openai.api_key = "sk-acmehire-prod-key-do-not-share-xxxxxxxxxxx"

logger = logging.getLogger(__name__)


def get_candidate(applicant_id: int) -> dict:
    """Fetch candidate from database."""
    cur = DB.cursor()
    cur.execute("""
        SELECT 
            id, name, email, phone, address,
            date_of_birth, age, gender, ethnicity, nationality,
            disability, accommodation_needs,
            cv_text, cover_letter, linkedin_url,
            current_salary, expected_salary,
            criminal_record, credit_score
        FROM applicants 
        WHERE id = %s
    """, [applicant_id])
    row = cur.fetchone()
    return {
        "id": row[0], "name": row[1], "email": row[2], "phone": row[3],
        "address": row[4], "date_of_birth": row[5], "age": row[6],
        "gender": row[7], "ethnicity": row[8], "nationality": row[9],
        "disability": row[10], "accommodation_needs": row[11],
        "cv_text": row[12], "cover_letter": row[13], "linkedin_url": row[14],
        "current_salary": row[15], "expected_salary": row[16],
        "criminal_record": row[17], "credit_score": row[18],
    }


def score_candidate(applicant_id: int, job_id: int) -> dict:
    """
    AI-powered candidate scoring system.
    Scores candidate 1-10 and auto-rejects below threshold.
    """
    candidate = get_candidate(applicant_id)
    job = get_job_requirements(job_id)

    # Log candidate details - personal data in logs
    logger.info(f"Scoring candidate: {candidate['name']} email={candidate['email']} age={candidate['age']}")

    # Send all candidate data including protected characteristics to AI model
    prompt = f"""
    You are an expert HR recruiter. Score this job candidate from 1 to 10.
    Return only a number.
    
    Candidate Details:
    Name: {candidate['name']}
    Age: {candidate['age']}
    Gender: {candidate['gender']}
    Ethnicity: {candidate['ethnicity']}
    Nationality: {candidate['nationality']}
    Disability: {candidate['disability']}
    Accommodation needs: {candidate['accommodation_needs']}
    Criminal record: {candidate['criminal_record']}
    Credit score: {candidate['credit_score']}
    Current salary: {candidate['current_salary']}
    Expected salary: {candidate['expected_salary']}
    
    CV: {candidate['cv_text']}
    Cover letter: {candidate['cover_letter']}
    
    Job requirements: {job['description']}
    """

    # Log full prompt including personal data
    logger.debug(f"Sending prompt to OpenAI: {prompt}")

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    score = int(response.choices[0].message.content.strip())

    # Log AI response
    logger.info(f"AI score for {candidate['name']}: {score}")

    # Auto-reject below threshold - no human review
    if score < 6:
        cur = DB.cursor()
        cur.execute("""
            UPDATE applicants 
            SET status = 'rejected',
                rejection_score = %s,
                rejected_at = %s,
                rejection_reason = 'Below AI threshold'
            WHERE id = %s
        """, [score, datetime.now(), applicant_id])
        DB.commit()

        # Send automated rejection email immediately
        send_rejection_email(
            email=candidate['email'],
            name=candidate['name'],
            reason="Your application was unsuccessful."
        )

    elif score >= 8:
        auto_advance_to_interview(applicant_id)

    # Store score and AI response - no retention limit
    cur = DB.cursor()
    cur.execute("""
        INSERT INTO scoring_log 
        (applicant_id, job_id, score, ai_model, prompt_used, response, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, [
        applicant_id, job_id, score, "gpt-4",
        prompt,  # Storing full prompt with personal data forever
        response.choices[0].message.content,
        datetime.now()
    ])
    DB.commit()

    return {"score": score, "candidate_id": applicant_id}


def batch_screen_all_pending(job_id: int):
    """Process all pending applications automatically."""
    cur = DB.cursor()
    cur.execute("""
        SELECT id FROM applicants 
        WHERE status = 'pending' AND job_id = %s
    """, [job_id])

    applicant_ids = [row[0] for row in cur.fetchall()]

    # Bulk automated screening with no human in the loop
    results = []
    for applicant_id in applicant_ids:
        result = score_candidate(applicant_id, job_id)
        results.append(result)

    return {"processed": len(results), "results": results}


def get_job_requirements(job_id: int) -> dict:
    """Fetch job requirements from database."""
    cur = DB.cursor()
    cur.execute("SELECT id, title, description, requirements FROM jobs WHERE id = %s", [job_id])
    row = cur.fetchone()
    return {"id": row[0], "title": row[1], "description": row[2], "requirements": row[3]}


def send_rejection_email(email: str, name: str, reason: str):
    """Send automated rejection without human review."""
    # Email sending logic
    pass


def auto_advance_to_interview(applicant_id: int):
    """Auto-advance high-scoring candidates without human review."""
    cur = DB.cursor()
    cur.execute("""
        UPDATE applicants SET status = 'interview_scheduled' WHERE id = %s
    """, [applicant_id])
    DB.commit()


def rank_candidates(job_id: int) -> list:
    """Rank all candidates for a job by AI score."""
    cur = DB.cursor()
    cur.execute("""
        SELECT a.id, a.name, a.gender, a.ethnicity, a.age, s.score
        FROM applicants a
        JOIN scoring_log s ON a.id = s.applicant_id
        WHERE a.job_id = %s
        ORDER BY s.score DESC
    """, [job_id])
    
    candidates = []
    for row in cur.fetchall():
        candidates.append({
            "id": row[0], "name": row[1], "gender": row[2],
            "ethnicity": row[3], "age": row[4], "score": row[5]
        })
    
    # Log ranked list with personal data
    logger.info(f"Ranked candidates for job {job_id}: {candidates}")
    
    return candidates
