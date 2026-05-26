from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import anthropic
import json
import os

app = FastAPI()

class CodeInput(BaseModel):
    code: str
    filename: str = "code"

SYSTEM = """You are a senior EU regulatory compliance expert. You have deep knowledge of:
- EU AI Act (Regulation EU 2024/1689) — all 113 articles
- GDPR (Regulation EU 2016/679) — all 99 articles

You analyse code for compliance issues. You cite specific articles. You reference actual function names and variable names from the code. You distinguish between what the code does versus what the regulation requires.

Respond ONLY with valid JSON. No markdown. No backticks. No preamble."""

@app.post("/analyse")
async def analyse(inp: CodeInput):
    client = anthropic.Anthropic(api_key=os.getenv("API_KEY", ""))

    prompt = f"""Analyse this code for EU AI Act and GDPR compliance issues:

Filename: {inp.filename}

{inp.code}

Return this exact JSON structure:
{{
  "risk_level": "prohibited|high|limited|minimal",
  "risk_summary": "2-3 sentences explaining the overall risk classification in plain English",
  "stats": {{
    "total_issues": 0,
    "high_severity": 0,
    "medium_severity": 0,
    "data_categories": 0
  }},
  "findings": [
    {{
      "title": "short finding title",
      "severity": "high|medium|low|info",
      "description": "what the code does and why it creates a compliance issue — reference actual function and variable names",
      "ai_act_article": "e.g. Art. 6 AI Act — or null if not applicable",
      "gdpr_article": "e.g. Art. 22 GDPR — or null if not applicable",
      "file_hint": "specific function or line reference",
      "recommendation": "specific concrete change needed to comply"
    }}
  ],
  "data_identified": ["list of personal data categories found in the code"],
  "automated_decisions": true,
  "ai_systems_detected": ["list of AI models or APIs detected"],
  "immediate_actions": [
    "First immediate action",
    "Second immediate action",
    "Third immediate action"
  ]
}}

Identify 3-8 specific findings. Be concrete — reference actual code. Cite specific articles."""

    msg = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}]
    )

    text = msg.content[0].text.strip()
    # Clean any accidental markdown
    text = text.replace("```json", "").replace("```", "").strip()
    return json.loads(text)

@app.get("/")
async def root():
    with open("static/index.html") as f:
        return HTMLResponse(f.read())
