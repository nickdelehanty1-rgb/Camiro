# Camiro — EU Regulatory Intelligence Platform

> **Camiro provides technical compliance decision support. It is not legal advice and does not replace review by qualified legal, privacy, security or regulatory professionals.**

---

## What Camiro Does

Camiro is the technical evidence layer for EU AI Act and GDPR compliance.

Instead of asking a DPO to describe their AI system in English, you upload the actual code. Camiro reads it — running deterministic scanners first, then grounding LLM analysis in retrieved legal obligations — and returns a structured compliance report with every finding cited to a specific article.

**Compliance by code, not questionnaire.**

### What Camiro is not

- Not a checklist tool
- Not a legal compliance certificate
- Not a replacement for a lawyer, DPO or qualified privacy professional
- Not a guarantee of compliance

### What Camiro produces

- Risk classification (prohibited / high / limited / minimal)
- Specific findings with article citations
- Evidence items linked to file and line references
- An evidence graph connecting code, data, AI systems, vendors and legal obligations
- Remediation tasks
- A compliance report suitable for DPO review

---

## Architecture

```
Code input
    │
    ▼
Secret Redaction          ← strips API keys, tokens, passwords
    │
    ▼
Deterministic Scanners    ← 10 scanners, no LLM
    ├── PersonalDataScanner
    ├── SpecialCategoryScanner
    ├── AIUsageScanner
    ├── AutomatedDecisionScanner
    ├── VendorScanner
    ├── DataStorageScanner
    ├── RetentionDeletionScanner
    ├── LoggingScanner
    ├── CookieTrackingScanner
    └── SecurityControlScanner
    │
    ▼
Evidence Graph Builder    ← nodes, edges, obligation links
    │
    ▼
Legal Corpus              ← 24 GDPR + AI Act obligations
    │
    ▼
LLM Analysis              ← Claude, grounded in scanner findings
    │                        and retrieved legal obligations only
    ▼
Structured Report         ← findings, citations, tasks, graph
```

---

## Tech Stack

- Python 3.11+
- FastAPI
- Anthropic Claude API
- PostgreSQL + pgvector (for corpus embeddings, Phase 2+)
- SQLAlchemy 2 + Alembic
- Docker Compose for local development
- Railway for deployment

---

## Setup

### Prerequisites

- Python 3.11+
- PostgreSQL (or use Docker Compose)
- Anthropic API key

### Local development

**1. Clone and enter the project**

```bash
cd /Users/nick/Desktop/Canopy
```

**2. Create virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**3. Set up environment variables**

```bash
cp .env.example .env
```

Edit `.env` and set:

```
API_KEY=sk-ant-your-key-here
DATABASE_URL=postgresql://camiro:camiro@localhost:5432/camiro
```

**4. Start PostgreSQL with Docker**

```bash
docker compose up db -d
```

Or use an existing PostgreSQL instance and update `DATABASE_URL`.

**5. Run database migrations**

```bash
alembic upgrade head
```

**6. Start the server**

```bash
uvicorn main:app --reload --port 8000
```

**7. Open the scanner**

```
http://127.0.0.1:8000
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `API_KEY` | Yes | Anthropic API key (named API_KEY to avoid Railway interception) |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `MAX_INPUT_CHARS` | No | Maximum code input size (default: 50000) |
| `DEMO_PASSWORD` | No | Optional password gate for public demo |
| `DEBUG` | No | Enable debug logging (default: false) |
| `REDACT_SECRETS` | No | Redact secrets before LLM call (default: true) |
| `LOG_SUBMITTED_CODE` | No | Log submitted code (default: false, keep off) |

---

## API Endpoints

### Demo (backward compatible)

```
GET  /          — Scanner UI
POST /analyse   — Run compliance scan (original endpoint)
GET  /health    — Health check
```

### Scan

```
POST /scan/code          — Full scan with organisation/project context
POST /scan/multi-file    — Scan multiple files (Phase 2)
```

### Corpus

```
GET /corpus/sources      — List all regulatory sources in registry
GET /corpus/obligations  — List all seeded obligations
```

### Graph (Phase 2+)

```
GET /graph/nodes         — List graph nodes for a project
GET /graph/edges         — List graph edges for a project
GET /graph/summary       — Graph summary
```

---

## How to Run Sample Scans

Three sample apps are included under `samples/`.

### AcmeHire — AI Recruitment (PROHIBITED risk expected)

```bash
cat samples/acmehire/app.py
```

Paste contents into the scanner at `http://127.0.0.1:8000`

Expected findings:
- Prohibited AI practice — gender, ethnicity, disability in scoring
- GDPR Art. 9 special category data (ethnicity, disability, criminal record)
- GDPR Art. 22 automated decision-making without human review
- AI Act Art. 6 potential high-risk classification (recruitment)
- AI Act Art. 14 missing human oversight
- GDPR Art. 28 — DPA required for OpenAI
- GDPR Art. 32 — hardcoded credentials, sensitive data in logs
- GDPR Art. 5 — no retention/deletion mechanism

### FinScore — AI Credit Scoring (HIGH risk expected)

```bash
cat samples/finscore/app.py
```

Expected findings:
- GDPR Art. 9 — medical history, disability, criminal record
- GDPR Art. 22 — fully automated loan decisions
- AI Act Art. 6 — credit scoring is Annex III high-risk
- GDPR Art. 28 — DPA required for Anthropic API
- Automated fund disbursement without human review

### ShopTrack — Ecommerce Tracking (LIMITED risk expected)

```bash
cat samples/shoptrack/app.py
```

Expected findings:
- ePrivacy — tracking before consent (Google Analytics, Meta Pixel, Mixpanel)
- GDPR Art. 6 — no consent mechanism
- GDPR Art. 5 — no retention schedule for analytics data
- GDPR Art. 32 — cookie without security attributes
- Personal data in logs (email, IP address)

---

## How to Ingest Corpus

The corpus registry is at `app/corpus/corpus_registry.yml`.

In v1, the following sources are enabled:
- GDPR
- Irish Data Protection Act 2018
- ePrivacy Directive
- Irish ePrivacy Regulations
- EDPB Guidelines
- DPC Guidance
- EU AI Act
- AI Act Commission Guidance

To see all registered sources:

```
GET /corpus/sources
```

To see all seeded obligations:

```
GET /corpus/obligations
```

Full corpus ingestion (EUR-Lex API integration) is Phase 2.

---

## Deploy to Railway

**1. Push to GitHub**

```bash
git add .
git commit -m "deploy"
git push origin main
```

**2. Connect Railway to your GitHub repo**

Go to railway.app → New Project → Deploy from GitHub.

**3. Set environment variables in Railway**

```
API_KEY = your-anthropic-key
DATABASE_URL = your-postgres-url
```

Railway provides a managed PostgreSQL service — add it from the Railway dashboard.

**4. Set start command**

In Railway service settings → Start Command:
```
uvicorn main:app --host 0.0.0.0 --port $PORT
```

---

## What the System Does Not Do

- Does not store submitted code by default
- Does not train on submitted code
- Does not provide legal advice
- Does not certify compliance
- Does not replace a DPIA, legal review, or DPO assessment
- Does not cover all 40+ regulations in the corpus registry (v1 covers GDPR and AI Act)
- Does not yet integrate with GitHub, GitLab or CI/CD pipelines (Phase 2)
- Does not yet ingest live regulatory updates from EUR-Lex (Phase 2)

---

## Legal Disclaimer

Camiro provides technical compliance decision support. It is not legal advice and does not replace review by qualified legal, privacy, security or regulatory professionals.

All findings are generated by automated analysis and require human review before reliance. Camiro does not guarantee accuracy, completeness or fitness for any particular regulatory purpose.

---

## Roadmap

| Phase | Description | Status |
|---|---|---|
| Phase 1 | Database models, settings, migrations | Done |
| Phase 2 | Corpus registry — 40+ EU regulations | Done |
| Phase 3 | Deterministic scanners — 10 modules | Done |
| Phase 4 | Evidence graph builder + updated pipeline | Done |
| Phase 5 | Sample apps + README | Done |
| Phase 6 | Live EUR-Lex corpus ingestion | Planned |
| Phase 7 | GitHub App integration | Planned |
| Phase 8 | DPIA and Article 30 document generation | Planned |
| Phase 9 | Full evidence graph UI | Planned |
| Phase 10 | Enterprise deployment options | Planned |

---

## Contact

nick@camiro.ai
