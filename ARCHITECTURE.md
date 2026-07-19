# Camiro — Architecture Reference

## Overview

Camiro is a FastAPI application deployed on Railway. It provides EU AI Act / GDPR
compliance scanning for code, documents, and agentic AI logs. Scanning is a two-layer
pipeline: deterministic Python scanners produce structured evidence, which is then
grounded into a prompt sent to an Anthropic LLM for legal-obligation mapping.

---

## Entrypoints

| File | Role |
|------|------|
| `main.py` | FastAPI app, all HTTP routes, LLM call, pipeline orchestration |
| `start.sh` | `exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}` |
| `Procfile` | Railway start command (calls `start.sh`) |

---

## Scan Pipeline (end-to-end flow)

```
HTTP POST /scan/code  OR  /analyse
        │
        ▼
_run_full_scan(code, filename, org_id, proj_id)          [main.py]
        │
        ├─ Step 1: run_all_scanners(code, filename)       [app/scanners/orchestrator.py]
        │          ├─ SecretRedactionScanner              redact secrets first
        │          ├─ PersonalDataScanner                 regex PII detection
        │          ├─ SpecialCategoryScanner              Art.9 GDPR categories
        │          ├─ AIUsageScanner                      AI provider + domain context
        │          ├─ AutomatedDecisionScanner            GDPR Art.22 / AI Act Art.14
        │          ├─ VendorScanner                       third-party processors
        │          ├─ DataStorageScanner                  DB/storage usage
        │          ├─ RetentionDeletionScanner            retention/TTL signals
        │          ├─ LoggingScanner                      personal data in logs
        │          ├─ CookieTrackingScanner               tracking cookies
        │          ├─ SecurityControlScanner              auth/encryption gaps
        │          └─ DataFlowScanner                     AST-verified data flows
        │          Returns: {scanner_findings, summary, redacted_code, secrets_found}
        │
        ├─ Step 2: GraphBuilder.build_from_scanner_results()  [app/graph/builder.py]
        │          Builds nodes/edges/evidence graph from scanner output
        │
        ├─ Step 3: load_obligation_seeds()                [app/corpus/loader.py]
        │          Loads GDPR + AI Act legal obligations from obligation_seeds.yml
        │
        ├─ Step 4: build_llm_prompt(scanner_results, filename, obligations)  [main.py]
        │          Constructs a grounded prompt separating AST facts from pattern inferences
        │
        ├─ Step 5: anthropic.Anthropic().messages.create(...)  [main.py:466-473]
        │          MODEL: currently hardcoded "claude-sonnet-4-6" → should be CAMIRO_MODEL
        │          MAX_TOKENS: hardcoded 3000
        │          Returns structured JSON: risk_level, findings[], stats, etc.
        │
        ├─ Step 6: Merge _graph metadata into response
        │
        └─ Step 7: Attach _disclaimer → return to caller
```

### Document scan path

```
HTTP POST /scan/document
        │
        ▼
run_document_scan(text, filename, code_summary)          [app/scanners/orchestrator.py]
        └─ EvidenceIntakeScanner                         [app/scanners/evidence_intake_scanner.py]
           Detects contradictions, missing evidence, and observed facts in compliance docs
           (privacy notices, DPIAs, DPAs, AI policies)
```

### Agent scan path

```
HTTP POST /analyse  (with agent code or action log)
        └─ run_agent_scan()                              [app/scanners/orchestrator.py]
           ├─ AgentConfigScanner
           ├─ ToolPermissionScanner
           ├─ AgentActionLogScanner
           └─ DataFlowScanner
```

---

## LLM Call Sites

| Location | Line | Notes |
|----------|------|-------|
| `main.py` | 466–473 | Only production LLM call. `model="claude-sonnet-4-6"` hardcoded. `max_tokens=3000` hardcoded. |
| `tests/test_agent_scanners.py` | 58 | Test file — demo/sample only, not invoked in production |
| `samples/finscore/app.py` | 42, 75 | Demo sample, not production code |
| `samples/acmehire_agent/agent.py` | 217 | Demo sample, not production code |

---

## PDF Report Generator

The PDF is generated **client-side** using **jsPDF 2.5.1** loaded from a CDN.
All PDF logic lives in `static/index.html` in the `downloadPDF()` function (~245 lines of JS).
There is no server-side PDF generation.

Known defects (Phase 2 targets):
1. **Broken glyphs** — uses `⚖` (symbol font) with no safe Unicode fallback; extracts as garbage
2. **Article citation** — produces "Article 13 · Article 13, Article 14" (duplicate/unnormalised)
3. **Truncated action text** — recommendation text clipped mid-word at frame edge
4. **Stat block structure** — number and label rendered as separate text objects; text extraction detaches them
5. **Empty footer** — `· ·` slot has no date, model, or ruleset version

---

## Frontend

| File | Role |
|------|------|
| `static/landing.html` | Marketing / landing page (`GET /`) |
| `static/index.html` | Scanner UI (`GET /scanner`) — full single-page app |

---

## Config and Environment Loading

### `app/settings.py` — centralised Settings (pydantic-settings)
| Setting | Env var | Default |
|---------|---------|---------|
| `api_key` | `API_KEY` | `""` |
| `database_url` | `DATABASE_URL` | `postgresql://camiro:camiro@localhost:5432/camiro` |
| `max_input_chars` | `MAX_INPUT_CHARS` | `50000` |
| `demo_password` | `DEMO_PASSWORD` | `None` |
| `redact_secrets` | `REDACT_SECRETS` | `True` |
| `log_submitted_code` | `LOG_SUBMITTED_CODE` | `False` |
| `debug` | `DEBUG` | `False` |

### `main.py` — direct os.getenv() calls (not using Settings — Phase 1 fix)
- `API_KEY = os.getenv("API_KEY", "")` — line 27
- `MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "50000"))` — line 28

---

## Hardcoded Values to Fix (Phase 1)

| File | Line | Value | Fix |
|------|------|-------|-----|
| `main.py` | 468 | `model="claude-sonnet-4-6"` | `os.getenv("CAMIRO_MODEL", "claude-fable-5")` |
| `main.py` | 469 | `max_tokens=3000` | `settings.max_tokens` |
| `main.py` | 27–28 | Direct `os.getenv()` | Use `settings` object |
| `app/settings.py` | — | Missing `camiro_model`, `max_tokens` fields | Add them |

---

## Corpus and Obligations

- `app/corpus/obligation_seeds.yml` — GDPR + AI Act obligation definitions (loaded at runtime)
- `app/corpus/corpus_registry.yml` — source registry (ingestion config)
- `app/corpus/loader.py` — `load_obligation_seeds()`, `load_corpus_registry()`

---

## Eval Harness

- `evals/run_evals.py` — submits corpus cases to `/scan/code`, normalises responses, calls scorer
- `evals/score.py` — precision/recall/tier accuracy scorer
- `evals/corpus/` — labelled test cases (`.py` + `.expected.json` pairs)
- `evals/results/` — scanner output (written per run, gitignored)

`normalise()` in `run_evals.py` maps API response to `{risk_tier, findings[], data_types}`.
Currently `risk_tier` maps from `raw.get("risk_tier", raw.get("classification", raw.get("tier")))` —
but Camiro returns `risk_level`, not `risk_tier`. **Phase 7 fix required.**

---

## Dependencies (requirements.txt)

```
fastapi, uvicorn[standard], anthropic, python-multipart,
pydantic-settings, sqlalchemy[asyncio], asyncpg, alembic,
psycopg2-binary, pyyaml, python-dotenv
```

Phase 5 additions needed: `pdfplumber` or `pypdf`, `python-docx`
Phase 6 additions needed: `slowapi`
