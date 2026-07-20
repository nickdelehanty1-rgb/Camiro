"""
Camiro evaluation runner.

Submits every corpus case to a running Camiro instance and stores the raw
scanner output in results/, then invokes the scorer.

Usage:
    python run_evals.py --url https://web-production-640bb.up.railway.app
    python run_evals.py --url http://localhost:8000
    python run_evals.py --score-only        # re-score existing outputs

IMPORTANT — adapt scan_one() to your actual API contract. It currently
assumes POST {url}/api/scan with JSON {"code": "...", "filename": "..."}.
Print one raw response with --debug to see your real shape, then adjust
normalise() so score.py receives:
    {"risk_tier": ..., "findings": [...], "data_types": [...]}
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path
import ssl
from urllib import request, error

def _ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()

SSL_CTX = _ssl_context()

BASE = Path(__file__).parent
CORPUS = BASE / "corpus"
RESULTS = BASE / "results"


def scan_one(url: str, code: str, filename: str, timeout: int = 300) -> dict:
    """POST a code sample to the Camiro scan endpoint. ADAPT to your API."""
    payload = json.dumps({
        "code": code,
        "filename": filename,
        "organisation_name": "Camiro Evals",
        "project_name": "Evaluation Harness",
    }).encode()
    req = request.Request(
        f"{url.rstrip('/')}/scan/code",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
        return json.loads(resp.read().decode())


def normalise(raw: dict) -> dict:
    """Map Camiro's response shape onto the scorer's expected shape.

    Camiro returns:
      risk_level: "prohibited" | "high" | "limited" | "minimal"
      findings[]: {title, description, recommendation, severity,
                   ai_act_article, gdpr_article, articles[]}
      data_identified: ["name", "email", ...]
    """
    findings = []
    for f in raw.get("findings", []):
        # Build articles list from the pre-formatted field or from raw ai_act/gdpr fields
        raw_articles = f.get("articles") or []
        if not raw_articles:
            raw_articles = [a for a in [f.get("ai_act_article"), f.get("gdpr_article")] if a]
        findings.append({
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "recommendation": f.get("recommendation", ""),
            "severity": f.get("severity", "info"),
            "articles": raw_articles,
        })
    return {
        # Camiro uses risk_level; scorer expects risk_tier
        "risk_tier": raw.get("risk_level"),
        "findings": findings,
        "data_types": raw.get("data_identified", []),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", help="Base URL of the running Camiro instance")
    ap.add_argument("--score-only", action="store_true",
                    help="Skip scanning; score existing outputs in results/")
    ap.add_argument("--debug", action="store_true",
                    help="Print the first raw API response and exit")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="Seconds between API calls (rate-limit courtesy)")
    args = ap.parse_args()

    RESULTS.mkdir(exist_ok=True)

    if not args.score_only:
        if not args.url:
            ap.error("--url is required unless --score-only")
        labels = sorted(CORPUS.rglob("*.expected.json"))
        print(f"Running {len(labels)} corpus cases against {args.url}\n")
        for label_path in labels:
            expected = json.loads(label_path.read_text())
            case_id = expected["case_id"]
            code_path = label_path.with_name(
                label_path.name.replace(".expected.json", ".py"))
            if not code_path.exists():
                print(f"  SKIP {case_id}: no code file {code_path.name}")
                continue
            print(f"  scanning {case_id} ...", end=" ", flush=True)
            try:
                raw = scan_one(args.url, code_path.read_text(), code_path.name)
            except error.HTTPError as e:
                print(f"HTTP {e.code}: {e.read().decode()[:200]}")
                continue
            except Exception as e:
                print(f"ERROR: {e}")
                continue
            if args.debug:
                print("\n--- RAW RESPONSE ---")
                print(json.dumps(raw, indent=2)[:3000])
                return 0
            out = normalise(raw)
            out_path = RESULTS / (case_id.replace("/", "__") + ".output.json")
            out_path.write_text(json.dumps(out, indent=2))
            n = len(out["findings"])
            print(f"ok ({n} findings, tier={out['risk_tier']})")
            time.sleep(args.delay)

    # score
    sys.path.insert(0, str(BASE))
    from score import run as score_run
    return score_run(CORPUS, RESULTS)


if __name__ == "__main__":
    sys.exit(main())
