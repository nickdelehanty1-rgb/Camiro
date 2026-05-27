import yaml
import os
from pathlib import Path

CORPUS_DIR = Path(__file__).parent


def load_corpus_registry() -> list[dict]:
    path = CORPUS_DIR / "corpus_registry.yml"
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("sources", [])


def load_obligation_seeds() -> list[dict]:
    path = CORPUS_DIR / "obligation_seeds.yml"
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("obligations", [])


def get_enabled_sources() -> list[dict]:
    return [s for s in load_corpus_registry() if s.get("ingest_enabled", False)]


def get_obligations_for_source(short_name: str) -> list[dict]:
    return [
        o for o in load_obligation_seeds()
        if o.get("legal_source_short_name") == short_name
    ]
