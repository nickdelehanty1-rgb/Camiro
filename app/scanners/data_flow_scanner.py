"""
DataFlowScanner v0 — single-file, intraprocedural taint analysis for Python.

Seeds taint from personal-data-named identifiers (parameters + assignments),
propagates through assignments and f-strings, fires when a tainted name
reaches a classified sink (AI model, logger, DB write, outbound HTTP).

Deliberately conservative: fewer high-confidence findings over noisy output.
Scope: single-file, intraprocedural only. No cross-function or cross-file flow.
"""
import ast
import re
from typing import Optional
from .base import BaseScanner, ScannerFinding

# ---------------------------------------------------------------------------
# Taint seeding: identifier name → personal data?
# ---------------------------------------------------------------------------

_PD_TERMS = frozenset({
    'email', 'name', 'phone', 'address', 'dob', 'birth', 'born',
    'cv', 'resume', 'candidate', 'applicant', 'salary', 'income',
    'credit', 'health', 'medical', 'diagnosis', 'biometric', 'location',
    'gender', 'ethnicity', 'disability', 'nationality', 'criminal',
    'ssn', 'passport',
})

_CAMEL_RE = re.compile(r'([a-z])([A-Z])')
_ID_SUFFIX_RE = re.compile(r'[_]?id$', re.IGNORECASE)


def _is_pd_name(identifier: str) -> bool:
    """Return True if an identifier name suggests it holds personal data."""
    # Skip numeric foreign-key fields: user_id, applicant_id, candidate_id, etc.
    if _ID_SUFFIX_RE.search(identifier):
        return False
    parts = _CAMEL_RE.sub(r'\1_\2', identifier).lower().split('_')
    for part in parts:
        if part in _PD_TERMS:
            return True
        # Simple plural handling: candidates → candidate, emails → email
        if part.endswith('s') and part[:-1] in _PD_TERMS:
            return True
    return False


# ---------------------------------------------------------------------------
# Sink classification
# ---------------------------------------------------------------------------

_LOG_METHODS = frozenset({'info', 'debug', 'warning', 'error', 'critical', 'exception'})
_LOG_OBJECTS = frozenset({'logger', 'logging', 'log'})

# Each entry: (substring of dotted call name, human label, confidence, tags)
_SINK_TABLE: list[tuple[str, str, float, list[str]]] = [
    # AI model sinks — highest evidential value
    ('chat.completions.create', 'AI model call (OpenAI/Azure)', 0.90,
     ['data_flow', 'personal_data', 'ai_sink', 'GDPR_ART28', 'AI_ACT_ART6']),
    ('messages.create',         'AI model call (Anthropic)',    0.90,
     ['data_flow', 'personal_data', 'ai_sink', 'GDPR_ART28', 'AI_ACT_ART6']),
    ('completions.create',      'AI model call',                0.88,
     ['data_flow', 'personal_data', 'ai_sink', 'GDPR_ART28', 'AI_ACT_ART6']),
    ('generate_content',        'AI model call (Google)',       0.90,
     ['data_flow', 'personal_data', 'ai_sink', 'GDPR_ART28', 'AI_ACT_ART6']),
    ('invoke_model',            'AI model call (Bedrock)',      0.90,
     ['data_flow', 'personal_data', 'ai_sink', 'GDPR_ART28', 'AI_ACT_ART6']),
    # Database write sinks
    ('cur.execute',             'database write',               0.80,
     ['data_flow', 'personal_data', 'db_sink', 'GDPR_ART5', 'GDPR_ART32']),
    ('cursor.execute',          'database write',               0.80,
     ['data_flow', 'personal_data', 'db_sink', 'GDPR_ART5', 'GDPR_ART32']),
    ('session.add',             'ORM database write',           0.80,
     ['data_flow', 'personal_data', 'db_sink', 'GDPR_ART5', 'GDPR_ART32']),
    ('db.execute',              'database write',               0.80,
     ['data_flow', 'personal_data', 'db_sink', 'GDPR_ART5', 'GDPR_ART32']),
    # Outbound HTTP sinks
    ('requests.post',           'outbound HTTP POST',           0.80,
     ['data_flow', 'personal_data', 'http_sink', 'GDPR_ART28', 'GDPR_ART44']),
    ('requests.put',            'outbound HTTP PUT',            0.80,
     ['data_flow', 'personal_data', 'http_sink', 'GDPR_ART28', 'GDPR_ART44']),
    ('requests.patch',          'outbound HTTP PATCH',          0.80,
     ['data_flow', 'personal_data', 'http_sink', 'GDPR_ART28', 'GDPR_ART44']),
    ('httpx.post',              'outbound HTTP POST',           0.80,
     ['data_flow', 'personal_data', 'http_sink', 'GDPR_ART28', 'GDPR_ART44']),
    ('httpx.put',               'outbound HTTP PUT',            0.80,
     ['data_flow', 'personal_data', 'http_sink', 'GDPR_ART28', 'GDPR_ART44']),
    ('httpx.patch',             'outbound HTTP PATCH',          0.80,
     ['data_flow', 'personal_data', 'http_sink', 'GDPR_ART28', 'GDPR_ART44']),
    # Vector DB / embedding sinks
    ('index.upsert',            'vector DB upsert',             0.75,
     ['data_flow', 'personal_data', 'vector_sink', 'GDPR_ART28']),
    ('collection.add',          'vector DB insert',             0.75,
     ['data_flow', 'personal_data', 'vector_sink', 'GDPR_ART28']),
    ('vectorstore.add_texts',   'vector DB insert',             0.75,
     ['data_flow', 'personal_data', 'vector_sink', 'GDPR_ART28']),
    ('add_documents',           'vector DB insert',             0.75,
     ['data_flow', 'personal_data', 'vector_sink', 'GDPR_ART28']),
]


def _classify_sink(call_name: str) -> Optional[tuple[str, float, list[str]]]:
    """Return (label, confidence, tags) if call_name is a known sink, else None."""
    lower = call_name.lower()

    for pattern, label, conf, tags in _SINK_TABLE:
        if pattern in lower:
            return (label, conf, tags)

    # Logger method pattern: logger.info, logging.debug, app_logger.warning, etc.
    parts = lower.split('.')
    if len(parts) >= 2 and parts[-1] in _LOG_METHODS:
        base = parts[-2]
        if base in _LOG_OBJECTS or base.endswith('log') or base.endswith('logger'):
            return ('logging call', 0.85,
                    ['data_flow', 'personal_data', 'log_sink', 'GDPR_ART32'])

    if lower == 'print':
        return ('print/stdout output', 0.75,
                ['data_flow', 'personal_data', 'log_sink', 'GDPR_ART32'])

    return None


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _call_name(node: ast.Call) -> str:
    """Collapse a.b.c(...) func-chain into the string 'a.b.c'."""
    parts: list[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    return '.'.join(reversed(parts))


def _tainted_in_expr(node: ast.AST, tainted: set[str]) -> list[str]:
    """Return deduplicated tainted names that appear anywhere within node."""
    return list({
        n.id
        for n in ast.walk(node)
        if isinstance(n, ast.Name) and n.id in tainted
    })


# ---------------------------------------------------------------------------
# Taint walker
# ---------------------------------------------------------------------------

class _TaintWalker(ast.NodeVisitor):
    """
    Single-pass AST visitor.
    Seeds taint from PD-named parameters and assignments.
    Propagates taint through assignments containing tainted names.
    Fires a finding when a tainted name reaches a classified sink call.
    """

    def __init__(self, lines: list[str]) -> None:
        self._tainted: dict[str, int] = {}   # varname → line first tainted
        self.findings: list[dict] = []
        self._lines = lines

    def _seed(self, name: str, lineno: int) -> None:
        if name not in self._tainted:
            self._tainted[name] = lineno

    def _line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()
        return ''

    # -- Taint seeding from function parameters --

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for arg in (node.args.args + node.args.posonlyargs + node.args.kwonlyargs):
            if _is_pd_name(arg.arg):
                self._seed(arg.arg, arg.lineno)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # -- Taint seeding and propagation through assignments --

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and _is_pd_name(target.id):
                self._seed(target.id, node.lineno)

        hit = _tainted_in_expr(node.value, set(self._tainted))
        if hit:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._seed(target.id, node.lineno)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None:
            self.generic_visit(node)
            return
        if isinstance(node.target, ast.Name):
            if _is_pd_name(node.target.id):
                self._seed(node.target.id, node.lineno)
            if _tainted_in_expr(node.value, set(self._tainted)):
                self._seed(node.target.id, node.lineno)
        self.generic_visit(node)

    # -- Sink detection --

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        sink = _classify_sink(name)
        if sink:
            label, confidence, tags = sink
            all_args = list(node.args) + [kw.value for kw in node.keywords]
            tainted_found = list({
                v
                for arg in all_args
                for v in _tainted_in_expr(arg, set(self._tainted))
            })
            if tainted_found:
                lineno = node.lineno
                source_info = ', '.join(
                    f'{v} (line {self._tainted[v]})' for v in sorted(tainted_found)
                )
                self.findings.append({
                    'source_vars':  tainted_found,
                    'source_lines': {v: self._tainted[v] for v in tainted_found},
                    'sink_name':    name,
                    'sink_label':   label,
                    'sink_line':    lineno,
                    'confidence':   confidence,
                    'tags':         tags,
                    'excerpt':      self._line_text(lineno),
                    'description':  (
                        f"{', '.join(sorted(tainted_found))} "
                        f"flow{'s' if len(tainted_found) == 1 else ''} into "
                        f"{label} ({name}) on line {lineno}. "
                        f"Taint source(s): {source_info}."
                    ),
                })

        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Public scanner class
# ---------------------------------------------------------------------------

class DataFlowScanner(BaseScanner):
    """
    AST-based single-file taint scanner for Python.
    Detects personal-data variable flows into AI, logging, DB, and HTTP sinks.
    """
    name = "data_flow"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        # Skip non-Python files
        if filename and '.' in filename and not filename.endswith('.py'):
            return []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        walker = _TaintWalker(code.splitlines())
        walker.visit(tree)

        findings: list[ScannerFinding] = []
        seen: set[tuple] = set()

        for raw in walker.findings:
            key = (frozenset(raw['source_vars']), raw['sink_name'], raw['sink_line'])
            if key in seen:
                continue
            seen.add(key)

            source_vars = sorted(raw['source_vars'])
            flow_type = next(
                (t for t in raw['tags'] if t.endswith('_sink')),
                'unknown_sink',
            )
            findings.append(ScannerFinding(
                scanner_name=self.name,
                finding_type='personal_data_flow',
                title=(
                    f"Personal data flows into {raw['sink_label']}: "
                    f"{', '.join(source_vars)}"
                ),
                description=raw['description'],
                confidence=raw['confidence'],
                file_path=filename,
                line_start=raw['sink_line'],
                evidence_excerpt=(raw['excerpt'] or '')[:200] or None,
                tags=raw['tags'],
                suggested_node_type='data_flow',
                metadata={
                    'source_variables': source_vars,
                    'source_lines':     raw['source_lines'],
                    'sink_name':        raw['sink_name'],
                    'sink_line':        raw['sink_line'],
                    'flow_type':        flow_type,
                },
            ))

        return findings
