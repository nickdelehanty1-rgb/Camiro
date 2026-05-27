from dataclasses import dataclass, field
from typing import Optional
import re


@dataclass
class ScannerFinding:
    scanner_name: str
    finding_type: str
    title: str
    description: str
    confidence: float = 1.0
    file_path: Optional[str] = None
    function_name: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence_excerpt: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    suggested_node_type: Optional[str] = None
    metadata: dict = field(default_factory=dict)


class BaseScanner:
    name: str = "base"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        raise NotImplementedError

    def _get_lines(self, code: str) -> list[str]:
        return code.split("\n")

    def _find_line(self, code: str, pattern: str) -> Optional[int]:
        for i, line in enumerate(code.split("\n"), 1):
            if pattern in line:
                return i
        return None

    def _find_lines_matching(self, code: str, pattern: re.Pattern) -> list[tuple[int, str]]:
        results = []
        for i, line in enumerate(code.split("\n"), 1):
            if pattern.search(line):
                results.append((i, line.strip()))
        return results

    def _excerpt(self, line: str, max_len: int = 120) -> str:
        line = line.strip()
        return line[:max_len] + "..." if len(line) > max_len else line
