"""Utilities for formatting article reference lists into human-readable citations."""
import re

_ART_RE = re.compile(r'\bArt(?:icle)?s?\.?\s*(\d+)', re.IGNORECASE)


def format_articles(refs: list[str]) -> str:
    """Format a list of article reference strings into a readable citation.

    Deduplicates, extracts article numbers, collapses consecutive numbers into
    en-dash ranges, and joins with commas and "and".  Uses "Article" (singular)
    for a single number and "Articles" (plural) for two or more.

    Examples:
        ["Art. 13"]                        -> "Article 13"
        ["Art. 13", "Art. 14"]             -> "Articles 13–14"
        ["Art. 5", "Art. 13", "Art. 14"]   -> "Articles 5 and 13–14"
        ["Art. 13", "Art. 13", "Art. 14"]  -> "Articles 13–14"
    """
    if not refs:
        return ""

    nums: set[int] = set()
    for ref in refs:
        for m in _ART_RE.finditer(ref):
            nums.add(int(m.group(1)))

    sorted_nums = sorted(nums)

    if not sorted_nums:
        # No parseable article numbers — deduplicate and return as-is
        unique = list(dict.fromkeys(r.strip() for r in refs if r.strip()))
        if not unique:
            return ""
        prefix = "Articles" if len(unique) > 1 else "Article"
        if len(unique) == 1:
            return f"{prefix} {unique[0]}"
        if len(unique) == 2:
            return f"{prefix} {unique[0]} and {unique[1]}"
        return f"{prefix} {', '.join(unique[:-1])} and {unique[-1]}"

    # Collapse consecutive numbers into ranges
    groups: list[str] = []
    start = end = sorted_nums[0]
    for n in sorted_nums[1:]:
        if n == end + 1:
            end = n
        else:
            groups.append(f"{start}–{end}" if start != end else str(start))
            start = end = n
    groups.append(f"{start}–{end}" if start != end else str(start))

    prefix = "Articles" if len(sorted_nums) > 1 else "Article"

    if len(groups) == 1:
        return f"{prefix} {groups[0]}"
    if len(groups) == 2:
        return f"{prefix} {groups[0]} and {groups[1]}"
    return f"{prefix} {', '.join(groups[:-1])} and {groups[-1]}"
