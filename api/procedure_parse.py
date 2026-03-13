"""
procedure_parse.py — heuristic parser for structured procedure content.

parse_procedure(text: str) -> dict with keys:
  steps:           list[str]  — numbered/bulleted action steps       (max 8)
  warnings:        list[str]  — WARNING/CAUTION/DANGER/IMPORTANT     (max 6)
  prereqs:         list[str]  — PPE/prepare/ensure/required lines    (max 6)
  troubleshooting: list[str]  — error/alarm/fault/troubleshooting    (max 6)

All values are deduplicated (case-insensitive) and each entry ≤ 300 chars.
Caller should concatenate the cited chunk with adjacent chunks (same doc,
±2 around the cited index) before calling, for broader context.
"""

from __future__ import annotations

import re

# ── Compiled patterns ──────────────────────────────────────────────────────────

# Numbered step: "1. ", "1) ", "Step 1:", "Step 1."
_NUMBERED = re.compile(
    r'^\s*(?:step\s+\d+\s*[:.]?\s*|\d+[.)]\s+)',
    re.IGNORECASE,
)

# Bullet step: "• ", "- ", "* " at line start
_BULLET = re.compile(r'^\s*[•\-\*]\s+')

# Explicit warning/caution/danger/important/note header at line start
_WARNING_HEADER = re.compile(
    r'^\s*(?:warning|caution|danger|important|alert|note)\s*[:!]?\s*',
    re.IGNORECASE,
)

# Inline safety-critical language (for non-step lines)
_WARNING_INLINE = re.compile(
    r'\b(?:WARNING|CAUTION|DANGER|IMPORTANT)\b',
)

# Prerequisite: explicit start word or inline prerequisite language
_PREREQ_START = re.compile(
    r'^\s*(?:ensure|check|verify|confirm|prepare|wear|don\b|put\s+on'
    r'|before\s+(?:you\s+)?(?:begin|start|operat|using|perform|use))',
    re.IGNORECASE,
)
_PREREQ_INLINE = re.compile(
    r'\b(?:PPE|personal\s+protective\s+equipment|required|prerequisite'
    r'|preparation|before\s+use|must\s+be\s+(?:in\s+place|present|ready|worn)'
    r'|prior\s+to|before\s+beginning|before\s+starting)\b',
    re.IGNORECASE,
)

# Troubleshooting: lines mentioning error conditions, alarms, faults, codes
_TROUBLESHOOT = re.compile(
    r'\b(?:troubleshoot(?:ing)?'
    r'|error(?:\s+code)?'
    r'|alarm'
    r'|fault(?:\s+code)?'
    r'|malfunction'
    r'|diagnostic'
    r'|if\s+the\s+(?:machine|unit|device|display|led|light|indicator)'
    r')\b',
    re.IGNORECASE,
)


def _dedup(lst: list[str]) -> list[str]:
    """Return list with case-insensitive duplicates removed (first occurrence wins)."""
    seen: set[str] = set()
    out: list[str] = []
    for item in lst:
        key = re.sub(r'\s+', ' ', item.strip().lower())
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def parse_procedure(
    text: str,
    max_steps: int = 8,
    max_warnings: int = 6,
    max_prereqs: int = 6,
    max_troubleshooting: int = 6,
) -> dict:
    """
    Parse procedure text into structured components.

    Returns dict with keys: steps, warnings, prereqs, troubleshooting.
    All values are deduplicated lists of clean strings (≤ 300 chars each).
    """
    steps:           list[str] = []
    warnings:        list[str] = []
    prereqs:         list[str] = []
    troubleshooting: list[str] = []

    for raw_line in text.split('\n'):
        line = raw_line.strip()
        if not line or len(line) < 4:
            continue

        # ── Explicit warning/caution header ──────────────────────────────────
        if _WARNING_HEADER.match(line):
            body = _WARNING_HEADER.sub('', line).strip()
            entry = body if len(body) > 4 else line
            warnings.append(entry[:300])
            continue

        # ── Numbered step ─────────────────────────────────────────────────────
        if _NUMBERED.match(line):
            body = _NUMBERED.sub('', line).strip()
            if body and len(body) > 4:
                steps.append(body[:300])
            continue

        # ── Bullet step ───────────────────────────────────────────────────────
        if _BULLET.match(line):
            body = _BULLET.sub('', line).strip()
            if body and len(body) > 4:
                steps.append(body[:300])
            continue

        # ── Inline WARNING/CAUTION/DANGER/IMPORTANT (all-caps signal only) ───
        if _WARNING_INLINE.search(line) and 10 < len(line) <= 400:
            warnings.append(line[:300])
            continue

        # ── Troubleshooting ───────────────────────────────────────────────────
        if _TROUBLESHOOT.search(line) and 10 < len(line) <= 400:
            troubleshooting.append(line[:300])
            continue

        # ── Prerequisite ──────────────────────────────────────────────────────
        if (_PREREQ_START.match(line) or _PREREQ_INLINE.search(line)) and 10 < len(line) <= 400:
            prereqs.append(line[:300])
            continue

    return {
        "steps":           _dedup(steps)[:max_steps],
        "warnings":        _dedup(warnings)[:max_warnings],
        "prereqs":         _dedup(prereqs)[:max_prereqs],
        "troubleshooting": _dedup(troubleshooting)[:max_troubleshooting],
    }
