"""
procedure_parse.py — heuristic parser for structured procedure content.

parse_procedure(text: str) -> dict with keys:
  steps:    list[str]  — numbered/bulleted action steps
  warnings: list[str]  — WARNING/CAUTION/DANGER/NOTE lines
  prereqs:  list[str]  — prerequisite/ensure/check lines
  codes:    list[str]  — fault/alarm/error codes

Caller should concatenate the cited chunk with adjacent chunks (same doc,
nearby indices) before calling, so warnings/prereqs that appear just before
or after the exact step sequence are captured.
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

# Explicit warning/caution/danger header at line start
_WARNING_HEADER = re.compile(
    r'^\s*(?:warning|caution|danger|alert|note)\s*[:!]?\s*',
    re.IGNORECASE,
)

# Inline safety-critical language anywhere in a non-step line
_WARNING_INLINE = re.compile(
    r'\b(?:warning|caution|danger|do\s+not|must\s+not|should\s+not|never|hazard)\b',
    re.IGNORECASE,
)

# Prerequisite start: "Ensure …", "Check …", "Verify …", "Before beginning …"
_PREREQ_START = re.compile(
    r'^\s*(?:ensure|check|verify|confirm|before\s+(?:you\s+)?(?:begin|start|operat|using|perform))',
    re.IGNORECASE,
)

# Inline prerequisite language
_PREREQ_INLINE = re.compile(
    r'\b(?:required|prerequisite|must\s+be\s+(?:in\s+place|present|ready|installed)'
    r'|prior\s+to|before\s+beginning|before\s+starting)\b',
    re.IGNORECASE,
)

# Fault/alarm/error codes: "E-01", "F3", "ERR 404", "ALARM-02"
_FAULT_CODE = re.compile(
    r'\b(?:error|alarm|fault|code|err)\s*[-:#]?\s*\d+\b'
    r'|\b[A-Z]{1,4}[-_]\d{2,4}\b',
    re.IGNORECASE,
)


def parse_procedure(text: str, max_each: int = 12) -> dict:
    """
    Parse procedure text into structured components.

    Returns dict with keys: steps, warnings, prereqs, codes.
    All values are lists of clean strings (≤ 300 chars each).
    """
    steps: list[str]    = []
    warnings: list[str] = []
    prereqs: list[str]  = []
    codes: list[str]    = []
    codes_seen: set[str] = set()

    for raw_line in text.split('\n'):
        line = raw_line.strip()
        if not line or len(line) < 4:
            continue

        # ── Explicit warning/caution header ──────────────────────────────────
        if _WARNING_HEADER.match(line):
            body = _WARNING_HEADER.sub('', line).strip()
            entry = body if len(body) > 4 else line
            if len(warnings) < max_each:
                warnings.append(entry[:300])
            continue

        # ── Numbered step ─────────────────────────────────────────────────────
        if _NUMBERED.match(line):
            body = _NUMBERED.sub('', line).strip()
            if body and len(body) > 4 and len(steps) < max_each:
                steps.append(body[:300])
            continue

        # ── Bullet step ───────────────────────────────────────────────────────
        if _BULLET.match(line):
            body = _BULLET.sub('', line).strip()
            if body and len(body) > 4 and len(steps) < max_each:
                steps.append(body[:300])
            continue

        # ── Inline warning sentence (not already a step) ──────────────────────
        if _WARNING_INLINE.search(line) and 10 < len(line) <= 400:
            if len(warnings) < max_each:
                warnings.append(line[:300])
            continue

        # ── Prerequisite ──────────────────────────────────────────────────────
        if (_PREREQ_START.match(line) or _PREREQ_INLINE.search(line)) and 10 < len(line) <= 400:
            if len(prereqs) < max_each:
                prereqs.append(line[:300])
            continue

        # ── Fault/alarm codes from any remaining line ─────────────────────────
        for m in _FAULT_CODE.finditer(line):
            code = m.group().strip()
            if code not in codes_seen and len(codes) < max_each:
                codes_seen.add(code)
                codes.append(code)

    return {
        "steps":    steps,
        "warnings": warnings,
        "prereqs":  prereqs,
        "codes":    codes,
    }
