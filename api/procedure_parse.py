"""
procedure_parse.py — heuristic parser for structured procedure content.

parse_procedure(text: str) -> dict with keys:
  steps:           list[str]  — numbered/bulleted action steps       (max 8)
  warnings:        list[str]  — WARNING/CAUTION/DANGER/IMPORTANT     (max 6)
  prereqs:         list[str]  — PPE/prepare/ensure/required lines    (max 6)
  troubleshooting: list[str]  — error/alarm/fault/troubleshooting    (max 6)

procedure_quality(proc: dict, excerpt: str) -> dict with keys:
  score:    int   — 0-100 quality score
  signals:  dict  — raw signal counts/flags
  decision: str   — "ok" | "weak" | "reject"

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


# ── Quality scoring ────────────────────────────────────────────────────────────

# Front-matter signal (mirrors _FRONT_MATTER_SIGNAL in main.py)
_FRONT_MATTER_QUALITY = re.compile(
    r'rescueintellitech|katy[\s,]+tx|copyright|all\s+rights\s+reserved'
    r'|user[\s\-_]*manual|www\.\S+\.\S+|https?://\S+',
    re.IGNORECASE,
)

# TOC-like: contains "CONTENTS" or dotted leaders (.....5 or more dots)
_TOC_CONTENTS = re.compile(r'\bcontents\b', re.IGNORECASE)
_DOTTED_LEADER = re.compile(r'\.{5,}')

# Imperative sentence: starts with a capitalized verb-like word (>=3 chars),
# NOT starting with one of the excluded non-imperative openers.
_IMPERATIVE_EXCLUDE = re.compile(
    r'^(?:The|A|An|This|These|When|If)\b',
)
_CAPITALIZED_START = re.compile(r'^[A-Z][a-z]{2,}')


def _count_imperatives(excerpt: str) -> int:
    """Count sentences that start with a capitalized verb-like word."""
    count = 0
    for raw in excerpt.split('\n'):
        line = raw.strip()
        if not line:
            continue
        # Split into sentences naively on '. '
        for sentence in re.split(r'(?<=[.!?])\s+', line):
            s = sentence.strip()
            if not s:
                continue
            if _IMPERATIVE_EXCLUDE.match(s):
                continue
            if _CAPITALIZED_START.match(s):
                count += 1
    return count


def procedure_quality(proc: dict, excerpt: str) -> dict:
    """
    Score a parsed procedure + excerpt for extraction quality.

    Returns:
      {
        "score": 0-100,
        "signals": {
          "numbered_steps": int,
          "imperatives": int,
          "warnings": int,
          "toc_like": bool,
          "front_matter": bool,
        },
        "decision": "ok" | "weak" | "reject",
      }
    """
    numbered_steps = len(proc.get("steps", []))
    warnings_count = len(proc.get("warnings", []))
    prereqs_count  = len(proc.get("prereqs", []))

    imperatives  = _count_imperatives(excerpt)
    toc_like     = bool(_TOC_CONTENTS.search(excerpt) or _DOTTED_LEADER.search(excerpt))
    front_matter = bool(_FRONT_MATTER_QUALITY.search(excerpt))

    # Decision
    if (toc_like or front_matter) and numbered_steps == 0 and imperatives < 2:
        decision = "reject"
    elif numbered_steps < 3 and warnings_count == 0 and prereqs_count == 0:
        decision = "weak"
    else:
        decision = "ok"

    # Score calculation
    score = 0
    score += min(numbered_steps * 10, 40)
    score += min(imperatives * 5, 20)
    score += min(warnings_count * 5, 15)
    if toc_like:
        score -= 30
    if front_matter:
        score -= 20
    score = max(0, min(100, score))

    return {
        "score": score,
        "signals": {
            "numbered_steps": numbered_steps,
            "imperatives":    imperatives,
            "warnings":       warnings_count,
            "toc_like":       toc_like,
            "front_matter":   front_matter,
        },
        "decision": decision,
    }
