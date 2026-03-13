"""
text_clean.py — deterministic cleanup for corpus excerpts and summaries.

Public API
----------
clean_lines(text: str) -> str
    Drop boilerplate lines (TOC, addresses, URLs, copyright, all-caps
    headers, high digit-density, mostly-punctuation), collapse whitespace,
    and strip non-printing characters.

make_summary(text: str, max_chars: int = 500) -> str
    Apply clean_lines(), then truncate to *max_chars* at a sentence or
    word boundary and return a single paragraph suitable for display.
"""

from __future__ import annotations

import re
import unicodedata

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_URL = re.compile(r'https?://\S+|ftp://\S+|www\.\S+\.\S+', re.IGNORECASE)

_EMAIL = re.compile(r'\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b', re.IGNORECASE)

_STREET = re.compile(
    r'\b\d+\s+\w[\w\s]{2,30}'
    r'\b(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln'
    r'|way|court|ct|suite|ste)\b',
    re.IGNORECASE,
)

# "Katy, TX 77493" style — city, two-letter state, optional ZIP
_CITY_STATE_ZIP = re.compile(
    r'\b[A-Z][a-z]{1,25},\s*[A-Z]{2}(?:\s*\d{5}(?:-\d{4})?)?\b'
)

_COPYRIGHT = re.compile(
    r'\bcopyright\b|all\s+rights\s+reserved|©',
    re.IGNORECASE,
)

_TOC = re.compile(
    r'\btable[\s\-_]*of[\s\-_]*contents\b|\bcontents\b',
    re.IGNORECASE,
)

_MANUAL_TITLE = re.compile(
    r'\buser[\s\-_]*(?:manual|guide)\b',
    re.IGNORECASE,
)

# Two or more ALL-CAPS words in a row (e.g. "SOLO RESCUE DECON UNIT")
_ALL_CAPS_HEADER = re.compile(r'^(?:[A-Z]{3,}[\s\-/,]*){2,}$')

# Section-number density pattern (e.g. "1.2.3")
_SECTION_NUM = re.compile(r'\b\d+(?:\.\d+)+\b')

# Control / non-printing characters (keep normal whitespace \t \n \r)
_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')

_MULTI_BLANK = re.compile(r'\n{3,}')

# Dotted leaders used in TOC entries (5+ consecutive dots)
_DOTTED_LEADER = re.compile(r'\.{5,}')


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _remove_nonprinting(text: str) -> str:
    text = _CTRL.sub('', text)
    return unicodedata.normalize('NFC', text)


def _is_noise_line(line: str) -> bool:
    """Return True when *line* is boilerplate and should be dropped."""
    stripped = line.strip()
    if not stripped:
        return False  # blank lines are kept (collapsed later)
    if len(stripped) < 4:
        return True

    if _URL.search(stripped):
        return True
    if _EMAIL.search(stripped):
        return True
    if _STREET.search(stripped):
        return True
    if _CITY_STATE_ZIP.search(stripped):
        return True
    if _COPYRIGHT.search(stripped):
        return True
    if _TOC.search(stripped):
        return True
    if _MANUAL_TITLE.search(stripped):
        return True
    if _ALL_CAPS_HEADER.match(stripped):
        return True

    n = max(len(stripped), 1)

    # High digit density (>= 30 % digits) — phone numbers, page-number lists
    if sum(c.isdigit() for c in stripped) / n > 0.30:
        return True

    # Section-number density > 12 % of words — TOC entry rows
    words = stripped.split()
    n_words = max(len(words), 1)
    if len(_SECTION_NUM.findall(stripped)) / n_words > 0.12:
        return True

    # Dotted TOC leaders (e.g. "Introduction .......... 3")
    if _DOTTED_LEADER.search(stripped):
        return True

    # Mostly punctuation (>= 50 % non-alphanumeric non-space) — dashes, bars
    non_alnum_space = sum(1 for c in stripped if not c.isalnum() and not c.isspace())
    if non_alnum_space / n >= 0.50:
        return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def clean_lines(text: str) -> str:
    """
    Drop boilerplate lines, collapse whitespace, remove non-printing chars.

    Returns a cleaned string with normalized newlines.
    """
    text = _remove_nonprinting(text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')

    kept: list[str] = []
    for line in text.split('\n'):
        if _is_noise_line(line):
            continue
        line = re.sub(r'[ \t]+', ' ', line).strip()
        kept.append(line)

    cleaned = '\n'.join(kept)
    cleaned = _MULTI_BLANK.sub('\n\n', cleaned).strip()
    return cleaned


def make_summary(text: str, max_chars: int = 500) -> str:
    """
    Clean *text* and return a concise single paragraph up to *max_chars*.

    Truncation prefers sentence boundaries ('. '), then word boundaries.
    Appends '…' when truncated.
    """
    cleaned = clean_lines(text)

    # Flatten to one paragraph
    para = re.sub(r'\s*\n+\s*', ' ', cleaned).strip()

    if len(para) <= max_chars:
        return para

    window = para[:max_chars]
    last_period = window.rfind('. ')
    if last_period > max_chars // 3:
        return window[: last_period + 1]

    last_space = window.rfind(' ')
    if last_space > 0:
        return window[:last_space] + '…'

    return window + '…'
