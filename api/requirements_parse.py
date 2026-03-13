"""
requirements_parse.py — heuristic parser for structured electrical requirements.

parse_requirements(text: str) -> dict with keys:
  items:           list[dict]  — {model, voltage, amps} per model/voltage variant
  wiring_notes:    list[str]   — lines about power supply routing / wiring rules
  grounding_notes: list[str]   — lines about grounding / RFI / EMI
  raw_signals:     dict        — signal counts for debugging

make_requirements_summary(items, wiring_notes) -> str
  Compact ≤350-char paragraph suitable for guidance["summary"] override.

Caller should pass _combined (adjacent chunks ±2 already fetched in
_corpus_fts_retrieve) so that wiring context from adjacent pages is captured.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Inline spec: "2001 12 VDC requires 41 amps" / "2002 or 2002HP 24VDC requires 30 amps"
# Model group may be "NNNN" or "NNNN or NNNNxx"
_INLINE_SPEC = re.compile(
    r'(\d{4}(?:\s+or\s+\d{4}[A-Za-z0-9]*)?)'   # model(s)
    r'\s+'
    r'(\d+\s*V[DA][CA])'                          # voltage  (12 VDC / 24VDC)
    r'\s+requires?\s+'                            # "requires "
    r'(\d+)\s*amps?',                             # amps value
    re.IGNORECASE,
)

# Table-row spec (fallback): "2001 12 VDC 41" — bare number at end of line
# Only used when inline extraction yields nothing.
_TABLE_ROW_SPEC = re.compile(
    r'^[ \t]*(\d{4}(?:\s+or\s+\d{4}[A-Za-z0-9]*)?)'
    r'\s+'
    r'(\d+\s*V[DA][CA])'
    r'\s+'
    r'(\d{1,3})\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Wiring note keywords: lines about electrical power source, routing, protection.
# "supply" and "circuit" alone are excluded — too broad (match "water supply").
_WIRING_KW = re.compile(
    r'\b(?:battery|disconnect|contactor|PTO'
    r'|fuse|breaker|high[\s\-]power|wire\s+size|gauge|AWG'
    r'|power\s+(?:supply|terminal|cable|wire)'
    r'|apparatus\s+battery)\b',
    re.IGNORECASE,
)

# Grounding note keywords
_GROUNDING_KW = re.compile(
    r'\b(?:ground(?:ing)?|RFI|EMI|interference|strap|shield)\b',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_voltage(v: str) -> str:
    """Normalize '24VDC' → '24 VDC'; '12 VDC' unchanged."""
    v = v.strip().upper()
    return re.sub(r'(\d)(V[DA][CA])', r'\1 \2', v)


def _compact_voltage(v: str) -> str:
    """'24 VDC' → '24VDC' for compact summary display."""
    return v.replace(' ', '')


def _expand_model_group(model_str: str, voltage: str, amps: int) -> list[dict]:
    """Expand 'M1 or M2' into two item dicts."""
    parts = re.split(r'\s+or\s+', model_str.strip(), flags=re.IGNORECASE)
    return [{"model": p.strip(), "voltage": voltage, "amps": amps} for p in parts]


def _split_sentences(text: str) -> list[str]:
    """Return sentence-like units from text (newline-split then '. '-split)."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for part in re.split(r'(?<=[.!?])\s+', line):
            s = part.strip()
            if len(s) >= 20:
                out.append(s)
    return out


def _dedup(lst: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in lst:
        key = re.sub(r'\s+', ' ', item.strip().lower())[:100]
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# Hygiene filter
# ---------------------------------------------------------------------------

# Keywords that make a note worth keeping — electrical/grounding relevance.
_HYGIENE_KEEP_KW = re.compile(
    r'\b(?:vdc|volt|amp|battery|disconnect|contactor|pto'
    r'|ground(?:ing)?|strap|rfi|emi)\b',
    re.IGNORECASE,
)

# Pointer-only phrases that make a line a redirect, not content.
_HYGIENE_POINTER = re.compile(
    r'\b(?:refer\s+to\s+(?:section|page)'
    r'|see\s+(?:section|page)'
    r'|for\s+(?:complete|more|full|additional|detailed?)\s+'
    r'(?:information|details?|specifications?|requirements?))\b',
    re.IGNORECASE,
)


def filter_requirements_notes(
    wiring_notes: list[str],
    grounding_notes: list[str],
) -> tuple[list[str], list[str]]:
    """
    Remove low-signal notes from wiring/grounding lists.

    Rules (applied in order, preserving original order):
    1. Keep a note only if it contains at least one relevance keyword
       (vdc, volt, amp, battery, disconnect, contactor, pto, ground,
       strap, rfi, emi).
    2. Drop a note that is pointer-only ("refer to section", "see section",
       "for details") UNLESS it also contains a relevance keyword.
    3. Cap: wiring_notes to 4, grounding_notes to 2.
    """
    def _keep(note: str) -> bool:
        has_kw = bool(_HYGIENE_KEEP_KW.search(note))
        if not has_kw:
            return False
        if _HYGIENE_POINTER.search(note):
            # Pointer phrases allowed only when they also carry spec keywords.
            # (The has_kw check above already ensures at least one kw is present.)
            return True
        return True

    filtered_wiring = [n for n in wiring_notes if _keep(n)][:4]
    filtered_grounding = [n for n in grounding_notes if _keep(n)][:2]
    return filtered_wiring, filtered_grounding


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_requirements(text: str) -> dict:
    """
    Parse requirements text into structured components.

    Returns dict:
      items:           list[dict]  — {model: str, voltage: str, amps: int}
      wiring_notes:    list[str]   — max 6
      grounding_notes: list[str]   — max 4
      raw_signals:     dict
    """
    items: list[dict] = []
    seen_items: set[tuple] = set()
    n_inline = 0
    n_table = 0

    # Phase 1 — inline spec ("requires N amps" format)
    for m in _INLINE_SPEC.finditer(text):
        n_inline += 1
        model_str = m.group(1)
        voltage = _normalize_voltage(m.group(2))
        amps = int(m.group(3))
        for item in _expand_model_group(model_str, voltage, amps):
            key = (item["model"].upper(), item["voltage"], item["amps"])
            if key not in seen_items:
                seen_items.add(key)
                items.append(item)

    # Phase 2 — table-row spec (fallback when inline yields nothing)
    if not items:
        for m in _TABLE_ROW_SPEC.finditer(text):
            n_table += 1
            model_str = m.group(1)
            voltage = _normalize_voltage(m.group(2))
            amps = int(m.group(3))
            for item in _expand_model_group(model_str, voltage, amps):
                key = (item["model"].upper(), item["voltage"], item["amps"])
                if key not in seen_items:
                    seen_items.add(key)
                    items.append(item)

    # Phase 3 — wiring and grounding notes from sentences
    wiring_notes: list[str] = []
    grounding_notes: list[str] = []
    for sentence in _split_sentences(text):
        if _WIRING_KW.search(sentence):
            wiring_notes.append(sentence[:300])
        if _GROUNDING_KW.search(sentence):
            grounding_notes.append(sentence[:300])

    wiring_notes = _dedup(wiring_notes)[:6]
    grounding_notes = _dedup(grounding_notes)[:4]

    # Hygiene pass: remove pointer-only / low-signal notes and cap counts.
    wiring_notes, grounding_notes = filter_requirements_notes(wiring_notes, grounding_notes)

    return {
        "items": items,
        "wiring_notes": wiring_notes,
        "grounding_notes": grounding_notes,
        "raw_signals": {
            "inline_matches": n_inline,
            "table_matches": n_table,
            "wiring_candidates": len(wiring_notes),
            "grounding_candidates": len(grounding_notes),
        },
    }


def make_requirements_summary(items: list[dict], wiring_notes: list[str]) -> str:
    """
    Build a compact ≤350-char summary paragraph from parsed requirements.

    Format: "<wiring prefix>. Minimum service: M1 V1 A1A; M2 V2 A2A; ..."
    Falls back to generic prefix if no wiring note is available.
    """
    # Compact spec list  e.g. "2001 12VDC 41A"
    spec_parts: list[str] = []
    for it in items:
        spec_parts.append(f"{it['model']} {_compact_voltage(it['voltage'])} {it['amps']}A")

    spec_str = "; ".join(spec_parts) if spec_parts else ""

    # Prefix: use first wiring note that mentions battery and is long enough
    # to be a complete thought (≥30 chars), trimmed to ~120 chars.
    prefix = ""
    for note in wiring_notes:
        nl = note.lower()
        if "battery" in nl and len(note) >= 30:
            trimmed = note[:120].rstrip().rstrip('.,;')
            prefix = trimmed
            break

    if not prefix:
        prefix = "Electrical power requirements"

    if spec_str:
        summary = f"{prefix}. Minimum service: {spec_str}."
    else:
        summary = f"{prefix}."

    return summary[:350]
