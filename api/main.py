import hashlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# ── Structured logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("keystone.api")

from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query as QueryParam, Request, Response, UploadFile
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization as _crypto_ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as DBSession

from audit import compute_entry_hash, verify_entry, validate_hmac_key
from auth import verify_password
from input_sanitizer import check_injection
from database import Base, SessionLocal, engine, get_db
from models import AuditEntry, Document, ManagedUser, Query, Session, User, UserManagementEvent
from schemas import (
    AssignTaskRequest,
    AuditResponse,
    AuditVerifyResponse,
    CreateVersionRequest,
    DismissTaskRequest,
    DocumentVersionResponse,
    GuidanceResponse,
    LoginRequest,
    LoginResponse,
    QueryRequest,
    QueryResponse,
    ReviewCommentRequest,
    ResolveTaskRequest,
    SourceResponse,
)
from cf_identity import (
    AppUser,
    get_current_user,
    get_cf_enabled,
    get_demo_sim_enabled,
    init_role_config,
    seed_managed_users,
)
from ingest_lib import (
    VALID_DOMAINS as _INGEST_VALID_DOMAINS,
    VALID_CONTENT_KINDS as _INGEST_VALID_CONTENT_KINDS,
    infer_domain as _ingest_infer_domain,
    mime_for as _ingest_mime_for,
    is_supported_mime as _ingest_is_supported_mime,
    build_chunks_pdf as _ingest_build_chunks_pdf,
    build_chunks_other as _ingest_build_chunks_other,
    sha256_file as _ingest_sha256_file,
)
from procedure_parse import parse_procedure, procedure_quality
from requirements_parse import make_requirements_summary, parse_requirements
from reranker import rerank_chunks
from seed import DEMO_QUERIES, seed_demo_data
from text_clean import clean_lines, make_summary
import hhem_scorer
import ollama_client
from compliance import router as compliance_router

# Maps scenario_key -> guidance template (from seeded data)
_GUIDANCE_TEMPLATES: dict = {q["scenario_key"]: q for q in DEMO_QUERIES}

# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

_SCENARIO_MIN_LEVEL: dict[str, int] = {
    "restricted": 1,   # officer+ only
}
_ROLE_LEVEL: dict[str, int] = {
    "member": 0,
    "custodian": 1,
    "officer": 1,
    "authority": 2,
}
_ROLE_PERMISSIONS: dict[str, frozenset] = {
    "member": frozenset({
        "query", "view_own_history", "view_own_audit", "view_documents",
    }),
    "officer": frozenset({
        "query", "view_own_history", "view_own_audit", "view_documents",
        "access_officer_restricted",
    }),
    "custodian": frozenset({
        "query", "view_own_history", "view_own_audit", "view_documents",
        "upload_to_staging", "edit_corpus_metadata", "system_health",
        "backup_restore", "view_all_audit", "view_staging_queue",
    }),
    "authority": frozenset({
        "query", "view_own_history", "view_own_audit", "view_documents",
        "access_officer_restricted", "upload_to_staging", "promote_document", "reject_document",
        "decision_review", "audit_export_governance", "view_all_audit",
        "view_all_user_activity", "approve_role_assignments",
        "case_management", "view_staging_queue", "edit_corpus_metadata",
    }),
}


def _has_perm(user: "AppUser", perm: str) -> bool:
    """Return True if user's role grants the specified permission. Fail-closed."""
    return perm in _ROLE_PERMISSIONS.get(user.role, frozenset())

# Fail-closed refusal used when role is denied by ACL.
_ACL_REFUSAL_GUIDANCE = {
    "type": "refusal",
    "reasonCode": "ACCESS_RESTRICTED",
    "title": "Access restricted",
    "message": (
        "The system cannot provide this content for the current role. "
        "No restricted source details are shown."
    ),
    "safeNextStep": "Contact a supervisor or document custodian if you believe access should be granted.",
    "hiddenSource": True,
}

# ---------------------------------------------------------------------------
# Chunk reranker — penalizes TOC/front-matter, boosts procedural content
# ---------------------------------------------------------------------------

_TOC_SIGNAL = re.compile(
    r'\btable[\s\-_]*of[\s\-_]*contents\b|\bcontents\b',
    re.IGNORECASE,
)
_SECTION_NUM = re.compile(r'\b\d+(\.\d+)+\b')
_PROCEDURAL = re.compile(
    r'\b(?:operat(?:ion|e|ing|ional)|procedur(?:e|es|al)|steps?\b|start(?:ing|up)?'
    r'|shutdown|troubleshoot(?:ing)?|maintenanc(?:e|ing)|alarm|warning|caution'
    r'|danger|decontaminat|decon|rescue|hazmat|response|deploy|activat|emergency'
    r'|instruction|guidanc|protocol)\b',
    re.IGNORECASE,
)

# Front-matter signals: vendor name, city/state, copyright, URLs, "user manual"
_FRONT_MATTER_SIGNAL = re.compile(
    r'rescueintellitech|katy[\s,]+tx|copyright|all\s+rights\s+reserved'
    r'|user[\s\-_]*manual|www\.\S+\.\S+|https?://\S+',
    re.IGNORECASE,
)

# Numbered step pattern: "1." / "Step 1" / "1)" at line start (boost signal)
_NUMBERED_STEP = re.compile(
    r'(?:^|\n)\s*(?:step\s+\d+|(?:\d+)[.)]\s)',
    re.IGNORECASE,
)

# ── Electrical-injury vs AED-shock-delivery disambiguation ──────────────────
# When a query is about treating an electric-shock victim (electrical_injury
# intent), penalize chunks about AED shock delivery (the device shocking the
# patient) so CPR/first-aid content ranks above AED-operation content.

# Triggers electrical_injury intent detection on the query side.
_ELECTRICAL_INJURY_INTENT = re.compile(
    r'\belectric(?:al)?\s+shock\b|\belectrocut(?:ed|ion)\b'
    r'|\bshock\s+victim\b|\belectrical\s+injur(?:y|ies)\b',
    re.IGNORECASE,
)

# Markers in a *chunk* that indicate AED shock-delivery content (not victim care).
_AED_DELIVERY_MARKERS = re.compile(
    r'\baed\b|\bdefibrillat(?:e|ion|or|ing)\b'
    r'|\bshock\s+(?:advised|delivered|indicated)\b'
    r'|\banalyzing\s+rhythm\b|\bshockable\s+rhythm\b',
    re.IGNORECASE,
)

# Markers in a *chunk* that confirm electrical-injury treatment content.
_ELECTRICAL_INJURY_MARKERS = re.compile(
    r'\belectrocut(?:ed|ion)\b|\belectric(?:al)?\s+(?:shock|burn|injur)\b'
    r'|\bcardiac\s+arrest\b|\bcpr\b|\bresuscitat',
    re.IGNORECASE,
)

# ── CPR procedure intent ──────────────────────────────────────────────────────
# When a query is about CPR/rescue breathing in the context of an electrical
# or cardiac emergency, boost chunks containing CPR procedure keywords and
# penalize chunks that are primarily about MAYDAY/radio procedures.

# Triggers CPR intent detection on the query side.
_CPR_INTENT = re.compile(
    r'\bcpr\b|\bcompress(?:ion|ions)\b|\brescue\s+breath(?:ing|s)?\b'
    r'|\bcardiac\s+arrest\b|\bresuscitat|\bchest\s+compress',
    re.IGNORECASE,
)

# Keywords in a chunk that confirm CPR procedure content.
_CPR_PROCEDURE_MARKERS = re.compile(
    r'\bcpr\b|\bcompress(?:ion|ions)\b|\brescue\s+breath|\bairway\b'
    r'|\bbreath(?:ing|s)?\b|\bchest\b|\baed\b|\bdefibrillat'
    r'|\bpulse\b|\bresuscitat|\bcardiac',
    re.IGNORECASE,
)

# Markers in a chunk that indicate primarily MAYDAY/radio/fire-ops content.
_MAYDAY_CONTENT_MARKERS = re.compile(
    r'\bmayday\b|\bpass\s+device\b|\bscba\b|\brit\b|\brapid\s+intervention',
    re.IGNORECASE,
)

# ── Requirements / specifications intent ──────────────────────────────────────
# When a query asks about requirements or specifications, boost chunks that
# carry a heading-like REQUIREMENTS/SPECIFICATIONS/CONNECTIONS line and
# penalize chunks that are dense safety-caution lists without such a heading
# AND without structured specification data (voltage/amperage/pressure tables).
# This avoids over-penalizing chunks that embed spec data inside CAUTION items
# (e.g. "CAUTION: Must use 12 VDC / 41 amps") while still demoting pure
# safety-warning lists that happened to match on the word "require".

# Triggers requirements intent detection on the query side.
# Covers explicit requirement/specification vocabulary AND specific
# electrical-unit terms (amps, VDC, voltage, minimum service) which appear
# almost exclusively in electrical-requirements queries in this domain.
_REQUIREMENTS_INTENT = re.compile(
    r'\b(?:electrical|power)\s+requirement(?:s)?\b'
    r'|\brequirement(?:s)?\b'
    r'|\bspecification(?:s)?\b'
    r'|\binstall(?:ation)?\s+req'
    r'|\belectrical\s+connections?\b'
    r'|\bamp\s+draw\b'
    r'|\bamps?\b'
    r'|\bVDC\b'
    r'|\bvoltage\b'
    r'|\bminimum\s+service\b'
    r'|\bpsi\b'
    r'|\bgpm\b'
    r'|\bflow\s+rate\b'
    r'|\bwater\s+(?:pressure|supply|connection)\b'
    r'|\bpressure\s+requirement',
    re.IGNORECASE,
)

# Heading-like signal: a line on its own whose text IS a requirements/
# specifications/connections section title.  The trailing \s*(?:\n|$) prevents
# false matches on mid-sentence constructs like "TO POSITIVE BATTERY CONNECTION,".
_REQUIREMENTS_HEADING_SIGNAL = re.compile(
    r'(?:^|\n)\s*'
    r'(?:ELECTRICAL|POWER|SYSTEM|INSTALLATION|MINIMUM|WATER|HYDRAULIC|PLUMBING|SERVICE)?\s*'
    r'(?:REQUIREMENTS?|SPECIFICATIONS?|ELECTRICAL\s+CONNECTIONS?|CONNECTIONS?|SUPPLY\s+REQUIREMENTS?)'
    r'\s*(?:\n|$)',
    re.MULTILINE,
)

# Dense safety-caution marker.
_SAFETY_CAUTION_DENSE = re.compile(
    r'\b(?:CAUTION|WARNING|DANGER)\s*:',
    re.IGNORECASE,
)

# Structured specification data pattern: numbered values with electrical/
# pressure/flow units.  Presence indicates the chunk carries actual spec data
# (even if embedded inside CAUTION items) and should not be penalized.
_SPEC_DATA_SIGNAL = re.compile(
    r'\b\d+\s*(?:VDC|VAC|V\b|amps?|A\b|psi|gpm|rpm|kPa|bar)\b',
    re.IGNORECASE,
)

# Pointer language: chunk redirects to another section instead of giving data.
# "Refer to Section 7", "See Section 4 for complete specifications", etc.
_POINTER_SIGNAL = re.compile(
    r'\b(?:refer(?:ence)?|see)\s+(?:to\s+)?(?:section|page)\s+\d'
    r'|for\s+(?:complete|more|full|additional)\s+'
    r'(?:information|details?|specifications?|requirements?)'
    r'\s*,?\s*(?:refer|see)\b',
    re.IGNORECASE,
)

# Explicit "requires N amps/VDC" pattern — distinguishes a spec section
# that states requirements inline ("2001 12 VDC requires 41 amps;") from a
# safety-caution section that embeds the same data in a table under CAUTION
# text ("require a minimum current rating of at least: 2001 12 VDC 41").
# The latter uses non-inline tabular format and produces zero matches here.
_EXPLICIT_REQUIRES_SPEC = re.compile(
    r'\b(?:requires?|rated\s+(?:at|for)|minimum\s+(?:of\s+)?)\s*\d+\s*'
    r'(?:amps?|amp|VDC|VAC|volts?|psi|gpm|rpm|kPa)\b',
    re.IGNORECASE,
)


def _rerank_score(chunk_index: int, text: str, fts_rank: float) -> float:
    """
    Deterministic reranker score (higher = prefer this chunk).

    Penalties:
      - "table of contents" / "contents" keyword  → ×0.10
      - Front-matter signals (vendor, city/state, copyright, URL, "user manual")
                                                   → ×0.05
      - Digit density > 8 %                        → ×(0.1 … 1.0)
      - Section-number density > 12 %              → ×0.20
      - First chunk of document (chunk_index == 0) → ×0.50

    Boosts:
      - Each procedural signal word                → ×(1.0 + min(n×0.25, 2.0))
      - Numbered-step patterns (Step 1, 1., 2))    → ×1.50
    """
    score = float(fts_rank)

    lower = text.lower()

    if _TOC_SIGNAL.search(lower):
        score *= 0.10

    if _FRONT_MATTER_SIGNAL.search(text):
        score *= 0.05

    n_chars = max(len(text), 1)
    digit_density = sum(1 for c in text if c.isdigit()) / n_chars
    if digit_density > 0.08:
        score *= max(0.10, 1.0 - digit_density * 4)

    n_words = max(len(text.split()), 1)
    n_section_nums = len(_SECTION_NUM.findall(text))
    if n_section_nums / n_words > 0.12:
        score *= 0.20

    # Penalize first chunk only when it truly looks like TOC/front-matter.
    # Short LRFD protocol files start procedural content in chunk 0 and must
    # NOT be penalised here — the _is_toc_like check gates this correctly.
    if chunk_index == 0 and not _PROCEDURAL.search(text):
        score *= 0.50

    n_proc = len(_PROCEDURAL.findall(text))
    if n_proc > 0:
        score *= 1.0 + min(n_proc * 0.25, 2.0)

    if _NUMBERED_STEP.search(text):
        score *= 1.50

    return score


def _rerank_score_no_digit_penalty(chunk_index: int, text: str, fts_rank: float) -> float:
    """Like _rerank_score but omits digit-density and section-number-density
    penalties.  Used for spec-data chunks under requirements intent: dense
    numeric content in a spec list is evidence of value, not TOC noise.
    """
    score = float(fts_rank)
    lower = text.lower()
    if _TOC_SIGNAL.search(lower):
        score *= 0.10
    if _FRONT_MATTER_SIGNAL.search(text):
        score *= 0.05
    if chunk_index == 0 and not _PROCEDURAL.search(text):
        score *= 0.50
    n_proc = len(_PROCEDURAL.findall(text))
    if n_proc > 0:
        score *= 1.0 + min(n_proc * 0.25, 2.0)
    if _NUMBERED_STEP.search(text):
        score *= 1.50
    return score


def _rerank_score_spec_table(chunk_index: int, text: str, fts_rank: float) -> float:
    """Like _rerank_score but also skips the front-matter and digit-density
    penalties.  Used when a chunk is identified as a spec table (≥3 lines
    containing spec-unit data).  Technical spec tables from device manuals
    often include the vendor address on the same page; the address text must
    not suppress the actual specification data.
    """
    score = float(fts_rank)
    lower = text.lower()
    # Only TOC keyword is still penalised — a spec table inside a TOC is
    # unlikely but that would be a true false-positive and worth suppressing.
    if _TOC_SIGNAL.search(lower):
        score *= 0.10
    if chunk_index == 0 and not _PROCEDURAL.search(text):
        score *= 0.50
    n_proc = len(_PROCEDURAL.findall(text))
    if n_proc > 0:
        score *= 1.0 + min(n_proc * 0.25, 2.0)
    if _NUMBERED_STEP.search(text):
        score *= 1.50
    return score


def _is_toc_like(chunk_index: int, text: str) -> bool:
    """Return True if chunk is almost certainly TOC or front-matter.

    Criteria (any one is sufficient):
      - Contains "table of contents" or bare "contents" heading
      - Section-number density > 12 % of words  (e.g. "1.1  Foo  1.2  Bar …")
      - Front-matter signals (vendor name, city/state, copyright, URL, user manual)
      - First chunk AND no procedural signals (title pages / cover sheets)
    """
    lower = text.lower()
    if _TOC_SIGNAL.search(lower):
        return True
    n_words = max(len(text.split()), 1)
    n_section_nums = len(_SECTION_NUM.findall(text))
    if n_section_nums / n_words > 0.12:
        return True
    if _FRONT_MATTER_SIGNAL.search(text):
        return True
    if chunk_index == 0 and not _PROCEDURAL.search(text):
        return True
    return False


# ---------------------------------------------------------------------------
# Retrieval engine (lexical scoring)
# ---------------------------------------------------------------------------

_STOP_WORDS = {
    '', 'a', 'an', 'the', 'is', 'are', 'our', 'what', 'how', 'show', 'me',
    'to', 'of', 'and', 'or', 'in', 'for', 'did', 'i', 'my', 'should',
    'right', 'now', 'do', 'does', 'it', 'this', 'that', 'be', 'was', 'were',
    'have', 'has', 'had', 'with', 'at', 'by', 'from', 'up', 'about', 'into',
    'on', 'if', 'no', 'not', 'so', 'as', 'we', 'you', 'they', 'their',
}

# High-frequency domain-generic terms that appear in nearly every document.
# Excluded from OR-expansion fallback queries so they don't pollute ranking
# when the primary AND-query returns zero results.
_OR_EXPANSION_STOP = _STOP_WORDS | {
    'procedure', 'procedures', 'protocol', 'protocols', 'guideline', 'guidelines',
    'care', 'method', 'methods', 'technique', 'techniques', 'step', 'steps',
    'process', 'treatment', 'management', 'use', 'using', 'used',
    'perform', 'performing', 'performed', 'follow', 'following',
    'approach', 'action', 'actions', 'activity', 'activities',
    # Generic operational/hydraulic/admin terms that appear in many apparatus
    # and medical documents — excluding them prevents off-domain OR-expansion
    # hits on partial token overlap.
    # e.g. "hydrant water supply flow rate" must not match the foam manual on
    # "water OR flow OR rate"; "covid vaccination schedule personnel" must not
    # match equipment manuals on "schedule OR personnel" alone.
    'water', 'supply', 'flow', 'rate',
    'schedule', 'personnel', 'staff', 'record', 'records',
    'system', 'systems', 'service',
    # Clearly out-of-scope / environment terms that should never yield
    # fire/medical corpus hits via OR expansion:
    # "weather forecast tomorrow" must not match EMR text on a single token.
    'weather', 'forecast', 'tomorrow', 'morning', 'tonight',
    'today', 'yesterday', 'date', 'time', 'hour', 'hours',
    # HR/admin terms beyond what was already covered:
    'payroll', 'salary', 'overtime', 'vacation', 'discipline', 'disciplinary',
    'employment', 'memo', 'staffing', 'station', 'shift',
    # Generic domain-context terms that appear in nearly every fire/structural
    # document and would cause off-domain OR-expansion hits when used alone or
    # mixed with out-of-scope tokens:
    #   "roof" alone → must not approve structural protocol without context
    #   "structural" alone in OR expansion → cross-domain false positive risk
    #     (e.g. "burn treatment after structural fire" must not match lrfd-003)
    #   "fire" alone → every LRFD doc mentions fire; too broad for OR expansion
    #   "after" → generic preposition with no domain signal
    #   "equipment" / "allocation" / "budget" → admin/inventory terms that
    #     appear in apparatus manuals and must not approve via single-token OR
    #   "annual" / "department" → financial/org terms that appear in admin
    #     documents (infobooks) but carry no procedural signal on their own;
    #     "annual budget", "department budget" should always refuse fail-closed
    'roof', 'structural', 'fire', 'after',
    'equipment', 'allocation', 'budget',
    'annual', 'department',
    # Generic EMR domain terms that appear in nearly every medical chunk.
    # OR-expansion on "patient" returns patient-movement, patient-assessment,
    # and patient-scoring content regardless of the actual medical topic.
    # Without this exclusion, a query like "how to treat a patient having a
    # heart attack" routes to the Glasgow Coma Scale table as its top hit.
    'patient', 'patients',
}

# Medical vocabulary gate — RC1b fix.
# Gate B uses this to distinguish genuine medical queries (AND-matched EMR
# result is plausibly on-topic) from coincidental word collisions like
# "chief" → "chief complaint" or "incident command" → ICS sections in EMR.
# If none of the query tokens appear here, Gate B refuses rather than
# returning EMR content to a non-medical_reference mode caller.
_MEDICAL_QUERY_TOKENS = frozenset({
    'cardiac', 'heart', 'pulse', 'cpr', 'resuscitation', 'resuscitate',
    'defibrillation', 'defibrillator', 'aed',
    'hemorrhage', 'haemorrhage', 'tourniquet', 'laceration',
    'bleed', 'bleeding',
    'airway', 'choking', 'asphyxia', 'asphyxiation',
    'fracture', 'fractures', 'splint', 'sprain',
    'burn', 'burns', 'scald',
    'seizure', 'seizures', 'convulsion', 'convulsions',
    'stroke', 'concussion', 'unconscious', 'unresponsive',
    'poison', 'poisoning', 'overdose', 'monoxide', 'narcotic',
    'anaphylaxis', 'anaphylactic', 'allergy', 'allergic', 'epinephrine',
    'hypothermia', 'frostbite', 'heatstroke', 'hyperthermia',
    'hypoperfusion', 'shock',
    'symptom', 'symptoms', 'nausea', 'vomiting', 'vital', 'vitals',
    'nosebleed', 'epistaxis', 'diabetes', 'diabetic', 'insulin', 'asthma',
    'chest', 'wound', 'wounds',
    'medical', 'medication', 'medicine', 'patient', 'patients',
    'triage', 'ems', 'paramedic', 'ambulance',
})

# Synonym expansion applied during OR-expansion fallback.
# Maps a normalised token to a list of equivalent FTS terms.
# Used so queries using lay or clinical language find the same chunks.
_QUERY_SYNONYMS: dict[str, list[str]] = {
    # ── Medical / EMR ──────────────────────────────────────────────────────────
    'nosebleed':   ['nosebleed', 'epistaxis'],
    'epistaxis':   ['epistaxis', 'nosebleed'],
    'cpr':         ['cpr', 'resuscitation', 'compressions'],
    'aed':         ['aed', 'defibrillator', 'defibrillation'],
    'defibrillator': ['defibrillator', 'aed', 'defibrillation'],
    'hypothermia': ['hypothermia', 'cold', 'exposure'],
    'burn':        ['burn', 'burns', 'thermal'],
    'burns':       ['burns', 'burn', 'thermal'],
    'fracture':    ['fracture', 'fractures', 'broken'],
    'bleeding':    ['bleeding', 'hemorrhage', 'haemorrhage'],
    'hemorrhage':  ['hemorrhage', 'haemorrhage', 'bleeding'],
    'haemorrhage': ['haemorrhage', 'hemorrhage', 'bleeding'],
    'shock':       ['shock', 'hypoperfusion'],
    'seizure':     ['seizure', 'seizures', 'convulsion'],
    'seizures':    ['seizures', 'seizure', 'convulsion'],
    'convulsion':  ['convulsion', 'seizure', 'seizures'],
    'stroke':      ['stroke', 'cerebrovascular'],
    'choking':     ['choking', 'obstruction', 'airway'],
    'unconscious': ['unconscious', 'unresponsive'],
    'unresponsive':['unresponsive', 'unconscious'],
    'overdose':    ['overdose', 'poisoning', 'narcotic'],
    'chest':       ['chest', 'cardiac', 'heart'],
    # ── Fire ops / LRFD operational ────────────────────────────────────────────
    'mayday':      ['mayday', 'distress'],
    'rit':         ['rit', 'rapid', 'intervention'],
    # "rapid intervention team" — maps back to rit so it finds lrfd-007 via OR.
    'rapid':       ['rapid', 'rit', 'intervention'],
    'declaration': ['declaration', 'mayday', 'distress'],  # "emergency declaration"
    # "snow load" — lrfd-001 covers roof load (snow is the most common roof load).
    'snow':        ['snow', 'roof', 'load'],
    # ── Apparatus / equipment ──────────────────────────────────────────────────
    # FoamPro brand name does not always stem predictably; expand to generic terms.
    'foampro':     ['foam', 'foampro', 'proportioning'],
    'foam':        ['foam', 'foampro', 'proportioning'],
    # Decontamination short forms + equipment.
    'decon':       ['decon', 'decontamination', 'decontaminate'],
    'decontamination': ['decontamination', 'decon', 'decontaminate'],
    # Decon washer equipment — operation section uses "wash" not "washer".
    'washer':      ['washer', 'wash'],
    # ── Structural ─────────────────────────────────────────────────────────────
    'collapse':    ['collapse', 'zone', 'structural'],
    'structural':  ['structural', 'triage', 'collapse'],
    # ── OHS / Industrial safety ────────────────────────────────────────────────
    # Abbreviations and common terms from Alberta OHS Code
    'lel':         ['lel', 'lower explosive limit', 'flammable', 'explosive'],
    'uel':         ['uel', 'upper explosive limit', 'flammable', 'explosive'],
    'ppe':         ['ppe', 'personal protective equipment', 'protection'],
    'oel':         ['oel', 'occupational exposure limit', 'exposure limit'],
    'twas':        ['twa', 'time weighted average', 'exposure limit'],
    'twa':         ['twa', 'time weighted average', 'exposure limit'],
    'stel':        ['stel', 'short term exposure limit', 'exposure limit'],
    'loto':        ['loto', 'lockout', 'tagout', 'hazardous energy', 'isolation'],
    'lockout':     ['lockout', 'loto', 'tagout', 'hazardous energy'],
    'tagout':      ['tagout', 'loto', 'lockout', 'hazardous energy'],
    'scba':        ['scba', 'self contained breathing', 'breathing apparatus', 'respirator'],
    'sar':         ['sar', 'supplied air respirator', 'respirator'],
    'whmis':       ['whmis', 'hazardous materials', 'workplace hazardous'],
    'sds':         ['sds', 'safety data sheet', 'msds'],
    'msds':        ['msds', 'material safety data sheet', 'sds'],
    'h2s':         ['h2s', 'hydrogen sulfide', 'hydrogen sulphide', 'sour gas'],
    'confined':    ['confined', 'confined space', 'restricted space'],
    'fall':        ['fall', 'fall protection', 'fall arrest', 'guardrail'],
    'harness':     ['harness', 'fall arrest', 'full body harness', 'lanyard'],
    'lanyard':     ['lanyard', 'harness', 'fall arrest'],
    'guardrail':   ['guardrail', 'guard rail', 'fall protection', 'barrier'],
    'scaffold':    ['scaffold', 'scaffolding', 'scaffolds', 'platform'],
    'scaffolding': ['scaffolding', 'scaffold', 'scaffolds', 'platform'],
    'trench':      ['trench', 'excavation', 'shoring', 'trenching'],
    'excavation':  ['excavation', 'trench', 'shoring', 'excavating'],
    'shoring':     ['shoring', 'trench', 'excavation'],
    'ventilation': ['ventilation', 'ventilating', 'airflow', 'air supply'],
    'noise':       ['noise', 'hearing', 'decibel', 'dba', 'audiometric'],
    'hearing':     ['hearing', 'noise', 'decibel', 'audiometric'],
    'crane':       ['crane', 'hoist', 'rigging', 'lifting'],
    'hoist':       ['hoist', 'crane', 'rigging', 'lifting'],
    'rigging':     ['rigging', 'crane', 'hoist', 'sling'],
    'chemical':    ['chemical', 'hazardous', 'toxic', 'substance'],
    'hazardous':   ['hazardous', 'chemical', 'toxic', 'dangerous'],
    'impairment':  ['impairment', 'impaired', 'fitness', 'duty'],
    'heights':     ['heights', 'height', 'fall protection', 'elevated'],
    'height':      ['height', 'heights', 'fall protection', 'elevated'],
}

_EVIDENCE_THRESHOLD = 1

# Minimum ts_rank_cd score accepted from Postgres FTS.
# Chunks ranked below this are near-zero-relevance noise and are discarded
# before reranking.  Applies to both AND and OR-expansion FTS paths.
# 0.05 excludes "procedure"-stem matches in unrelated documents while
# retaining secondary-topic chunks that rank 0.1-0.2.
_FTS_RANK_MIN = 0.05

# ---------------------------------------------------------------------------
# Corpus root (used by retrieval, document endpoint, and availability check)
# ---------------------------------------------------------------------------

_CORPUS_ROOT = Path(os.environ.get("CORPUS_ROOT", "/srv/keystone-corpus"))

# Extensions that the /document endpoint can actually serve.
_SUPPORTED_DOC_EXTENSIONS = frozenset({".pdf", ".docx", ".txt"})

# ---------------------------------------------------------------------------
# Relevance gate — deterministic token-overlap check applied before returning
# approved guidance.  Prevents unrelated documents from being approved.
# ---------------------------------------------------------------------------

# Relevance gate disabled — will be replaced by HHEM hallucination scoring
# (KDAT-086). Token-overlap caused over-refusal on regulatory text where
# question vocabulary diverges from statute language.
# Gate code and _relevance_score function are preserved for future reference.
_RELEVANCE_THRESHOLD = 0.0

# Disabled alongside _RELEVANCE_THRESHOLD (was 0.18).
_RELEVANCE_THRESHOLD_OR_OPERATIONAL = 0.0

# Multi-answer configuration.
# Maximum number of distinct-document answers to return (including primary).
_MULTI_ANSWER_MAX: int = 3
# Normalised rerank score thresholds (secondary_score / primary_score).
# "Strong match" ≥ 0.85 — nearly as good as the primary answer.
# "Related" ≥ 0.72 — meaningfully relevant but weaker signal.
# Below 0.72 — suppressed; not included in the answers list.
_MULTI_ANSWER_STRONG_THRESHOLD: float = 0.85
_MULTI_ANSWER_RELATED_THRESHOLD: float = 0.72

# KDAT-064d: Hybrid retrieval weights.
# Equal weight — regulatory text benefits from semantic matching alongside
# keyword matching (was 60/40 FTS/vector).
_HYBRID_W_FTS     = 0.50   # FTS normalized score weight
_HYBRID_W_VEC     = 0.50   # vector cosine similarity weight
# Minimum raw cosine similarity for a vector row to participate in the merge.
# Rows below this floor are dropped before normalization so that a batch of
# uniformly low-similarity results cannot inflate after min-max scaling and
# push irrelevant content into the merged ranking.
_HYBRID_VEC_FLOOR = 0.20

# KDAT-064e: LLM answer generation from evidence pack.
# The prompt enforces evidence-only answering with explicit citation rules.
# The LLM is called AFTER all policy gates pass and sees only ACL-filtered,
# status-filtered, reranked chunks.  It never runs on refused queries.
_LLM_SYSTEM_PROMPT = (
    "You are a safety procedure assistant. "
    "Answer the question using ONLY the evidence provided below. "
    "Do not use any prior knowledge.\n\n"
    "Rules:\n"
    "- State the answer directly and concisely. Do not add a disclaimer or "
    "preamble when the evidence supports a clear answer.\n"
    "- Every factual claim must cite the source document title and page.\n"
    "- If the evidence contains numbered steps, preserve the step numbers and order.\n"
    "- The evidence may come from regulatory explanation guides, training manuals, "
    "codes of practice, or safety supplements. All of these are valid sources. "
    "Regulatory explanation guides explain legal requirements through commentary "
    "and examples — extract the concrete requirements from them.\n"
    "- If the evidence discusses the topic but uses indirect or formal language, "
    "extract and state the relevant requirements clearly. Do not hedge when the "
    "evidence contains information that answers the question, even partially.\n"
    "- Only say \"The available evidence does not address this question.\" when "
    "the evidence is truly about a completely different topic and contains NO "
    "information relevant to the question.\n"
    "- Do not speculate or add information beyond the evidence.\n"
    "- Use clear, direct language appropriate for workplace safety."
)


def _build_evidence_pack(top5_rows: list) -> str:
    """Build a labeled text string from top-5 reranked chunk rows.

    Each chunk is prefixed with its source title and page/chunk locator.
    Input rows: 7-tuples (rel_path, title, chunk_index, text, score, page, domain).
    """
    parts = []
    for rel_path, title, chunk_idx, chunk_text, score, page, domain in top5_rows:
        loc = f"page {page}" if page is not None else f"chunk {chunk_idx}"
        parts.append(f"[Source: {title}, {loc}]\n{chunk_text.strip()}")
    return "\n\n---\n\n".join(parts)


def _validate_llm_output(answer: str, evidence_titles: list[str]) -> str:
    """
    Basic output validation: check that the LLM didn't
    fabricate document references not in the evidence pack.
    This is a lightweight check, not a full citation parser.
    """
    # If the answer mentions phrases that suggest injection got through,
    # return a safe fail-closed response instead.
    injection_signals = [
        'all documents in', 'list of documents',
        'here are the documents', 'document titles:',
        'i have access to', 'my instructions',
        'system prompt', 'i was told to',
    ]
    answer_lower = answer.lower()
    for signal in injection_signals:
        if signal in answer_lower:
            logger.warning("LLM output injection signal detected: %r", signal)
            return ("The available evidence does not fully address "
                    "this question.")
    # Warn if the response mentions document titles not in the evidence pack.
    # This can indicate hallucination or corpus leakage; does not block the response.
    if evidence_titles:
        evidence_titles_lower = {t.lower() for t in evidence_titles}
        # Look for quoted or bracketed strings that look like document titles
        import re as _re
        cited = _re.findall(r'\[Source:\s*([^\],]+)', answer) + _re.findall(r'"([^"]{10,80})"', answer)
        for title in cited:
            if title.strip().lower() not in evidence_titles_lower:
                logger.warning(
                    "LLM output references title not in evidence pack: %r", title[:120]
                )
    return answer


def _add_llm_answer(guidance: dict, question: str, top5: list) -> None:
    """Attempt LLM synthesis from evidence pack.  Mutates guidance in-place.

    Adds:
      guidance["answer"]        — LLM text or deterministic summary fallback
      guidance["answer_source"] — "llm" | "deterministic"
      guidance["confidence"]["gen_model"]       — model name used
      guidance["confidence"]["gen_latency_ms"]  — wall-clock ms for generate()
      guidance["confidence"]["evidence_titles"] — titles of chunks fed to LLM
    """
    from input_sanitizer import sanitize_query_for_llm
    evidence = _build_evidence_pack(top5)
    safe_question = sanitize_query_for_llm(question)
    user_prompt = (
        "[USER QUESTION]\n"
        f"{safe_question}\n"
        "[/USER QUESTION]\n\n"
        "[EVIDENCE FROM APPROVED DOCUMENTS]\n"
        f"{evidence}\n"
        "[/EVIDENCE FROM APPROVED DOCUMENTS]"
    )
    t0 = time.monotonic()
    answer = ollama_client.generate(_LLM_SYSTEM_PROMPT, user_prompt)
    gen_ms = int((time.monotonic() - t0) * 1000)
    evidence_titles = [row[1] for row in top5]
    if answer:
        answer = _validate_llm_output(answer, evidence_titles)
        guidance["answer"] = answer
        guidance["answer_source"] = "llm"
    else:
        guidance["answer"] = guidance.get("summary", "")
        guidance["answer_source"] = "deterministic"
    conf = guidance.setdefault("confidence", {})
    conf["gen_model"]       = ollama_client.GEN_MODEL
    conf["gen_latency_ms"]  = gen_ms
    conf["evidence_titles"] = evidence_titles


_LLM_HEDGE_PHRASES = [
    "does not address this question",
    "does not fully address this question",
    "does not address the specific",
    "does not directly address",
    "does not contain relevant information",
    "cannot be answered from the evidence",
    "no relevant information",
    "cannot find any relevant",
    "not relevant to",
    "the evidence does not",
    "no information about",
    "the provided evidence does not",
]

_LLM_REFUSAL_ON_HEDGE = {
    "type": "refusal",
    "reasonCode": "INSUFFICIENT_EVIDENCE",
    "title": "No relevant guidance found",
    "message": (
        "The available documents do not contain relevant guidance for this question. "
        "Ask about a specific safety procedure, regulation, or hazard covered in the corpus."
    ),
    "safeNextStep": "Consult your supervisor or safety officer for guidance outside the corpus.",
    "hiddenSource": False,
}


def _llm_hedges(answer: str) -> bool:
    """Return True if the LLM answer signals that the evidence is irrelevant."""
    lower = answer.lower()
    return any(phrase in lower for phrase in _LLM_HEDGE_PHRASES)


_NO_RELEVANT_PROCEDURE_REFUSAL = {
    "type": "refusal",
    "reasonCode": "NO_RELEVANT_PROCEDURE",
    "title": "No approved guidance found for this query",
    "message": (
        "Result withheld — evidence confidence was insufficient for this query. "
        "The matched content did not contain enough terms relevant to your question."
    ),
    "safeNextStep": "Ask about a specific procedure, equipment, or emergency by name.",
    "hiddenSource": False,
}


def _relevance_score(question: str, excerpt: str) -> float:
    """
    Token-overlap relevance score.

    score = |question_tokens ∩ excerpt_tokens| / max(1, |question_tokens|)

    Deterministic, no network calls.  Returns 1.0 when the question has no
    meaningful tokens (empty question → don't gate).
    """
    q_tokens = _tokenize(question)
    if not q_tokens:
        return 1.0
    e_tokens = _tokenize(excerpt)
    return len(q_tokens & e_tokens) / len(q_tokens)


def _doc_available(doc_id: str) -> bool:
    """
    True iff the corpus document file exists on disk with a supported extension.

    Used to populate guidance.document.available so the console can decide
    whether to render the "Open document" button.
    """
    if not doc_id:
        return False
    target = (_CORPUS_ROOT / "active" / doc_id).resolve()
    return target.exists() and target.suffix.lower() in _SUPPORTED_DOC_EXTENSIONS


_STEM_SUFFIXES = (
    'ations', 'ating', 'ation', 'ated', 'ting', 'tion',
    'ment', 'ness', 'ance', 'ence', 'ing', 'ize', 'ise',
    'ate', 'ed', 'er', 'es', 's',
)


def _stem(word: str) -> str:
    """Minimal suffix stripping for relevance gate token matching.

    Approximates common Porter reductions without any external dependency.
    Ensures the query-side tokenizer aligns with Postgres's built-in English
    stemmer so that e.g. "decontaminate" matches a chunk containing
    "decontamination".  Minimum stem length: 4 characters.
    """
    for sfx in _STEM_SUFFIXES:
        if word.endswith(sfx) and len(word) - len(sfx) >= 4:
            return word[:-len(sfx)]
    return word


def _tokenize(text: str) -> set[str]:
    return {_stem(t) for t in re.split(r'\W+', text.lower()) if t not in _STOP_WORDS and len(t) > 2}


def _lexical_score(terms: set[str], doc: Document) -> int:
    corpus = f"{doc.title} {doc.section} {doc.excerpt or ''}".lower()
    return sum(1 for t in terms if t in corpus)


def _build_multi_answers(
    reranked: list,
    primary_rel: str,
    primary_rerank: float,
    primary_doc: dict,
    primary_summary: str,
    primary_excerpt: str,
    question: str,
    relevance_threshold: float,
    content_kind_map: dict,
) -> list[dict]:
    """Return a list of per-document answer dicts for multi-answer ranked responses.

    The first entry is always the primary answer.  Subsequent entries are the
    best chunks from distinct documents that pass both the relevance gate and
    the normalised-score threshold.  Returns an empty list when no secondary
    answers qualify (caller should omit the 'answers' key in that case).

    Each entry format:
        {rank, confidence, documentId, title, page, chunkIndex, domain,
         content_kind, summary, excerpt}

    confidence is one of "Strong match" (≥ _MULTI_ANSWER_STRONG_THRESHOLD)
    or "Related" (≥ _MULTI_ANSWER_RELATED_THRESHOLD).  Raw scores are not
    exposed to callers.
    """
    if primary_rerank <= 0:
        return []

    secondary: list[dict] = []
    seen_docs: set[str] = {primary_rel}

    for row in reranked[1:]:
        rel, title, ci, txt, rank, pg, dom = row
        if rel in seen_docs:
            continue
        if _is_toc_like(ci, txt):
            continue
        ck = content_kind_map.get(rel, "procedure")
        row_rerank = _rerank_score(ci, txt, rank) * (1.15 if ck == "procedure" else 1.0)
        norm = min(1.0, row_rerank / primary_rerank)
        if norm < _MULTI_ANSWER_RELATED_THRESHOLD:
            continue
        clean_sec = clean_lines(txt)
        if _relevance_score(question, clean_sec) < relevance_threshold:
            continue
        label = "Strong match" if norm >= _MULTI_ANSWER_STRONG_THRESHOLD else "Related"
        eff_pg = pg if pg is not None else ci
        secondary.append({
            "rank": len(secondary) + 2,
            "confidence": label,
            "documentId": rel,
            "title": title,
            "page": eff_pg,
            "chunkIndex": ci,
            "domain": dom,
            "content_kind": ck,
            "summary": make_summary(clean_sec),
            "excerpt": clean_sec[:1500],
        })
        seen_docs.add(rel)
        if len(secondary) >= _MULTI_ANSWER_MAX - 1:
            break

    if not secondary:
        return []

    primary_entry: dict = {
        "rank": 1,
        "confidence": "Strong match",
        "documentId": primary_doc.get("documentId", ""),
        "title": primary_doc.get("title", ""),
        "page": primary_doc.get("page", 0),
        "chunkIndex": primary_doc.get("chunkIndex", 0),
        "domain": primary_doc.get("domain", ""),
        "content_kind": primary_doc.get("content_kind", "procedure"),
        "summary": primary_summary,
        "excerpt": primary_excerpt,
    }
    return [primary_entry] + secondary


def _hybrid_merge(
    fts_rows: list,
    vec_rows: list,
    w_fts: float,
    w_vec: float,
    vec_floor: float,
) -> "tuple[list, str]":
    """
    Merge FTS and vector result sets into a single ranked list.

    Both inputs are 7-tuples: (rel_path, title, chunk_index, text,
                                score, page, domain).
    Returns (merged_rows, retrieval_source).
      retrieval_source: "fts_only" | "vector_only" | "hybrid"
      merged_rows: same 7-tuple shape; score = weighted normalized combined score.
    """
    # Drop vector rows below minimum cosine similarity floor before normalization
    # so that low-signal entries don't inflate after min-max scaling.
    vec_rows = [r for r in vec_rows if r[4] >= vec_floor]

    has_fts = bool(fts_rows)
    has_vec = bool(vec_rows)

    if not has_vec:
        return list(fts_rows), "fts_only"
    if not has_fts:
        return list(vec_rows), "vector_only"

    # Min-max normalize scores within each set independently.
    fts_mn = min(r[4] for r in fts_rows)
    fts_mx = max(r[4] for r in fts_rows)
    vec_mn = min(r[4] for r in vec_rows)
    vec_mx = max(r[4] for r in vec_rows)

    def _norm_fts(s: float) -> float:
        return (s - fts_mn) / (fts_mx - fts_mn) if fts_mx > fts_mn else 1.0

    def _norm_vec(s: float) -> float:
        return (s - vec_mn) / (vec_mx - vec_mn) if vec_mx > vec_mn else 1.0

    # Merge by (rel_path, chunk_index) key.
    # A chunk present in both sets accumulates both weighted contributions.
    # A chunk present in only one set carries only that contribution.
    merged: dict = {}

    for row in fts_rows:
        key = (row[0], row[2])
        merged[key] = {"row": row, "score": w_fts * _norm_fts(row[4])}

    for row in vec_rows:
        key = (row[0], row[2])
        if key in merged:
            merged[key]["score"] += w_vec * _norm_vec(row[4])
        else:
            merged[key] = {"row": row, "score": w_vec * _norm_vec(row[4])}

    result = sorted(
        [
            (e["row"][0], e["row"][1], e["row"][2],
             e["row"][3], e["score"],  e["row"][5], e["row"][6])
            for e in merged.values()
        ],
        key=lambda r: r[4],
        reverse=True,
    )
    return result, "hybrid"


def _corpus_fts_retrieve(
    question: str, mode: str, db: DBSession,
    domain_filter: "list[str] | None" = None,
    requester_role: str = "member",
) -> "tuple[dict, str, list, list] | None":
    """
    Postgres FTS retrieval from corpus_chunks.

    Returns None if corpus is empty — caller falls through to lexical fixtures.
    Returns a refusal tuple if corpus is non-empty but no FTS hits are found.

    domain_filter: when provided, only match documents whose domain is in
    the list.  None (default) = no domain restriction.
    requester_role: used for per-document min_role gate (additive check).
    """
    try:
        count = db.execute(text("SELECT COUNT(*) FROM corpus_chunks LIMIT 1")).scalar()
    except Exception:
        # Table may not exist on first startup before schema migration runs.
        # Must rollback: a failed SQL statement aborts the psycopg2 transaction,
        # which would cause every subsequent query in the same session to fail.
        db.rollback()
        return None

    if not count:
        return None  # corpus not yet ingested — fall through to lexical fixtures

    _domain_clause = "AND cd.domain = ANY(:domains)" if domain_filter else ""
    _domain_params: dict = {"domains": domain_filter} if domain_filter else {}

    _requester_level = _ROLE_LEVEL.get(requester_role, 0)

    _FTS_SQL = f"""
        SELECT
            cd.rel_path,
            cd.title,
            cc.chunk_index,
            cc.text,
            ts_rank_cd(cc.tsv, query) AS rank,
            cc.page,
            cd.domain
        FROM corpus_chunks cc
        JOIN corpus_documents cd ON cd.id = cc.doc_id
        CROSS JOIN websearch_to_tsquery('english', :q) query
        WHERE cc.tsv @@ query
          {_domain_clause}
          AND CASE cd.min_role
                WHEN 'member'    THEN 0
                WHEN 'custodian' THEN 0
                WHEN 'officer'   THEN 1
                WHEN 'authority' THEN 2
                ELSE 0 END <= :req_level
          AND (cd.status_override IS DISTINCT FROM 'restricted'
               OR :req_level >= 1)
        ORDER BY rank DESC
        LIMIT 50
    """
    _fts_params = {"q": question, "req_level": _requester_level, **_domain_params}
    rows = db.execute(text(_FTS_SQL), _fts_params).fetchall()
    # Discard near-zero-relevance noise from the AND query.
    rows = [r for r in rows if r[4] >= _FTS_RANK_MIN]

    # OR-expansion fallback: when AND-FTS returns nothing, retry with any matching term.
    # This handles equipment questions where brand/type keywords only appear in the
    # title/front-matter while operational content uses generic terms.
    #
    # Generic terms (procedure, protocol, care, …) are excluded via
    # _OR_EXPANSION_STOP so a high-frequency word doesn't pollute ranking and
    # let an unrelated document out-score the correct one.
    #
    # Synonym expansion: lay/clinical synonyms are folded so that e.g.
    # "nosebleed" also matches chunks that only contain "epistaxis".
    _used_or_fts = False
    if not rows:
        raw_tokens = [t for t in re.split(r'\W+', question.lower())
                      if t not in _OR_EXPANSION_STOP and len(t) > 2]
        # RC3: for long queries, sort tokens by corpus specificity (IDF) before
        # applying the 8-token cap.  Positional selection caused long narrative
        # queries (e.g. E09) to drop rare key terms like MAYDAY and RIT that
        # appear late in the sentence, using common scene-setting words instead.
        # One DB round trip; only runs when AND FTS already returned 0 rows.
        _OR_EXPANSION_CAP = 8
        if len(raw_tokens) > _OR_EXPANSION_CAP:
            try:
                placeholders = ", ".join(f":_idf{i}" for i in range(len(raw_tokens)))
                freq_rows = db.execute(
                    text(f"""
                        SELECT unnested.tok, COUNT(cc.id) AS df
                        FROM (SELECT unnest(ARRAY[{placeholders}]) AS tok) unnested
                        LEFT JOIN corpus_chunks cc
                            ON cc.tsv @@ to_tsquery('english', unnested.tok)
                        GROUP BY unnested.tok
                    """),
                    {f"_idf{i}": t for i, t in enumerate(raw_tokens)},
                ).fetchall()
                _pos = {t: i for i, t in enumerate(raw_tokens)}
                _df_map = {r[0]: r[1] for r in freq_rows}
                # Sort key: tokens absent from the corpus (df=0) are last —
                # they won't match any chunk so they waste OR-expansion slots.
                # Among present tokens, sort ascending by df (rarest first).
                raw_tokens = sorted(
                    raw_tokens,
                    key=lambda t: (0, _df_map[t], _pos[t]) if _df_map.get(t, 0) > 0
                                  else (1, 0, _pos[t]),
                )
            except Exception:
                db.rollback()
                # Fall back to positional selection on error.
        # Expand synonyms: replace each token with its synonym cluster (deduped).
        expanded: list[str] = []
        seen: set[str] = set()
        for tok in raw_tokens[:_OR_EXPANSION_CAP]:
            for syn in _QUERY_SYNONYMS.get(tok, [tok]):
                if syn not in seen:
                    expanded.append(syn)
                    seen.add(syn)
        if expanded:
            or_question = " OR ".join(expanded)
            try:
                or_rows = db.execute(text(_FTS_SQL), {"q": or_question, "req_level": _requester_level, **_domain_params}).fetchall()
                # Apply same rank floor to OR results.
                rows = [r for r in or_rows if r[4] >= _FTS_RANK_MIN]
                _used_or_fts = bool(rows)
            except Exception:
                db.rollback()

    # ── KDAT-064d: Hybrid vector retrieval ────────────────────────────────────
    # Runs after FTS + OR-expansion so that:
    #   - vec results supplement FTS hits (hybrid case)
    #   - vec results can recover when FTS returns 0 (vector_only case)
    # Graceful degradation: ollama_client.embed() returns None on any failure;
    # vec_rows stays empty and merge returns (fts_rows, "fts_only") unchanged.
    #
    # Vector SQL replicates ALL FTS WHERE clause filters verbatim:
    #   ACL, restricted, draft, superseded, domain.
    _retrieval_source = "fts_only"
    _query_vec = ollama_client.embed(question)
    _vec_rows: list = []
    if _query_vec is not None:
        _VEC_SQL = f"""
            SELECT
                cd.rel_path,
                cd.title,
                cc.chunk_index,
                cc.text,
                1.0 - (cc.embedding <=> CAST(:embedding AS vector)) AS cosine_sim,
                cc.page,
                cd.domain
            FROM corpus_chunks cc
            JOIN corpus_documents cd ON cd.id = cc.doc_id
            WHERE cc.embedding IS NOT NULL
              {_domain_clause}
              AND CASE cd.min_role
                    WHEN 'member'    THEN 0
                    WHEN 'custodian' THEN 0
                    WHEN 'officer'   THEN 1
                    WHEN 'authority' THEN 2
                    ELSE 0 END <= :req_level
              AND (cd.status_override IS DISTINCT FROM 'restricted'
                   OR :req_level >= 1)
              AND (cd.status_override IS DISTINCT FROM 'draft')
              AND (cd.status_override IS DISTINCT FROM 'superseded'
                   OR :mode != 'operational')
            ORDER BY cc.embedding <=> CAST(:embedding AS vector)
            LIMIT 50
        """
        _pg_vec = "[" + ",".join(str(v) for v in _query_vec) + "]"
        try:
            _vec_rows = db.execute(
                text(_VEC_SQL),
                {"embedding": _pg_vec, "req_level": _requester_level,
                 "mode": mode, **_domain_params},
            ).fetchall()
        except Exception:
            db.rollback()
            _vec_rows = []

    # When OR-expansion fires, FTS results are noisy (AND matched nothing);
    # vector search is the more reliable signal in that case.
    _w_fts = 0.30 if _used_or_fts else _HYBRID_W_FTS
    _w_vec = 0.70 if _used_or_fts else _HYBRID_W_VEC
    rows, _retrieval_source = _hybrid_merge(
        rows, _vec_rows, _w_fts, _w_vec, _HYBRID_VEC_FLOOR
    )
    # ── End hybrid block ──────────────────────────────────────────────────────

    if not rows:
        guidance = {
            "type": "refusal",
            "reasonCode": "INSUFFICIENT_EVIDENCE",
            "title": "No approved departmental guidance found",
            "message": (
                "No approved departmental guidance found for this query. "
                "The corpus does not contain a document that matches the terms in your question."
            ),
            "safeNextStep": "Rephrase your question with specific procedure or equipment names, or consult your supervisor.",
            "hiddenSource": False,
        }
        return guidance, "refused", [], []

    # ── All-generic-query guard ────────────────────────────────────────────────
    # If every token in the question (after removing _OR_EXPANSION_STOP) is
    # generic (nothing specific to a procedure, equipment, or emergency), the
    # FTS hit is likely driven by a domain-ubiquitous word (e.g. "protocol",
    # "roof", "equipment") that appears in every document.  Refuse fail-closed
    # rather than returning potentially misleading guidance.
    #
    # Examples caught here:
    #   "what is the protocol"  → tokens after OR-stop = {}   → refuse
    #   "roof"                  → tokens after OR-stop = {}   → refuse
    #   "budget allocation equipment" → tokens = {}           → refuse
    #
    # NOT caught (correctly passes through):
    #   "mayday declaration"    → tokens = {mayday, declaration}
    #   "rit activation"        → tokens = {rit, activation}
    #   "roof load assessment"  → tokens = {load (filtered), assessment} → {assessment}
    _meaningful_tokens = [
        t for t in re.split(r'\W+', question.lower())
        if t not in _OR_EXPANSION_STOP and len(t) > 2
    ]
    if not _meaningful_tokens:
        return {
            "type": "refusal",
            "reasonCode": "INSUFFICIENT_EVIDENCE",
            "title": "No approved departmental guidance found",
            "message": (
                "No approved departmental guidance found for this query. "
                "The question does not contain specific enough terms to retrieve "
                "a procedure, equipment document, or emergency protocol."
            ),
            "safeNextStep": "Ask about a specific procedure, equipment, or emergency by name.",
            "hiddenSource": False,
        }, "refused", [], []

    # Fetch content_kind for all matched documents in one query.
    # Used by intent-aware rerankers to apply kind-specific multipliers
    # without changing the row tuple structure.
    _matched_rels = list({r[0] for r in rows})
    try:
        _ck_rows = db.execute(
            text("SELECT rel_path, content_kind FROM corpus_documents"
                 " WHERE rel_path = ANY(:rels)"),
            {"rels": _matched_rels},
        ).fetchall()
        _content_kind_map: dict[str, str] = {r[0]: r[1] for r in _ck_rows}
    except Exception:
        db.rollback()
        _content_kind_map = {}

    # ── Rerank: generic quality filter before LLM evidence pack ──────────────
    # LRFD-specific reranker removed in dev/keystone-next.
    # See feature/pilot-enhancements for original fire-service intent detection
    # (electrical_injury, CPR, MAYDAY, requirements), domain routing, and
    # synonym boosting.
    _chunk_dicts = [
        {
            'rel_path': r[0], 'title': r[1], 'chunk_index': r[2],
            'text': r[3], 'score': r[4], 'page': r[5], 'domain': r[6],
        }
        for r in rows
    ]
    _reranked_dicts = rerank_chunks(_chunk_dicts, question, top_k=len(rows))
    reranked = [
        (d['rel_path'], d['title'], d['chunk_index'], d['text'],
         d['score'], d['page'], d['domain'])
        for d in _reranked_dicts
    ]

    top_rel, top_title, top_chunk, top_text, _fts_rank, top_page, _top_domain = reranked[0]
    _top_content_kind: str = _content_kind_map.get(top_rel, "procedure")
    _toc_filtered = False
    _used_fallback = False

    # If the best candidate still looks like TOC, try a document-level fallback:
    # fetch the first procedural (non-TOC) chunks from the same matched docs.
    if _is_toc_like(top_chunk, top_text):
        _toc_filtered = True
        matched_docs = list({r[0] for r in reranked[:5]})
        fallback_rows = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.chunk_index, cc.text, cc.page
                FROM corpus_chunks cc
                JOIN corpus_documents cd ON cd.id = cc.doc_id
                WHERE cd.rel_path = ANY(:docs)
                  AND cc.chunk_index > 0
                ORDER BY cd.rel_path, cc.chunk_index ASC
                LIMIT 40
            """),
            {"docs": matched_docs},
        ).fetchall()

        # Rerank with a neutral base score; procedural boosts differentiate them.
        _BASE = 0.001
        fallback_reranked = sorted(
            fallback_rows,
            key=lambda r: _rerank_score(r[2], r[3], _BASE),
            reverse=True,
        )

        for fb_rel, fb_title, fb_chunk, fb_text, fb_page in fallback_reranked:
            if not _is_toc_like(fb_chunk, fb_text):
                top_rel, top_title, top_chunk, top_text, top_page = (
                    fb_rel, fb_title, fb_chunk, fb_text, fb_page
                )
                # Re-look up domain for the fallback document.
                try:
                    _top_domain = db.execute(
                        text("SELECT domain FROM corpus_documents WHERE rel_path = :rel"),
                        {"rel": top_rel},
                    ).scalar() or "general"
                except Exception:
                    db.rollback()
                    _top_domain = "general"
                _top_content_kind = _content_kind_map.get(top_rel, "procedure")
                _used_fallback = True
                _fts_rank = _BASE
                break
        else:
            # All candidates — including fallback — look like TOC/front-matter.
            guidance = {
                "type": "refusal",
                "reasonCode": "NO_PROCEDURE_FOUND",
                "title": "No procedural section found",
                "message": (
                    "The documents matched your question but only returned "
                    "table-of-contents or front-matter sections. "
                    "Try a more specific question about the procedure or step you need."
                ),
                "safeNextStep": (
                    "Ask about a specific operation, step, or maintenance task "
                    "by name (e.g. 'decon machine startup steps')."
                ),
                "hiddenSource": False,
            }
            return guidance, "refused", [], []

    _clean_top = clean_lines(top_text)
    _eff_page = top_page if top_page is not None else top_chunk

    # ── Relevance gate — refuse if question tokens have no overlap with excerpt.
    # Applied in both operational and training modes.
    # OR-expansion results in operational mode require a stricter threshold:
    # the OR path already signals no AND match was found, so higher overlap is
    # needed before returning potentially weaker evidence as guidance.
    _eff_relevance_threshold = (
        _RELEVANCE_THRESHOLD_OR_OPERATIONAL
        if (_used_or_fts and mode == "operational")
        else _RELEVANCE_THRESHOLD
    )
    if _relevance_score(question, _clean_top) < _eff_relevance_threshold:
        # RC3 cascade: when OR expansion is in use and the top FTS result barely
        # misses the relevance threshold, try the next reranked candidates before
        # refusing.  The best FTS hit may be an off-topic document that scores
        # highly on a shared structural token (e.g. "floor" → floor-collapse
        # protocol) while the genuinely relevant doc sits one rank lower.
        # Cap at 3 fallbacks; skip TOC-like chunks; only active on the OR path.
        _cascade_found = False
        if _used_or_fts and not _used_fallback:
            for _cand in reranked[1:4]:
                _c_rel, _c_title, _c_chunk, _c_text, _c_rank, _c_page, _c_dom = _cand
                if _is_toc_like(_c_chunk, _c_text):
                    continue
                _c_clean = clean_lines(_c_text)
                if _relevance_score(question, _c_clean) >= _eff_relevance_threshold:
                    top_rel, top_title, top_chunk, top_text, _clean_top = (
                        _c_rel, _c_title, _c_chunk, _c_text, _c_clean
                    )
                    top_page   = _c_page
                    _fts_rank  = _c_rank
                    _top_domain = _c_dom
                    _top_content_kind = _content_kind_map.get(_c_rel, "procedure")
                    _cascade_found = True
                    break
        if not _cascade_found:
            return {
                "type": "refusal",
                "reasonCode": "NO_RELEVANT_PROCEDURE",
                "title": "No approved guidance found for this query",
                "message": (
                    "Result withheld — evidence confidence was insufficient for this query. "
                    "The matched content did not contain enough terms relevant to your question."
                ),
                "safeNextStep": "Ask about a specific procedure, equipment, or emergency by name.",
                "hiddenSource": False,
            }, "refused", [], []

    # ── RC6: equipment manual gate ────────────────────────────────────────────
    # Equipment/apparatus instruction manuals (BAM monitor, decon washer,
    # System 2000 pump) are tagged content_kind='equipment_manual'.  When an
    # OR-expanded result lands on one of these docs, a single coincidental
    # token match (e.g. "system" in a BAM parameter section, "fill" in a
    # decon washer panel description) is not enough to serve apparatus content
    # to a procedure query.  Require 0.40 token overlap — roughly 2/5 tokens.
    _RC6_EQUIPMENT_THRESHOLD = 0.40
    if (_used_or_fts
            and _top_content_kind == "equipment_manual"
            and _relevance_score(question, _clean_top) < _RC6_EQUIPMENT_THRESHOLD):
        return _NO_RELEVANT_PROCEDURE_REFUSAL, "refused", [], []

    # ── Fetch adjacent chunks for structured procedure parsing ────────────────
    # Window: top_chunk ± 2 (up to 5 chunks ≈ 7 500 chars of context).
    # Run combined text through clean_lines before parsing.
    try:
        adj_rows = db.execute(
            text("""
                SELECT cc.text
                FROM corpus_chunks cc
                JOIN corpus_documents cd ON cd.id = cc.doc_id
                WHERE cd.rel_path = :rel
                  AND cc.chunk_index BETWEEN :lo AND :hi
                ORDER BY cc.chunk_index
            """),
            {"rel": top_rel, "lo": top_chunk - 2, "hi": top_chunk + 2},
        ).fetchall()
        _raw_adj = "\n".join(r[0] for r in adj_rows)
        _combined = clean_lines(_raw_adj)
    except Exception:
        db.rollback()
        _raw_adj = top_text
        _combined = _clean_top
    # ── Anchor-first procedure extraction ─────────────────────────────────────
    # Parse procedure steps from the cited (anchor) chunk only.  Adjacent
    # chunks are kept in _combined for the excerpt/summary but must NOT
    # contribute to step extraction — adjacent sections often contain unrelated
    # bullet lists (e.g. AED device setup adjacent to CPR treatment steps).
    #
    # Procedure quality is assessed on the FULL parsed result BEFORE step-level
    # filtering so that query-token coverage of individual step text does not
    # reduce the apparent quality of a legitimate procedure document.
    # (e.g. "rit activation" tokens appear in only 1 of 8 MAYDAY steps, but
    # all 8 steps are valid procedure content — the quality must be ok.)
    # Step-level filtering runs afterwards for display purposes only.
    proc = parse_procedure(_clean_top)
    _pq = procedure_quality(proc, _clean_top)

    _question_tokens = _tokenize(question)
    if _question_tokens:
        # Drop steps whose token set is entirely disjoint from the question tokens.
        # A single shared token is sufficient to keep the step.
        proc["steps"] = [
            s for s in proc["steps"]
            if _tokenize(s) & _question_tokens
        ]

    # ── Fetch document-level metadata (owner/dates/status) ───────────────────
    try:
        _meta = db.execute(
            text("SELECT owner, effective_date, review_date, status_override"
                 " FROM corpus_documents WHERE rel_path = :rel"),
            {"rel": top_rel},
        ).fetchone()
    except Exception:
        db.rollback()
        _meta = None
    _owner     = (_meta[0] if _meta else "") or ""
    _eff_date  = (_meta[1] if _meta else "") or ""
    _rev_date  = (_meta[2] if _meta else "") or ""
    _status_ov = (_meta[3] if _meta else "") or ""

    # ── Prompt 2: Metadata-driven policy (status_override / review_date) ─────
    _today_str = datetime.now(timezone.utc).date().isoformat()

    # Belt-and-suspenders: restricted docs are filtered at SQL time (WHERE clause),
    # but if one reaches here (e.g. via TOC fallback fetching adjacent chunks
    # that lack the status gate), enforce fail-closed with no content leak.
    if _status_ov == "restricted" and _requester_level < 1:
        return _ACL_REFUSAL_GUIDANCE, "refused", [], []

    if mode == "operational":
        if _status_ov in ("superseded", "draft"):
            refusal = {
                "type": "refusal",
                "reasonCode": "NO_ACTIVE_PROCEDURE",
                "title": "No active approved guidance found",
                "message": (
                    "No active approved guidance found — the matched document has status "
                    f"'{_status_ov}' and cannot be used for operational decisions."
                ),
                "safeNextStep": "Consult your training officer for the current active version of this procedure.",
                "hiddenSource": False,
            }
            return refusal, "refused", [], []

    # Notice accumulator for approved path
    _notice: str | None = None
    if mode == "operational":
        if _rev_date and _rev_date < _today_str:
            _notice = "REVIEW_OVERDUE: This document's review date has passed. Verify currency before acting."
    else:  # training mode
        if _status_ov in ("superseded", "draft"):
            _notice = f"TRAINING_ONLY: document status is {_status_ov}"
        elif _status_ov == "restricted":
            _notice = "RESTRICTED_CONTENT: This document is restricted. Access granted for your role."

    # ── Confidence metadata ───────────────────────────────────────────────────
    _rerank_val = _rerank_score(top_chunk, top_text, _fts_rank)
    _reason_parts = [f"chunk {top_chunk} page {top_page}"]
    if _used_or_fts:
        _reason_parts.append("OR-expanded FTS (AND returned 0 hits)")
    if _used_fallback:
        _reason_parts.append(f"document fallback (initial top was TOC-like)")
    _reason_parts.append(f"FTS rank {_fts_rank:.4f}; rerank {_rerank_val:.4f}")
    if _reranked_dicts:
        _reason_parts.append(_reranked_dicts[0].get('rerank_reason', ''))

    # ── Prompt 3: Apply procedure quality decision ────────────────────────────
    _pq_notice: str | None = None
    _pq_steps    = proc["steps"]
    _pq_warnings = proc["warnings"]
    _pq_prereqs  = proc["prereqs"]
    _pq_troubles = proc["troubleshooting"]
    if _pq["decision"] == "reject":
        _pq_steps = []
        _pq_warnings = []
        _pq_prereqs = []
        _pq_troubles = []
        _pq_notice = "PROCEDURE_EXTRACT_REJECTED"
    elif _pq["decision"] == "weak":
        _pq_notice = "LOW_CONFIDENCE"

    # ── Policy gate A: operational + weak/rejected (non-medical) → LOW_CONFIDENCE
    # Fire-ops and lrfd_protocol documents with weak procedure quality are refused
    # in operational mode.  medical_emr is handled separately below.
    #
    # Exception: requirements/spec queries that retrieved a chunk with explicit
    # inline spec data ("requires 41 amps") are allowed through even if the
    # procedure parser returns weak quality — spec tables are not step-procedure
    # content and should not be refused on procedural quality grounds.
    # ── Requirements evidence (KDAT-015) ─────────────────────────────────────
    # Compute per-chunk signals for the selected top chunk.  Attached to
    # guidance JSON for debugging; also drives _is_spec_answer bypass below.
    _req_evidence: dict | None = None
    if bool(_REQUIREMENTS_INTENT.search(question)):
        _re_n_explicit = len(_EXPLICIT_REQUIRES_SPEC.findall(top_text))
        _re_heading    = bool(_REQUIREMENTS_HEADING_SIGNAL.search(top_text))
        _re_has_spec   = bool(_SPEC_DATA_SIGNAL.search(top_text))
        _re_is_ptr     = bool(_POINTER_SIGNAL.search(top_text))
        _re_spec_lines = [l for l in top_text.split("\n") if _SPEC_DATA_SIGNAL.search(l)]
        _spec_table_like = len(_re_spec_lines) >= 3
        _req_evidence = {
            "heading_hit":        _re_heading,
            "explicit_spec_lines": _re_n_explicit,
            "pointer_only":       _re_is_ptr and not _re_has_spec,
            "spec_table_like":    _spec_table_like,
        }

    _is_spec_answer = (
        bool(_REQUIREMENTS_INTENT.search(question))
        and (
            bool(_EXPLICIT_REQUIRES_SPEC.search(top_text))
            or (_req_evidence is not None and _req_evidence["spec_table_like"])
        )
    )
    # dev/keystone-next: loosened from ("weak", "reject") → "reject" only.
    # "weak" quality is normal for a general procedure corpus; refusing on it
    # is too aggressive outside the LRFD fire-service context.  KDAT-086.
    if mode == "operational" and _top_domain != "medical_emr" and _pq["decision"] == "reject" and not _is_spec_answer:
        return {
            "type": "refusal",
            "reasonCode": "LOW_CONFIDENCE",
            "title": "Reference material found — not an approved departmental procedure",
            "message": (
                "Reference material was found but could not be confirmed as an approved departmental procedure. "
                "The matched content did not have sufficient procedural structure for operational use."
            ),
            "safeNextStep": "Consult your supervisor for the current approved procedure.",
            "hiddenSource": False,
        }, "refused", [], []

    # ── Policy gate A2: operational scope guard ───────────────────────────────
    # DISABLED for dev/keystone-next: LRFD content_kind guard.
    # All 85 docs in the dev corpus are content_kind='procedure'; there is no
    # requirements corpus, so this gate produces only false refusals.
    # Re-enable when content_kind taxonomy is implemented for the target
    # corpus.  See KDAT-086 notes.
    _has_req_intent = bool(_REQUIREMENTS_INTENT.search(question))

    # ── Policy gate B: medical_emr domain → medical_reference card ──────────
    # DISABLED for dev/keystone-next: no medical_emr documents exist in the
    # dev corpus.  This gate can never fire and its card-type conversion would
    # shadow future procedure results if a stale domain tag slipped through.
    # Re-enable when a medical_emr sub-corpus is ingested.  See KDAT-086.
    if False and _top_domain == "medical_emr" and mode != "medical_reference":
        # RC1 fix: OR expansion in non-medical modes is off-domain leakage.
        # AND-matched EMR content in training/operational is still allowed through
        # (e.g. a fire-ops query that genuinely AND-matches an EMR document).
        # Only OR-expanded hits are refused here — OR expansion already signals
        # no AND match existed, so routing to EMR is cross-domain noise.
        if _used_or_fts:
            return _NO_RELEVANT_PROCEDURE_REFUSAL, "refused", [], []
        # RC1b: AND-matched EMR in non-medical mode requires medical vocabulary
        # in the question. Single-word coincidences ("chief" → "chief complaint",
        # "incident command" → ICS sections in EMR) must not route to EMR content.
        if not any(t in _MEDICAL_QUERY_TOKENS for t in _tokenize(question)):
            return _NO_RELEVANT_PROCEDURE_REFUSAL, "refused", [], []
        if mode == "operational" and _pq["decision"] == "reject":
            return {
                "type": "refusal",
                "reasonCode": "LOW_CONFIDENCE_MEDICAL",
                "title": "Medical guidance withheld — insufficient confidence",
                "message": (
                    "Medical reference material was found but confidence was insufficient to surface it. "
                    "Imprecise medical guidance could cause harm — this result has been withheld."
                ),
                "safeNextStep": (
                    "Contact your safety officer or supervisor for guidance. "
                    "Do not act on unverified medical information."
                ),
                "hiddenSource": False,
            }, "refused", [], []
        # Allowed — build a medical_reference guidance card (not "approved").
        _emr_disclaimer = (
            "Reference material found — NOT an approved departmental procedure. "
            "This is medical reference content only. "
            "Follow your organization's protocols and the direction of qualified medical personnel."
        )
        top5 = reranked[:5]
        medref_sources = [
            {
                "documentId": rel_path,
                "title": title,
                "status": "active",
                "allowed": True,
                "page": pg if pg is not None else chunk_idx,
                "chunkIndex": chunk_idx,
                "section": f"page {pg}" if pg is not None else f"chunk {chunk_idx}",
                "note": f"FTS rank {rank:.4f}  rerank {_rerank_score(chunk_idx, _text, rank):.4f}",
                "content_kind": _content_kind_map.get(rel_path, "procedure"),
            }
            for rel_path, title, chunk_idx, _text, rank, pg, _dom in top5
        ]
        medref_citations = [
            {
                "documentId": rel_path,
                "chunkIndex": chunk_idx,
                "page": pg,
                "snippet": chunk_text_val[:300],
            }
            for rel_path, _title, chunk_idx, chunk_text_val, _rank, pg, _dom in top5
        ]
        medref_notice = "LOW_CONFIDENCE" if mode == "training" and _pq["decision"] == "weak" else None
        medref_guidance: dict = {
            "type": "medical_reference",
            "notice": medref_notice,
            "disclaimer": _emr_disclaimer,
            "summary": make_summary(_clean_top),
            "excerpt": _clean_top[:1500],
            "keyPoints": _pq_warnings,
            "document": {
                "documentId": top_rel,
                "title": top_title,
                "section": f"page {top_page}" if top_page is not None else f"chunk {top_chunk}",
                "page": _eff_page,
                "chunkIndex": top_chunk,
                "status": _status_ov if _status_ov else "active",
                "effectiveDate": _eff_date,
                "reviewDate": _rev_date,
                "owner": _owner,
                "available": _doc_available(top_rel),
                "domain": _top_domain,
                "content_kind": _top_content_kind,
            },
            "steps": _pq_steps if _pq["decision"] == "ok" else [],
            "warnings": _pq_warnings,
            "confidence": {
                "rerank_reason":    "; ".join(_reason_parts),
                "toc_filtered":     _toc_filtered,
                "used_fallback":    _used_fallback,
                "or_expansion":     _used_or_fts,
                "fts_rank_min":     _FTS_RANK_MIN,
                "retrieval_source": _retrieval_source,
            },
            "procedure_quality": _pq,
        }
        _medref_primary_rerank = _rerank_val * (1.15 if _top_content_kind == "procedure" else 1.0)
        _medref_answers = _build_multi_answers(
            reranked, top_rel, _medref_primary_rerank,
            medref_guidance["document"], make_summary(_clean_top), _clean_top[:1500],
            question, _eff_relevance_threshold, _content_kind_map,
        )
        if _medref_answers:
            medref_guidance["answers"] = _medref_answers
        _add_llm_answer(medref_guidance, question, top5)
        # Targeted hedge-only refusal: if the LLM produced ONLY a hedge
        # phrase with no substantive content, convert to refusal.
        # This catches off-topic queries where the LLM correctly refuses
        # but the pipeline still marks "approved."
        # Full hedge gate disabled pending HHEM (KDAT-086).
        _medref_answer = medref_guidance.get("answer", "")
        if _medref_answer and _llm_hedges(_medref_answer) and len(_medref_answer.strip()) < 120:
            # Check if the retrieved content is actually relevant to the query
            # before falling back to deterministic. Off-topic queries should
            # still be refused even when the LLM hedges.
            _query_terms = {
                w for w in re.findall(r'[a-z0-9]+', question.lower())
                if len(w) > 2 and w not in {'the', 'what', 'how', 'are', 'for',
                    'does', 'with', 'from', 'this', 'that', 'which', 'when',
                    'where', 'who', 'whom', 'have', 'has', 'had', 'was', 'were',
                    'been', 'being', 'will', 'would', 'could', 'should', 'can',
                    'may', 'might', 'shall', 'must', 'need', 'required'}
            }
            _top_text_lower = medref_guidance.get("summary", "").lower()
            _top_title_lower = medref_guidance.get("document", {}).get("title", "").lower()
            # Also check the top chunk text for term overlap
            _top_chunk_text = ""
            if top5:
                _top_chunk_text = top5[0][3].lower()[:500]  # top5 row[3] is chunk text
            _combined = _top_text_lower + " " + _top_title_lower + " " + _top_chunk_text
            _term_hits = sum(1 for t in _query_terms if t in _combined)

            if _term_hits >= 2:
                logger.info(
                    "LLM hedge-only answer detected (%d chars, %d term hits) — falling back to deterministic",
                    len(_medref_answer.strip()), _term_hits,
                )
                medref_guidance["answer"] = medref_guidance.get("summary", "")
                medref_guidance["answer_source"] = "deterministic"
            else:
                logger.info(
                    "LLM hedge-only answer detected (%d chars, %d term hits) — refusing (low relevance)",
                    len(_medref_answer.strip()), _term_hits,
                )
                return {**_LLM_REFUSAL_ON_HEDGE}, "refused", [], []
        return medref_guidance, "allowed", medref_sources, medref_citations

    # ── Policy gate C: medical_reference mode → reference card ───────────────
    # Returns type="reference" (not "approved") with a hard disclaimer.
    # Steps/procedure card suppressed; only excerpt + key points shown.
    if mode == "medical_reference":
        if _top_domain != "medical_emr":
            # medical_reference mode matched a non-EMR document — refuse.
            return {
                "type": "refusal",
                "reasonCode": "NO_RELEVANT_PROCEDURE",
                "title": "No medical reference document found",
                "message": "No medical EMR document matched your question.",
                "safeNextStep": "Use your organization's approved medical or emergency protocols.",
                "hiddenSource": False,
            }, "refused", [], []
        _emr_disclaimer = (
            "Reference material found — NOT an approved operational procedure. "
            "Follow your organization's protocols and the direction of qualified medical personnel."
        )
        top5 = reranked[:5]
        ref_sources = [
            {
                "documentId": rel_path,
                "title": title,
                "status": "active",
                "allowed": True,
                "page": pg if pg is not None else chunk_idx,
                "chunkIndex": chunk_idx,
                "section": f"page {pg}" if pg is not None else f"chunk {chunk_idx}",
                "note": f"FTS rank {rank:.4f}  rerank {_rerank_score(chunk_idx, _text, rank):.4f}",
                "content_kind": _content_kind_map.get(rel_path, "procedure"),
            }
            for rel_path, title, chunk_idx, _text, rank, pg, _dom in top5
        ]
        ref_citations = [
            {
                "documentId": rel_path,
                "chunkIndex": chunk_idx,
                "page": pg,
                "snippet": chunk_text_val[:300],
            }
            for rel_path, _title, chunk_idx, chunk_text_val, _rank, pg, _dom in top5
        ]
        ref_guidance: dict = {
            "type": "reference",
            "notice": "MEDICAL_REFERENCE_NOT_PROTOCOL",
            "disclaimer": _emr_disclaimer,
            "summary": make_summary(_clean_top),
            "excerpt": _clean_top[:1500],
            "keyPoints": _pq_warnings,
            "document": {
                "documentId": top_rel,
                "title": top_title,
                "section": f"page {top_page}" if top_page is not None else f"chunk {top_chunk}",
                "page": _eff_page,
                "chunkIndex": top_chunk,
                "status": _status_ov if _status_ov else "active",
                "effectiveDate": _eff_date,
                "reviewDate": _rev_date,
                "owner": _owner,
                "available": _doc_available(top_rel),
                "domain": _top_domain,
                "content_kind": _top_content_kind,
            },
            "confidence": {
                "rerank_reason":    "; ".join(_reason_parts),
                "toc_filtered":     _toc_filtered,
                "used_fallback":    _used_fallback,
                "or_expansion":     _used_or_fts,
                "fts_rank_min":     _FTS_RANK_MIN,
                "retrieval_source": _retrieval_source,
            },
            "procedure_quality": _pq,
        }
        _ref_primary_rerank = _rerank_val * (1.15 if _top_content_kind == "procedure" else 1.0)
        _ref_answers = _build_multi_answers(
            reranked, top_rel, _ref_primary_rerank,
            ref_guidance["document"], make_summary(_clean_top), _clean_top[:1500],
            question, _eff_relevance_threshold, _content_kind_map,
        )
        if _ref_answers:
            ref_guidance["answers"] = _ref_answers
        _add_llm_answer(ref_guidance, question, top5)
        return ref_guidance, "allowed", ref_sources, ref_citations

    # ── Policy gate D: training + weak → reference type (not approved) ───────
    # Weak quality in training mode returns type="reference" with LOW_CONFIDENCE
    # notice so the operator sees the confidence level without a hard refusal.
    _force_reference = mode == "training" and _pq["decision"] == "weak"
    if _force_reference:
        _pq_notice = "LOW_CONFIDENCE"

    # Merge notices: quality notice takes precedence; if both, combine.
    # RESTRICTED_CONTENT is always surfaced — append rather than suppress so
    # that officer/authority callers always know a restricted document was returned.
    if _pq_notice and _notice:
        if _notice.startswith("RESTRICTED_CONTENT"):
            _final_notice: str | None = _pq_notice + "|" + _notice
        else:
            _final_notice = _pq_notice  # quality notice wins; status in type
    elif _pq_notice:
        _final_notice = _pq_notice
    else:
        _final_notice = _notice

    _guidance_type = "reference" if _force_reference else "approved"

    # ── Structured requirements extraction (requirements-intent queries) ──────
    # Parse _combined (anchor ± 2 adjacent chunks) so that wiring context from
    # neighbouring pages (e.g. chunk 29 "Power must be supplied directly from
    # the apparatus battery") is captured alongside the spec table in chunk 30.
    _req_data: dict | None = None
    _req_summary: str | None = None
    if _is_spec_answer or bool(_REQUIREMENTS_INTENT.search(question)):
        # Use raw (uncleaned) adjacent text so that lines like
        # "2002 or 2002HP 12 VDC requires 60 amps" (31% digit density) are
        # not dropped by clean_lines before spec parsing can extract them.
        _req_data = parse_requirements(_raw_adj)
        if _req_data["items"] or _req_data["wiring_notes"]:
            _req_summary = make_requirements_summary(
                _req_data["items"], _req_data["wiring_notes"]
            )

    # ── CLARIFY_MODEL notice ──────────────────────────────────────────────────
    # If requirements items reference multiple distinct models and the question
    # does not mention any of them, inject a CLARIFY_MODEL notice so the console
    # can offer one-click chips to re-run with a specific model appended.
    if _req_data is not None and len(_req_data.get("items", [])) > 0:
        _item_models = sorted({
            item["model"] for item in _req_data["items"]
            if item.get("model") and item["model"].strip()
        })
        if len(_item_models) > 1:
            _q_lower = question.lower()
            _named = any(m.lower() in _q_lower for m in _item_models)
            if not _named:
                _clarify_notice = "CLARIFY_MODEL: Models available: " + ", ".join(_item_models)
                # Merge into _final_notice; CLARIFY_MODEL is additive — append
                # after any existing quality notice rather than replacing it.
                if _final_notice:
                    _final_notice = _final_notice + "|" + _clarify_notice
                else:
                    _final_notice = _clarify_notice

    guidance: dict = {
        "type": _guidance_type,
        "summary": _req_summary if _req_summary else make_summary(_clean_top),
        "excerpt": _clean_top[:1500],
        "document": {
            "documentId": top_rel,
            "title": top_title,
            "section": f"page {top_page}" if top_page is not None else f"chunk {top_chunk}",
            "page": _eff_page,
            "chunkIndex": top_chunk,
            "status": _status_ov if _status_ov else "active",
            "effectiveDate": _eff_date,
            "reviewDate": _rev_date,
            "owner": _owner,
            # True iff file exists on disk with supported extension.
            # Console uses this to gate the "Open document" button.
            "available": _doc_available(top_rel),
            "domain": _top_domain,
            "content_kind": _top_content_kind,
        },
        # Procedure fields suppressed for reference type (weak quality)
        "steps":           [] if _force_reference else _pq_steps,
        "warnings":        [] if _force_reference else _pq_warnings,
        "prereqs":         [] if _force_reference else _pq_prereqs,
        "troubleshooting": [] if _force_reference else _pq_troubles,
        "confidence": {
            "rerank_reason":    "; ".join(_reason_parts),
            "toc_filtered":     _toc_filtered,
            "used_fallback":    _used_fallback,
            "or_expansion":     _used_or_fts,
            "fts_rank_min":     _FTS_RANK_MIN,
            "retrieval_source": _retrieval_source,
        },
        "procedure_quality": _pq,
    }
    # Attach structured requirements data when present (requirements-intent queries).
    # Emit when items were extracted (notes may be empty after hygiene filter).
    if _req_data is not None and (
        _req_data["items"]
        or _req_data["wiring_notes"]
        or _req_data["grounding_notes"]
    ):
        guidance["requirements"] = _req_data
    if _req_evidence is not None:
        guidance["requirements_evidence"] = _req_evidence
    if _final_notice is not None:
        guidance["notice"] = _final_notice
    # Return top 5 reranked candidates as sources/citations.
    top5 = reranked[:5]
    sources = [
        {
            "documentId": rel_path,
            "title": title,
            "status": "active",
            "allowed": True,
            "page": pg if pg is not None else chunk_idx,
            "chunkIndex": chunk_idx,
            "section": f"page {pg}" if pg is not None else f"chunk {chunk_idx}",
            "note": f"FTS rank {rank:.4f}  rerank {_rerank_score(chunk_idx, _text, rank):.4f}",
            "content_kind": _content_kind_map.get(rel_path, "procedure"),
        }
        for rel_path, title, chunk_idx, _text, rank, pg, _dom in top5
    ]
    citations = [
        {
            "documentId": rel_path,
            "chunkIndex": chunk_idx,
            "page": pg,
            "snippet": chunk_text_val[:300],
        }
        for rel_path, _title, chunk_idx, chunk_text_val, _rank, pg, _dom in top5
    ]
    # ── Multi-answer: collect secondary results from other documents ──────────
    _primary_rerank_val = _rerank_val * (1.15 if _top_content_kind == "procedure" else 1.0)
    _multi_answers = _build_multi_answers(
        reranked, top_rel, _primary_rerank_val,
        guidance["document"], guidance.get("summary", ""), _clean_top[:1500],
        question, _eff_relevance_threshold, _content_kind_map,
    )
    if _multi_answers:
        guidance["answers"] = _multi_answers
    _add_llm_answer(guidance, question, top5)

    # ── Stage 4: HHEM hallucination trust check (KDAT-086) ───────────────────
    _llm_answer = guidance.get("answer", "")

    # Targeted hedge-only refusal: if the LLM produced ONLY a hedge
    # phrase with no substantive content, convert to refusal.
    # This catches off-topic queries where the LLM correctly refuses
    # but the pipeline still marks "approved."
    # Full hedge gate disabled pending HHEM (KDAT-086).
    if _llm_answer and _llm_hedges(_llm_answer) and len(_llm_answer.strip()) < _HEDGE_ONLY_MIN_CHARS:
        # Check if the retrieved content is actually relevant to the query
        # before falling back to deterministic. Off-topic queries should
        # still be refused even when the LLM hedges.
        _query_terms = {
            w for w in re.findall(r'[a-z0-9]+', question.lower())
            if len(w) > 2 and w not in {'the', 'what', 'how', 'are', 'for',
                'does', 'with', 'from', 'this', 'that', 'which', 'when',
                'where', 'who', 'whom', 'have', 'has', 'had', 'was', 'were',
                'been', 'being', 'will', 'would', 'could', 'should', 'can',
                'may', 'might', 'shall', 'must', 'need', 'required'}
        }
        _top_text_lower = guidance.get("summary", "").lower()
        _top_title_lower = guidance.get("document", {}).get("title", "").lower()
        # Also check the top chunk text for term overlap
        _top_chunk_text = ""
        if top5:
            _top_chunk_text = top5[0][3].lower()[:500]  # top5 row[3] is chunk text
        _combined = _top_text_lower + " " + _top_title_lower + " " + _top_chunk_text
        _term_hits = sum(1 for t in _query_terms if t in _combined)

        if _term_hits >= _HEDGE_ONLY_TERM_HITS:
            logger.info(
                "LLM hedge-only answer detected (%d chars, %d term hits) — falling back to deterministic",
                len(_llm_answer.strip()), _term_hits,
            )
            guidance["answer"] = guidance.get("summary", "")
            guidance["answer_source"] = "deterministic"
            _llm_answer = guidance["answer"]
        else:
            logger.info(
                "LLM hedge-only answer detected (%d chars, %d term hits) — refusing (low relevance)",
                len(_llm_answer.strip()), _term_hits,
            )
            return {**_LLM_REFUSAL_ON_HEDGE}, "refused", [], []

    if _llm_answer:
        _premise = _build_evidence_pack(top5)
        _hhem_score = hhem_scorer.score(_premise, _llm_answer)
        _answer_source = guidance.get("answer_source", "llm")
        _hhem_threshold = hhem_scorer.get_threshold(_answer_source)
        guidance["factual_consistency_score"] = _hhem_score
        logger.info(
            "[keystone] HHEM score=%.4f threshold=%.2f answer_source=%s query_snippet=%r",
            _hhem_score if _hhem_score is not None else -1.0,
            _hhem_threshold,
            _answer_source,
            question[:80],
        )
        if _hhem_score is not None and _hhem_score < _hhem_threshold:
            logger.info(
                "[keystone] HHEM below threshold (%.4f < %.2f) answer_source=%s — LOW_FACTUAL_CONSISTENCY refusal",
                _hhem_score,
                _hhem_threshold,
                _answer_source,
            )
            return {
                "type": "refusal",
                "reasonCode": "LOW_FACTUAL_CONSISTENCY",
                "title": "Answer withheld — factual consistency check failed",
                "message": (
                    "The generated answer could not be verified against the source documents. "
                    "The content may not accurately reflect the retrieved procedures."
                ),
                "safeNextStep": "Consult the source documents directly or contact your supervisor.",
                "hiddenSource": False,
                "factual_consistency_score": _hhem_score,
            }, "refused", [], []
    else:
        guidance["factual_consistency_score"] = None

    return guidance, "allowed", sources, citations


def _retrieve(
    question: str, mode: str, role_level: int, db: DBSession,
    domain_filter: "list[str] | None" = None,
    requester_role: str = "member",
) -> tuple[dict, str, list, list]:
    """
    Primary retrieval dispatcher:
    - If corpus_chunks has rows: use Postgres FTS (websearch_to_tsquery).
    - Otherwise: lexical scoring against synthetic document fixtures.
    Fail-closed in both paths: INSUFFICIENT_EVIDENCE if nothing matches.
    """
    # FTS path — active whenever corpus has been ingested.
    fts_result = _corpus_fts_retrieve(question, mode, db,
                                      domain_filter=domain_filter,
                                      requester_role=requester_role)
    if fts_result is not None:
        return fts_result

    # Lexical fallback — used when corpus_chunks is empty (fresh DB / smoke tests).
    terms = _tokenize(question)

    all_docs = db.query(Document).all()

    # Mode filter: operational = active only; training = active + superseded
    if mode == "operational":
        candidates = [d for d in all_docs if d.status == "active"]
    else:
        candidates = [d for d in all_docs if d.status in ("active", "superseded")]

    scored = [(d, _lexical_score(terms, d)) for d in candidates]
    scored.sort(key=lambda x: -x[1])

    best_doc, best_score = (scored[0] if scored else (None, 0))

    if not best_doc or best_score < _EVIDENCE_THRESHOLD:
        guidance = {
            "type": "refusal",
            "reasonCode": "INSUFFICIENT_EVIDENCE",
            "title": "No approved departmental guidance found",
            "message": (
                "No approved departmental guidance found for this query. "
                "The corpus does not contain a document that matches the terms in your question."
            ),
            "safeNextStep": "Rephrase your question with specific procedure or equipment names, or consult your supervisor.",
            "hiddenSource": False,
        }
        return guidance, "refused", [], []

    # ACL check: if best doc requires higher role level, fail closed — no title/citations leaked
    if best_doc.min_role_level > role_level:
        return _ACL_REFUSAL_GUIDANCE, "refused", [], []

    # Restricted-status check for lexical fixture path (belt-and-suspenders).
    if getattr(best_doc, "status", "") == "restricted" and role_level < 1:
        return _ACL_REFUSAL_GUIDANCE, "refused", [], []

    _clean_ex = clean_lines(best_doc.excerpt or "")

    # Relevance gate — lexical score only checks token presence in doc body;
    # it doesn't confirm the question is *about* that document's topic.
    if _relevance_score(question, _clean_ex) < _RELEVANCE_THRESHOLD:
        return _NO_RELEVANT_PROCEDURE_REFUSAL, "refused", [], []

    guidance = {
        "type": "approved",
        "summary": make_summary(_clean_ex),
        "excerpt": _clean_ex[:800],
        "document": {
            "documentId": best_doc.document_id,
            "title": best_doc.title,
            "section": best_doc.section,
            "page": best_doc.page,
            "status": best_doc.status,
            "effectiveDate": best_doc.effective_date or "",
            "reviewDate": best_doc.review_date or "",
            "owner": best_doc.owner or "",
            # Lexical fixture docs do not have corpus files on disk.
            "available": False,
        },
    }
    sources = [{
        "documentId": best_doc.document_id,
        "title": best_doc.title,
        "status": best_doc.status,
        "allowed": True,
        "page": best_doc.page,
        "section": best_doc.section,
        "note": "Retrieved by lexical match.",
    }]
    citations = [{"documentId": best_doc.document_id, "page": best_doc.page, "section": best_doc.section}]
    return guidance, "allowed", sources, citations


def _scenario_key_from_guidance(guidance: dict) -> str:
    """Derive a scenarioKey that matches the guidance payload type."""
    t = guidance.get("type", "")
    if t == "approved":
        return "approved"
    if t in ("reference", "medical_reference"):
        return t          # "reference" or "medical_reference"
    if t == "refusal":
        code = guidance.get("reasonCode", "")
        if code == "ACCESS_RESTRICTED":
            return "restricted"
        return "refusal"
    # Unknown / legacy — fall back to reasonCode heuristic
    code = guidance.get("reasonCode", "")
    if code == "ACCESS_RESTRICTED":
        return "restricted"
    return "refusal"


# ---------------------------------------------------------------------------
# Startup — DB init is non-fatal; /health reflects readiness
# ---------------------------------------------------------------------------

_db_ready = False

# Build provenance — baked in at image build time via Dockerfile ARG → ENV.
# GIT_SHA is the short git SHA of the keystone-gov repo at build time.
# BUILD_TIMESTAMP is an ISO-8601 UTC string from the build host.
# Both default to "unknown" when the image was built without scripts/build-api.sh.
_BUILD_SHA: str = os.environ.get("GIT_SHA", "unknown").strip() or "unknown"
_BUILD_TS: str = os.environ.get("BUILD_TIMESTAMP", "unknown").strip() or "unknown"

# _VERSION: prefer baked SHA; fall back to live git (local dev); then "0.1.0".
if _BUILD_SHA != "unknown":
    _VERSION: str = _BUILD_SHA
else:
    try:
        _VERSION = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        _BUILD_SHA = _VERSION  # also update _BUILD_SHA for /health
    except Exception:
        _VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Governance config flags (read once at startup from environment)
# ---------------------------------------------------------------------------

_REQUIRE_DOC_CHANGE_APPROVAL = int(os.environ.get("REQUIRE_DOC_CHANGE_APPROVAL", "1"))
_REQUIRE_EVIDENCE_APPROVAL   = int(os.environ.get("REQUIRE_EVIDENCE_APPROVAL", "0"))
_TWO_PERSON_CONTROL          = int(os.environ.get("TWO_PERSON_CONTROL", "0"))
_EVIDENCE_APPROVAL_TTL_SECS  = int(os.environ.get("EVIDENCE_APPROVAL_TTL_SECONDS", "3600"))

# Public demo hardening (default: off).
# When enabled:
#   - Admin login is refused (403 PUBLIC_ADMIN_DISABLED).
#   - All write endpoints are blocked except POST /query and optionally
#     POST /decisions/* (controlled by PUBLIC_ALLOW_DECISIONS).
_PUBLIC_DEMO_MODE     = int(os.environ.get("PUBLIC_DEMO_MODE", "0"))
_PUBLIC_ALLOW_DECISIONS = int(os.environ.get("PUBLIC_ALLOW_DECISIONS", "1"))
# Reset endpoint secret — empty string disables the endpoint entirely.
_PUBLIC_DEMO_RESET_TOKEN: str = os.environ.get("PUBLIC_DEMO_RESET_TOKEN", "").strip()
_PUBLIC_DEMO_RETENTION_HOURS: int = int(os.environ.get("PUBLIC_DEMO_RETENTION_HOURS", "24"))

# ---------------------------------------------------------------------------
# Per-deployment quality gate parameters
# Defaults match the hardcoded values that were previously inline.
# Override via deployment.yaml quality_gates section.
# ---------------------------------------------------------------------------

# Hedge-only refusal gate: if the LLM answer is both a hedge phrase AND shorter
# than this limit, check term overlap before deciding to refuse or fall back.
_HEDGE_ONLY_MIN_CHARS: int = 120

# Minimum number of query terms that must appear in the top evidence before
# falling back to deterministic instead of refusing.
_HEDGE_ONLY_TERM_HITS: int = 2


def _apply_quality_gates() -> None:
    """Read quality_gates from deployment.yaml and apply overrides at startup."""
    global _HEDGE_ONLY_MIN_CHARS, _HEDGE_ONLY_TERM_HITS
    from deployment_config import CONFIG
    gates = CONFIG.get("quality_gates", {})
    if not gates:
        return
    if "hhem_threshold_llm" in gates:
        hhem_scorer.configure(llm_threshold=float(gates["hhem_threshold_llm"]))
    if "hhem_threshold_deterministic" in gates:
        hhem_scorer.configure(deterministic_threshold=float(gates["hhem_threshold_deterministic"]))
    if "hedge_only_min_chars" in gates:
        _HEDGE_ONLY_MIN_CHARS = int(gates["hedge_only_min_chars"])
        logger.info("[keystone] quality_gates: hedge_only_min_chars=%d", _HEDGE_ONLY_MIN_CHARS)
    if "hedge_only_term_hits" in gates:
        _HEDGE_ONLY_TERM_HITS = int(gates["hedge_only_term_hits"])
        logger.info("[keystone] quality_gates: hedge_only_term_hits=%d", _HEDGE_ONLY_TERM_HITS)


_apply_quality_gates()


# ---------------------------------------------------------------------------
# Evidence signing (Ed25519) — loaded once at startup
# ---------------------------------------------------------------------------

_SIGNING_KEY: "Ed25519PrivateKey | None" = None
_SIGNING_PUBKEY_PEM: "bytes | None" = None


def _load_signing_key() -> None:
    global _SIGNING_KEY, _SIGNING_PUBKEY_PEM
    key_path = os.environ.get("EVIDENCE_SIGNING_KEY_PATH", "").strip()
    if not key_path:
        print("[evidence] EVIDENCE_SIGNING_KEY_PATH not set — signing disabled",
              file=sys.stderr, flush=True)
        return
    p = Path(key_path)
    if not p.exists():
        print(f"[evidence] key not found at {key_path} — signing disabled",
              file=sys.stderr, flush=True)
        return
    try:
        raw = p.read_bytes()
        _SIGNING_KEY = _crypto_ser.load_pem_private_key(raw, password=None)  # type: ignore[assignment]
        _SIGNING_PUBKEY_PEM = _SIGNING_KEY.public_key().public_bytes(  # type: ignore[union-attr]
            encoding=_crypto_ser.Encoding.PEM,
            format=_crypto_ser.PublicFormat.SubjectPublicKeyInfo,
        )
        print(f"[evidence] signing key loaded from {key_path}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"[evidence] failed to load signing key: {exc}", file=sys.stderr, flush=True)


def _require_signing_key() -> None:
    if _SIGNING_KEY is None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Evidence signing not configured. "
                "Run scripts/gen-evidence-keys.sh and set EVIDENCE_SIGNING_KEY_PATH."
            ),
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_ready
    try:
        # Tables are pre-created by initdb/00-schema.sql when connecting as
        # keystone_app.  create_all() is a no-op if tables already exist.
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            if os.environ.get("SEED_DEMO_USERS", "").lower() == "true":
                seed_demo_data(db)
        finally:
            db.close()
        _db_ready = True
    except Exception as exc:
        print(f"[startup] DB init failed: {exc}", file=sys.stderr, flush=True)
        print("[startup] API will serve /health as degraded until DB is available.",
              file=sys.stderr, flush=True)
    _load_signing_key()
    init_role_config()
    try:
        db = SessionLocal()
        try:
            seed_managed_users(db)
        finally:
            db.close()
    except Exception as exc:
        print(f"[startup] seed_managed_users failed: {exc}", file=sys.stderr, flush=True)
    validate_hmac_key()
    # ── Startup security warnings ────────────────────────────────────────────
    _salt_val = os.environ.get("AUTH_PASSWORD_SALT", "")
    if not _salt_val or _salt_val == "dev-salt-change-me":
        logger.warning(
            "SECURITY WARNING: AUTH_PASSWORD_SALT is not set or uses the insecure default "
            "'dev-salt-change-me'. All password hashes use a known salt - set this env "
            "var to a 32+ character random value before exposing this API publicly."
        )
    elif len(_salt_val) < 16:
        logger.warning(
            "SECURITY WARNING: AUTH_PASSWORD_SALT is too short (%d chars). "
            "Use at least 32 random characters for production deployments.",
            len(_salt_val),
        )
    yield


app = FastAPI(title="Keystone Gov API", version="0.2.0", lifespan=lifespan)

# ── CORS ─────────────────────────────────────────────────────────────────────
# allow_credentials=False: API uses Bearer tokens in the Authorization header,
# not cookies, so credentials mode is not needed.  The wildcard origin is safe
# when credentials=False (no cross-origin cookie leakage).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
# Adds defensive HTTP headers to every response.  CSP and HSTS are handled
# by Cloudflare/Caddy upstream; Cache-Control, XCTO, and XFO are set here.

from fastapi import Request
from fastapi.responses import JSONResponse


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # API responses must not be cached by intermediaries.
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Global exception handlers — prevent internal detail leakage
# ---------------------------------------------------------------------------
# All HTTPExceptions with status >= 500 log the detail server-side but return
# a generic message to the client.  Unhandled exceptions are also caught.

@app.exception_handler(HTTPException)
async def sanitised_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code >= 500:
        # Log full detail server-side; return only a generic message to the client.
        logger.error(
            "HTTP %d at %s %s: %s",
            exc.status_code, request.method, request.url.path, exc.detail,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": "An internal server error occurred."},
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception at %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )


# ── Compliance router ─────────────────────────────────────────────────────────
app.include_router(compliance_router)


# ---------------------------------------------------------------------------
# In-memory rate limiters
# ---------------------------------------------------------------------------
# Simple sliding-window counters.  Process-local only; acceptable for a
# single-process deployment.  Not shared across workers.

# Login rate limiter: 5 attempts per IP per 60 seconds.
_LOGIN_RATE_LIMIT  = 5
_LOGIN_RATE_WINDOW = 60  # seconds
_login_attempts: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _check_login_rate_limit(ip: str) -> None:
    """Raise 429 if the IP has exceeded the login attempt threshold."""
    now = time.time()
    with _login_lock:
        window = _login_attempts.get(ip, [])
        window = [t for t in window if now - t < _LOGIN_RATE_WINDOW]
        if len(window) >= _LOGIN_RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Too many login attempts. Please wait before trying again.",
            )
        window.append(now)
        _login_attempts[ip] = window


# Query rate limiter: 20 queries per session token per 60 seconds.
_QUERY_RATE_LIMIT  = int(os.environ.get("QUERY_RATE_LIMIT", "20"))
_QUERY_RATE_WINDOW = 60  # seconds
_query_attempts: dict[str, list[float]] = {}
_query_lock = threading.Lock()


def _check_query_rate_limit(token: str) -> None:
    """Raise 429 if the session token has exceeded the query threshold."""
    now = time.time()
    with _query_lock:
        window = _query_attempts.get(token, [])
        window = [t for t in window if now - t < _QUERY_RATE_WINDOW]
        if len(window) >= _QUERY_RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Query rate limit exceeded. Please wait before submitting again.",
            )
        window.append(now)
        _query_attempts[token] = window


# ---------------------------------------------------------------------------
# Public demo guard middleware
# ---------------------------------------------------------------------------
#
# In PUBLIC_DEMO_MODE=1 all non-read, non-core requests are rejected before
# they reach route handlers.  This is defence-in-depth on top of the per-
# route role checks: even a valid officer/admin token cannot mutate state.
#
# Allowed in public demo mode:
#   - Any GET / HEAD / OPTIONS
#   - POST /query            (core demo flow)
#   - POST /auth/login       (handled by login endpoint; admin blocked there)
#   - POST /decisions/*      (if PUBLIC_ALLOW_DECISIONS=1, default)
#
# Everything else (PATCH, DELETE, other POSTs) → 403 PUBLIC_DEMO_READ_ONLY.


@app.middleware("http")
async def public_demo_guard(request: Request, call_next):
    if _PUBLIC_DEMO_MODE:
        method = request.method.upper()
        path   = request.url.path

        # Always allow reads and CORS pre-flight.
        if method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        # Core demo write: POST /query and POST /auth/login pass through.
        if method == "POST" and path in ("/query", "/auth/login"):
            return await call_next(request)

        # Reset endpoint — token-guarded, always allowed through middleware.
        if method == "POST" and path == "/public/reset":
            return await call_next(request)

        # Optional: allow recording operator decisions in demo.
        if _PUBLIC_ALLOW_DECISIONS and method == "POST" and path.startswith("/decisions/"):
            return await call_next(request)

        # Block all other writes.
        return JSONResponse(
            status_code=403,
            content={
                "detail": {
                    "message": "Write operations are disabled in public demo mode.",
                    "reasonCode": "PUBLIC_DEMO_READ_ONLY",
                }
            },
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


# Sessions expire after this many hours of age (measured from created_at).
SESSION_TTL_HOURS = 8


def get_current_session(
    authorization: str | None = Header(default=None),
    db: DBSession = Depends(get_db),
) -> Session:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.removeprefix("Bearer ")
    session = db.query(Session).filter(Session.token == token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    # ── Session TTL check ────────────────────────────────────────────────────
    # Sessions older than SESSION_TTL_HOURS are expired.  The row is deleted
    # so the next request fails fast (no DB row to find) and old tokens do not
    # accumulate indefinitely.
    if session.created_at:
        age_seconds = (datetime.utcnow() - session.created_at).total_seconds()
        if age_seconds > SESSION_TTL_HOURS * 3600:
            db.delete(session)
            db.commit()
            raise HTTPException(status_code=401, detail="Session expired — please log in again")
    return session


# ---------------------------------------------------------------------------
# Health (no auth)
# ---------------------------------------------------------------------------


@app.get("/health")
def health(request: Request):
    from deployment_config import CONFIG
    # Only expose build metadata to localhost or authenticated callers.
    # Unauthenticated external requests get status/db/version only.
    client_host = request.client.host if request.client else ""
    _is_local = client_host in ("127.0.0.1", "::1", "localhost")
    auth_header = request.headers.get("authorization", "")
    _has_token = auth_header.startswith("Bearer ")
    _show_build = _is_local or _has_token
    result = {
        "status": "ok" if _db_ready else "degraded",
        "service": "keystone-gov-api",
        "db": _db_ready,
        "version": _VERSION,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "public_demo_mode": bool(_PUBLIC_DEMO_MODE),
        "deployment_id": CONFIG.get("deployment", {}).get("id", "unknown"),
        **ollama_client.healthy(),
    }
    if _show_build:
        result["git_sha"] = _BUILD_SHA
        result["build_ts"] = _BUILD_TS
    return result


@app.get("/config")
def get_deployment_config():
    """Return deployment configuration for the console."""
    from deployment_config import CONFIG
    from compliance import get_checklist_summaries
    return {
        "deployment": CONFIG.get("deployment", {}),
        "roles": CONFIG.get("roles", []),
        "modes": CONFIG.get("modes", []),
        "suggested_queries": CONFIG.get("suggested_queries", []),
        "demo_credentials": CONFIG.get("demo_credentials", []),
        "features": CONFIG.get("features", {}),
        "checklists": get_checklist_summaries(),
    }


# ---------------------------------------------------------------------------
# Public demo reset
# ---------------------------------------------------------------------------
#
# POST /public/reset
# Header: X-Reset-Token: <token>
#
# Deletes all transient demo data (decisions, cases, evidence requests, doc
# change requests, doc events) and audit/query rows older than
# PUBLIC_DEMO_RETENTION_HOURS.  Corpus tables (corpus_documents,
# corpus_chunks) are never touched.
#
# Returns 404 when PUBLIC_DEMO_RESET_TOKEN is not configured (endpoint does
# not exist in that deployment).  Returns 403 on wrong token.
# ---------------------------------------------------------------------------


@app.post("/public/reset")
def public_reset(request: Request):
    # If the token is not configured, behave as if the endpoint does not exist.
    if not _PUBLIC_DEMO_RESET_TOKEN:
        raise HTTPException(status_code=404, detail="Not found")

    # Validate token from header.
    provided = (request.headers.get("x-reset-token") or "").strip()
    if not provided or provided != _PUBLIC_DEMO_RESET_TOKEN:
        raise HTTPException(
            status_code=403,
            detail={"message": "Invalid or missing X-Reset-Token.", "reasonCode": "RESET_TOKEN_INVALID"},
        )

    # Use DB owner credentials — keystone_app lacks DELETE on these tables.
    owner_url = os.environ.get("TAMPER_DATABASE_URL", "")
    if not owner_url:
        raise HTTPException(status_code=500, detail="TAMPER_DATABASE_URL not configured")

    from datetime import timedelta as _timedelta
    # queries.created_at is a timezone-naive DateTime column.
    cutoff_naive = datetime.utcnow() - _timedelta(hours=_PUBLIC_DEMO_RETENTION_HOURS)
    # audit_log.timestamp is a String column storing ISO-8601 UTC strings.
    cutoff_iso   = (datetime.now(timezone.utc) - _timedelta(hours=_PUBLIC_DEMO_RETENTION_HOURS)).isoformat()

    counts: dict[str, int] = {}
    owner_engine = create_engine(owner_url)
    try:
        with owner_engine.begin() as conn:
            # Delete transient operational tables (always wipe, no retention window).
            for tbl in (
                "evidence_export_requests",
                "corpus_doc_change_requests",
                "corpus_doc_events",
                "operator_decisions",
                "incident_cases",
            ):
                r = conn.execute(text(f"DELETE FROM {tbl}"))
                counts[tbl] = r.rowcount

            # Delete old queries.
            r = conn.execute(
                text("DELETE FROM queries WHERE created_at < :cutoff"),
                {"cutoff": cutoff_naive},
            )
            counts["queries"] = r.rowcount

            # Delete old audit log entries (timestamp is a String in ISO format).
            r = conn.execute(
                text("DELETE FROM audit_log WHERE timestamp < :cutoff"),
                {"cutoff": cutoff_iso},
            )
            counts["audit_log"] = r.rowcount
    finally:
        owner_engine.dispose()

    print(f"[public_reset] reset complete — deleted: {counts}", flush=True)

    return {
        "reset": True,
        "deleted": counts,
        "retention_hours": _PUBLIC_DEMO_RETENTION_HOURS,
    }


# ---------------------------------------------------------------------------
# Auth (no auth)
# ---------------------------------------------------------------------------


@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest, request: Request, db: DBSession = Depends(get_db)):
    # ── Rate limiting ────────────────────────────────────────────────────────
    # Brute-force protection: 5 attempts per IP per 60 seconds.
    client_ip = (request.headers.get("X-Forwarded-For") or
                 request.headers.get("X-Real-IP") or
                 (request.client.host if request.client else "unknown"))
    # Use only the first IP if X-Forwarded-For contains a chain.
    client_ip = client_ip.split(",")[0].strip()
    _check_login_rate_limit(client_ip)

    # Login endpoint is only available when CF Access is disabled or demo simulation is enabled.
    if get_cf_enabled() and not get_demo_sim_enabled():
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Password login is disabled — authenticate via Cloudflare Access.",
                "reasonCode": "CF_AUTH_REQUIRED",
            },
        )

    # ── Privileged user lookup via TAMPER_DATABASE_URL ───────────────────────
    # keystone_app (DATABASE_URL) does not have SELECT on password_hash.
    # Password verification must use the superuser connection.
    _auth_url = os.environ.get("TAMPER_DATABASE_URL", "")
    if not _auth_url:
        raise HTTPException(status_code=500, detail="Authentication service unavailable")
    _auth_engine = create_engine(_auth_url)
    try:
        with _auth_engine.connect() as _auth_conn:
            _user_row = _auth_conn.execute(
                text("SELECT id, username, role, password_hash FROM users WHERE username = :u"),
                {"u": req.username},
            ).first()
    finally:
        _auth_engine.dispose()

    # In public demo mode, authority login is disabled regardless of credentials.
    if _PUBLIC_DEMO_MODE and _user_row and _user_row.role == "authority":
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Authority login is disabled in public demo mode.",
                "reasonCode": "PUBLIC_ADMIN_DISABLED",
            },
        )

    if not _user_row or not verify_password(req.password, _user_row.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Invalidate any existing sessions for this user before issuing a new one.
    db.execute(text("DELETE FROM sessions WHERE user_id = :uid"), {"uid": _user_row.id})
    token = str(uuid.uuid4())
    db.add(Session(token=token, user_id=_user_row.id, username=_user_row.username, role=_user_row.role))
    db.commit()
    return LoginResponse(token=token, username=_user_row.username, role=_user_row.role)


@app.get("/auth/me")
def get_me(current_user: AppUser = Depends(get_current_user)):
    from schemas import MeResponse
    return MeResponse(
        user_id=current_user.user_id,
        email=current_user.email,
        display_name=current_user.display_name,
        assigned_role=current_user.assigned_role,
        effective_role=current_user.role,
        auth_source=current_user.auth_source,
        cf_enabled=get_cf_enabled(),
        sim_role=current_user.sim_role,
        sim_enabled=get_demo_sim_enabled(),
    )


# ---------------------------------------------------------------------------
# Query (requires auth; role from token only)
# ---------------------------------------------------------------------------


@app.post("/query", response_model=QueryResponse)
def submit_query(
    req: QueryRequest,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    # ── Rate limiting ────────────────────────────────────────────────────────
    # 20 queries per session token per 60 seconds.  Protects GPU from abuse.
    _check_query_rate_limit(current_user.user_id or current_user.email)

    # Role is ALWAYS derived from the authenticated session — request body value ignored.
    role = current_user.role
    role_level = _ROLE_LEVEL.get(role, 0)

    # ── Prompt injection check ───────────────────────────────────────────────
    # Fail-closed: if the query matches an injection pattern, return a policy
    # refusal and log it in the audit trail without exposing any corpus data.
    _is_safe, _injection_reason = check_injection(req.question)
    if not _is_safe:
        _inj_query_id = str(uuid.uuid4())
        _inj_now = datetime.now(timezone.utc).isoformat()
        _inj_guidance = {
            "type": "refusal",
            "reasonCode": "INPUT_REJECTED",
            "title": "Query could not be processed",
            "message": "This query was flagged and could not be processed. "
                       "Please rephrase your question about a specific safety procedure or equipment.",
            "safeNextStep": "Ask about a specific procedure, equipment type, or hazard by name.",
            "hiddenSource": False,
        }
        _inj_last = db.query(AuditEntry).order_by(AuditEntry.timestamp.desc()).first()
        _inj_prev_hash = _inj_last.entry_hash if _inj_last else ""
        _inj_entry_hash = compute_entry_hash(
            _inj_query_id, _inj_now, role, req.mode, "refused", _inj_prev_hash
        )
        db.add(Query(
            id=_inj_query_id,
            question="[REDACTED — injection pattern detected]",
            role=role,
            mode=req.mode,
            scenario_key="policy_refusal",
            guidance_json=_inj_guidance,
            created_at=datetime.now(timezone.utc),
        ))
        db.add(AuditEntry(
            id=str(uuid.uuid4()),
            query_id=_inj_query_id,
            receipt_id=f"receipt-{_inj_query_id[:8]}",
            timestamp=_inj_now,
            role_used=role,
            mode_used=req.mode,
            policy_outcome="refused",
            sources_considered_json=[],
            citations_returned_json=[],
            prev_hash=_inj_prev_hash,
            entry_hash=_inj_entry_hash,
            user_id=current_user.user_id,
            user_email=current_user.email,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            simulated_role_used=current_user.sim_role,
        ))
        db.commit()
        return QueryResponse(query_id=_inj_query_id, scenario_key="policy_refusal")

    # ── Jurisdiction guard — refuse queries about non-Alberta regulations ────
    # The corpus covers Alberta OHS only. Queries explicitly referencing
    # other jurisdictions (OSHA, US, UK HSE, EU, Australian WHS, etc.)
    # should be refused rather than returning Alberta content that doesn't
    # apply to the queried jurisdiction.
    _NON_ALBERTA_SIGNALS = {
        'osha', 'niosh', 'united states', 'u.s.', 'us federal',
        'uk', 'hse uk', 'british', 'england',
        'european', 'eu directive',
        'australian', 'safe work australia', 'worksafe',
        'ontario', 'british columbia', 'quebec', 'saskatchewan',
        'manitoba', 'nova scotia',
    }
    _q_lower = req.question.lower()
    _jurisdiction_match = [s for s in _NON_ALBERTA_SIGNALS if s in _q_lower]
    if _jurisdiction_match:
        _jur_query_id = str(uuid.uuid4())
        _jur_now = datetime.now(timezone.utc).isoformat()
        _jur_guidance = {
            "type": "refusal",
            "reasonCode": "JURISDICTION_MISMATCH",
            "title": "Query references a jurisdiction not covered by this corpus",
            "message": (
                f"This corpus covers Alberta OHS regulations only. "
                f"Your query appears to reference: {', '.join(_jurisdiction_match)}. "
                f"Consult the relevant jurisdiction's regulatory authority."
            ),
            "safeNextStep": "Rephrase your question for Alberta OHS, or consult the relevant jurisdiction directly.",
            "hiddenSource": False,
        }
        _jur_last = db.query(AuditEntry).order_by(AuditEntry.timestamp.desc()).first()
        _jur_prev_hash = _jur_last.entry_hash if _jur_last else ""
        _jur_entry_hash = compute_entry_hash(
            _jur_query_id, _jur_now, role, req.mode, "refused", _jur_prev_hash
        )
        db.add(Query(
            id=_jur_query_id,
            question=req.question,
            role=role,
            mode=req.mode,
            scenario_key="policy_refusal",
            guidance_json=_jur_guidance,
            created_at=datetime.now(timezone.utc),
        ))
        db.add(AuditEntry(
            id=str(uuid.uuid4()),
            query_id=_jur_query_id,
            receipt_id=f"receipt-{_jur_query_id[:8]}",
            timestamp=_jur_now,
            role_used=role,
            mode_used=req.mode,
            policy_outcome="refused",
            sources_considered_json=[],
            citations_returned_json=[],
            prev_hash=_jur_prev_hash,
            entry_hash=_jur_entry_hash,
            user_id=current_user.user_id,
            user_email=current_user.email,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            simulated_role_used=current_user.sim_role,
        ))
        db.commit()
        return QueryResponse(query_id=_jur_query_id, scenario_key="policy_refusal")

    # ── Domain scope guard — refuse queries outside OHS corpus topic scope ──
    # FC-005 (KDAT-001B) demonstrated that queries about non-OHS Alberta
    # regulations (e.g. TIER greenhouse gas reporting) could pass injection
    # and jurisdiction checks, then return wrong-Part chunks via semantic
    # overlap (mine gas chunks for a greenhouse gas query). HHEM cannot
    # catch this class because it scores answer-chunk consistency, not
    # query-corpus relevance.
    #
    # Phrases are multi-word anchors to avoid the KDAT-086 over-refusal
    # failure mode. Single tokens like "gas" or "tier" are intentionally
    # NOT listed because they appear legitimately in mine/fire/oil
    # contexts in the OHS Code.
    _OUT_OF_SCOPE_PHRASES = (
        # Emissions / environmental regulations (not OHS)
        "greenhouse gas",
        "emissions reporting",
        "carbon pricing",
        "carbon tax",
        # Workers Comp Board (separate Alberta agency)
        "wcb claim",
        "workers compensation",
        # CRA / tax (federal)
        "t2 corporate",
        "corporate tax",
        "income tax filing",
        # IT / procurement (not OHS)
        "microsoft 365",
        "office 365",
    )
    _scope_match = [p for p in _OUT_OF_SCOPE_PHRASES if p in _q_lower]
    if _scope_match:
        _scope_query_id = str(uuid.uuid4())
        _scope_now = datetime.now(timezone.utc).isoformat()
        _scope_guidance = {
            "type": "refusal",
            "reasonCode": "DOMAIN_OUT_OF_SCOPE",
            "title": "Query outside corpus scope",
            "message": (
                f"This corpus covers Alberta occupational health and safety "
                f"procedures only. Your query references topics outside that "
                f"scope: {', '.join(_scope_match)}. "
                f"Consult the relevant regulatory authority directly."
            ),
            "safeNextStep": (
                "Ask about a workplace safety procedure, hazard, or piece "
                "of equipment covered by the Alberta OHS Code."
            ),
            "hiddenSource": False,
        }
        _scope_last = db.query(AuditEntry).order_by(AuditEntry.timestamp.desc()).first()
        _scope_prev_hash = _scope_last.entry_hash if _scope_last else ""
        _scope_entry_hash = compute_entry_hash(
            _scope_query_id, _scope_now, role, req.mode, "refused", _scope_prev_hash
        )
        db.add(Query(
            id=_scope_query_id,
            question=req.question,
            role=role,
            mode=req.mode,
            scenario_key="policy_refusal",
            guidance_json=_scope_guidance,
            created_at=datetime.now(timezone.utc),
        ))
        db.add(AuditEntry(
            id=str(uuid.uuid4()),
            query_id=_scope_query_id,
            receipt_id=f"receipt-{_scope_query_id[:8]}",
            timestamp=_scope_now,
            role_used=role,
            mode_used=req.mode,
            policy_outcome="refused",
            sources_considered_json=[],
            citations_returned_json=[],
            prev_hash=_scope_prev_hash,
            entry_hash=_scope_entry_hash,
            user_id=current_user.user_id,
            user_email=current_user.email,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            simulated_role_used=current_user.sim_role,
        ))
        db.commit()
        return QueryResponse(query_id=_scope_query_id, scenario_key="policy_refusal")

    # medical_reference mode always forces domain_filter to medical_emr only.
    # This is a defense-in-depth guard — the FTS gate in _corpus_fts_retrieve
    # also enforces this, but we set it here so it applies to all retrieval paths.
    _effective_domain_filter: "list[str] | None" = req.domain_filter
    if req.mode == "medical_reference":
        _effective_domain_filter = ["medical_emr"]

    # Authority override: scenario_key short-circuits retrieval for demo purposes.
    # "restricted" is handled first (its template contains the member-refused fixture,
    # not the officer/authority approved guidance, so it needs ACL-aware handling).
    if req.scenario_key and _has_perm(current_user, "case_management"):
        if req.scenario_key == "restricted":
            min_level = _SCENARIO_MIN_LEVEL.get("restricted", 1)
            if role_level >= min_level:
                guidance = {
                    "type": "approved",
                    "summary": "Restricted post-incident disciplinary information. Access granted for current role.",
                    "excerpt": (
                        "Post-incident review dated 2025-11-03: disciplinary action was taken per department "
                        "standard operating procedure section 7.4. Details are restricted to supervisory "
                        "and administrative personnel only."
                    ),
                    "note": "Restricted to officer and authority roles only.",
                    "document": {
                        "documentId": "demo-fd-restricted-001",
                        "title": "Demo FD Post-Incident Disciplinary Memo (2025-11-03)",
                        "section": "7.4",
                        "page": 1,
                        "status": "active",
                        "effectiveDate": "2025-11-03",
                        "reviewDate": "2026-11-03",
                        "owner": "Fire Chief",
                    },
                }
                policy_outcome = "allowed"
                sources = [{
                    "documentId": "demo-fd-restricted-001",
                    "title": "Demo FD Post-Incident Disciplinary Memo",
                    "status": "active",
                    "allowed": True,
                    "page": 1,
                    "section": "7.4",
                    "note": "Accessible to officer/admin only.",
                }]
                citations = [{"documentId": "demo-fd-restricted-001", "page": 1, "section": "7.4"}]
            else:
                guidance = _ACL_REFUSAL_GUIDANCE
                policy_outcome = "refused"
                sources = []
                citations = []
            stored_scenario_key = "restricted"
        elif req.scenario_key in _GUIDANCE_TEMPLATES:
            template = _GUIDANCE_TEMPLATES[req.scenario_key]
            guidance = template["guidance"]
            policy_outcome = "allowed" if guidance["type"] == "approved" else "refused"
            sources = template["audit"]["sourcesConsidered"]
            citations = template["audit"]["citationsReturned"]
            stored_scenario_key = req.scenario_key
        else:
            # Unknown scenario_key — fall through to retrieval
            guidance, policy_outcome, sources, citations = _retrieve(req.question, req.mode, role_level, db, domain_filter=_effective_domain_filter, requester_role=role)
            stored_scenario_key = _scenario_key_from_guidance(guidance)
    else:
        # Real retrieval — scenario_key ignored unless user has case_management
        guidance, policy_outcome, sources, citations = _retrieve(req.question, req.mode, role_level, db, domain_filter=_effective_domain_filter, requester_role=role)
        stored_scenario_key = _scenario_key_from_guidance(guidance)

    query_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    db.add(Query(
        id=query_id,
        question=req.question,
        role=role,
        mode=req.mode,
        scenario_key=stored_scenario_key,
        guidance_json=guidance,
        created_at=datetime.now(timezone.utc),
    ))

    last = db.query(AuditEntry).order_by(AuditEntry.timestamp.desc()).first()
    prev_hash = last.entry_hash if last else ""

    entry_hash = compute_entry_hash(
        query_id, now, role, req.mode, policy_outcome, prev_hash
    )

    db.add(AuditEntry(
        id=str(uuid.uuid4()),
        query_id=query_id,
        receipt_id=f"receipt-{query_id[:8]}",
        timestamp=now,
        role_used=role,
        mode_used=req.mode,
        policy_outcome=policy_outcome,
        sources_considered_json=sources,
        citations_returned_json=citations,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        user_id=current_user.user_id,
        user_email=current_user.email,
        user_display_name=current_user.display_name,
        auth_source=current_user.auth_source,
        simulated_role_used=current_user.sim_role,
    ))
    db.commit()

    return QueryResponse(query_id=query_id, scenario_key=stored_scenario_key)


# ---------------------------------------------------------------------------
# Guidance (requires auth)
# ---------------------------------------------------------------------------


@app.get("/guidance/{query_id}", response_model=GuidanceResponse)
def get_guidance(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    audit = _build_audit_dict(entry) if entry else {}
    # Derive scenarioKey from the stored guidance payload so that the UI
    # always reflects what was actually returned (e.g. reference/medical_reference)
    # rather than the scenario that was requested or stored at query time.
    derived_key = _scenario_key_from_guidance(q.guidance_json or {})
    return GuidanceResponse(
        queryId=q.id,
        scenarioKey=derived_key,
        question=q.question,
        mode=q.mode,
        guidance=q.guidance_json,
        audit=audit,
    )


# ---------------------------------------------------------------------------
# Source (requires auth; ACL enforced on document access)
# ---------------------------------------------------------------------------


@app.get("/source/{document_id}/{page}", response_model=SourceResponse)
def get_source(
    document_id: str,
    page: int,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    # ── Corpus lookup: check corpus_documents first ────────────────────────
    # document_id matches corpus_documents.rel_path; page is the chunk index.
    try:
        corpus_row = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.text,
                       cd.owner, cd.effective_date, cd.review_date, cd.status_override
                FROM corpus_documents cd
                JOIN corpus_chunks cc ON cc.doc_id = cd.id
                WHERE cd.rel_path = :rel AND cc.chunk_index = :idx
            """),
            {"rel": document_id, "idx": page},
        ).fetchone()
    except Exception:
        db.rollback()
        corpus_row = None

    if corpus_row:
        rel_path, title, chunk_text, c_owner, c_eff, c_rev, c_status = corpus_row
        return SourceResponse(
            documentId=rel_path,
            page=page,
            title=title,
            section=f"passage {page}",
            status=c_status or "active",
            effectiveDate=c_eff or "",
            reviewDate=c_rev or "",
            owner=c_owner or "",
            excerpt=(chunk_text or "")[:800],
            highlight="",
            notes=[],
        )

    # ── Seeded fixture lookup (existing behavior) ──────────────────────────
    key = f"{document_id}:{page}"
    doc = db.query(Document).filter(Document.key == key).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Source not found")

    role_level = _ROLE_LEVEL.get(current_session.role, 0)
    if doc.min_role_level > role_level:
        raise HTTPException(status_code=403, detail="Access restricted for current role")

    return SourceResponse(
        documentId=doc.document_id,
        page=doc.page,
        title=doc.title,
        section=doc.section,
        status=doc.status,
        effectiveDate=doc.effective_date or "",
        reviewDate=doc.review_date or "",
        owner=doc.owner or "",
        excerpt=doc.excerpt or "",
        highlight=doc.highlight or "",
        notes=doc.notes_json or [],
    )


# ---------------------------------------------------------------------------
# Source by chunk index (corpus only; used when page is null)
# ---------------------------------------------------------------------------


@app.get("/source-chunk/{document_id:path}", response_model=SourceResponse)
def get_source_chunk(
    document_id: str,
    chunk_index: int,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    """Fetch a corpus source page by chunk_index instead of PDF page number.
    Used by the UI when guidance.document.chunkIndex is known but page is null.
    """
    try:
        corpus_row = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.text, cc.page,
                       cd.owner, cd.effective_date, cd.review_date, cd.status_override
                FROM corpus_documents cd
                JOIN corpus_chunks cc ON cc.doc_id = cd.id
                WHERE cd.rel_path = :rel AND cc.chunk_index = :idx
            """),
            {"rel": document_id, "idx": chunk_index},
        ).fetchone()
    except Exception:
        db.rollback()
        corpus_row = None

    if not corpus_row:
        raise HTTPException(status_code=404, detail="Passage not found")

    rel_path, title, chunk_text_val, page_num, c_owner, c_eff, c_rev, c_status = corpus_row
    return SourceResponse(
        documentId=rel_path,
        page=page_num if page_num is not None else chunk_index,
        title=title,
        section=f"page {page_num}" if page_num is not None else f"passage {chunk_index}",
        status=c_status or "active",
        effectiveDate=c_eff or "",
        reviewDate=c_rev or "",
        owner=c_owner or "",
        excerpt=(chunk_text_val or "")[:800],
        highlight="",
        notes=[],
    )


# ---------------------------------------------------------------------------
# Document file download (requires auth; serves corpus active/ files)
# ---------------------------------------------------------------------------

_DOC_MEDIA_TYPES: dict[str, str] = {
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt":  "text/plain; charset=utf-8",
}


@app.get("/document/{document_id:path}")
def get_document(
    document_id: str,
    mode: str = QueryParam(default="operational", pattern="^(operational|training)$"),
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """
    Serve a corpus document file from CORPUS_ROOT/active/<document_id>.

    Mode gating:
      - operational: document must be present in corpus_documents (implicitly active)
      - training:    same (all ingested corpus docs are active; superseded is not
                     implemented at corpus level yet)
      - restricted docs: corpus_documents has no restricted concept — all served docs
                         are active. Seeded fixtures with min_role_level > 0 are NOT
                         served here; use /source for those.

    Security:
      - Path is resolved and checked to be under CORPUS_ROOT/active/ (no traversal).
      - Only .pdf, .docx, and .txt are served; others return 415.
      - File must exist in corpus_documents table (existence not guessable).
    """
    # Validate document exists in DB (prevents guessing arbitrary filenames).
    try:
        doc_row = db.execute(
            text("SELECT rel_path FROM corpus_documents WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception:
        db.rollback()
        doc_row = None

    if not doc_row:
        raise HTTPException(status_code=404, detail="Document not found")

    # Resolve filesystem path and prevent path traversal.
    active_root = (_CORPUS_ROOT / "active").resolve()
    target = (active_root / document_id).resolve()

    if not str(target).startswith(str(active_root) + "/") and target != active_root:
        raise HTTPException(status_code=400, detail="Invalid document path")

    if not target.exists():
        raise HTTPException(status_code=404, detail="Document file not found on disk")

    suffix = target.suffix.lower()
    media_type = _DOC_MEDIA_TYPES.get(suffix)
    if not media_type:
        raise HTTPException(status_code=415, detail=f"Unsupported document type: {suffix}")

    # PDFs and TXT: inline so browser renders in-tab; DOCX: attachment for download.
    disposition = "inline" if suffix in (".pdf", ".txt") else "attachment"
    filename = target.name

    return FileResponse(
        path=str(target),
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Audit (requires auth)
# ---------------------------------------------------------------------------


@app.get("/audit/{query_id}", response_model=AuditResponse)
def get_audit(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    q = db.query(Query).filter(Query.id == query_id).first()
    question = q.question if q else ""
    return AuditResponse(**_build_audit_dict(entry), queryId=query_id, question=question)


@app.get("/audit/{query_id}/verify", response_model=AuditVerifyResponse)
def verify_audit(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")

    valid = verify_entry(
        query_id=query_id,
        timestamp=entry.timestamp,
        role_used=entry.role_used,
        mode_used=entry.mode_used,
        policy_outcome=entry.policy_outcome,
        prev_hash=entry.prev_hash,
        stored_hash=entry.entry_hash,
    )
    return AuditVerifyResponse(
        queryId=query_id,
        valid=valid,
        detail="HMAC matches" if valid else "HMAC mismatch — record may have been tampered",
    )


@app.get("/audit")
def list_audit(
    limit: int = 50,
    offset: int = 0,
    outcome: str | None = None,
    user_email: str | None = None,
    since: str | None = None,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """List audit log entries — officer/authority/custodian (view_all_audit)."""
    if not _has_perm(current_session, "view_all_audit"):
        raise HTTPException(status_code=403, detail="view_all_audit permission required")

    where_clauses: list[str] = []
    params: dict = {"limit": min(limit, 200), "offset": offset}

    if outcome:
        where_clauses.append("al.policy_outcome = :outcome")
        params["outcome"] = outcome
    if user_email:
        where_clauses.append("al.user_email ILIKE :user_email")
        params["user_email"] = f"%{user_email}%"
    if since:
        where_clauses.append("al.timestamp >= :since")
        params["since"] = since

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        rows = db.execute(text(f"""
            SELECT al.query_id, al.receipt_id, al.timestamp,
                   al.role_used, al.mode_used, al.policy_outcome,
                   al.user_email, al.user_display_name,
                   q.question
            FROM audit_log al
            LEFT JOIN queries q ON q.id = al.query_id
            {where_sql}
            ORDER BY al.timestamp DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()

        count_row = db.execute(text(f"""
            SELECT COUNT(*) FROM audit_log al
            {where_sql}
        """), {k: v for k, v in params.items() if k not in ("limit", "offset")}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    total = count_row[0] if count_row else 0
    items = []
    for r in rows:
        items.append({
            "query_id":         r[0],
            "receipt_id":       r[1],
            "timestamp":        r[2],
            "role_used":        r[3],
            "mode_used":        r[4],
            "policy_outcome":   r[5],
            "user_email":       r[6],
            "user_display_name": r[7],
            "question":         r[8] or "",
        })

    return {"total": total, "offset": offset, "limit": limit, "items": items}


# ---------------------------------------------------------------------------
# Evidence bundle export (admin only)
# ---------------------------------------------------------------------------


_ZIP_DATE = (1980, 1, 1, 0, 0, 0)  # deterministic ZipInfo date_time


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip_writestr_det(zf: zipfile.ZipFile, name: str, data: "bytes | str") -> bytes:
    """Write a file into zf with deterministic date_time; return the raw bytes written."""
    raw = data.encode() if isinstance(data, str) else data
    info = zipfile.ZipInfo(filename=name, date_time=_ZIP_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, raw)
    return raw


def _build_evidence_data(
    query_id: str, db: DBSession
) -> "tuple[dict, dict, dict, str, bytes | None, bool, dict | None]":
    """
    Gather all evidence data for a query.

    Returns:
      (guidance, audit_dict, verify_dict, excerpt_text,
       cited_page_pdf, pdf_included, corpus_doc_meta)
    """
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")

    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    audit_dict = _build_audit_dict(entry) if entry else {}

    if entry:
        _valid = verify_entry(
            query_id=query_id,
            timestamp=entry.timestamp,
            role_used=entry.role_used,
            mode_used=entry.mode_used,
            policy_outcome=entry.policy_outcome,
            prev_hash=entry.prev_hash,
            stored_hash=entry.entry_hash,
        )
        verify_dict = {
            "queryId": query_id,
            "valid": _valid,
            "detail": "HMAC matches" if _valid else "HMAC mismatch — record may have been tampered",
        }
    else:
        verify_dict = {"queryId": query_id, "valid": False, "detail": "Audit entry not found"}

    guidance = q.guidance_json or {}
    excerpt_text = guidance.get("excerpt", "")
    cited_page_pdf: bytes | None = None
    corpus_doc_meta: dict | None = None

    if guidance.get("type") == "approved":
        doc = guidance.get("document", {})
        doc_id    = doc.get("documentId", "")
        chunk_idx = doc.get("chunkIndex")
        page_num  = doc.get("page")

        # Full chunk text from DB
        if doc_id and chunk_idx is not None:
            try:
                _chunk_row = db.execute(
                    text("""
                        SELECT cc.text FROM corpus_chunks cc
                        JOIN corpus_documents cd ON cd.id = cc.doc_id
                        WHERE cd.rel_path = :rel AND cc.chunk_index = :idx
                    """),
                    {"rel": doc_id, "idx": chunk_idx},
                ).fetchone()
                if _chunk_row:
                    excerpt_text = _chunk_row[0] or excerpt_text
            except Exception:
                db.rollback()

        # Corpus provenance
        if doc_id:
            try:
                _corp_row = db.execute(
                    text("""
                        SELECT rel_path, sha256, status_override, effective_date, review_date
                        FROM corpus_documents WHERE rel_path = :rel
                    """),
                    {"rel": doc_id},
                ).fetchone()
                if _corp_row:
                    corpus_doc_meta = {
                        "rel_path":        _corp_row[0],
                        "sha256":          _corp_row[1],
                        "status_override": _corp_row[2],
                        "effective_date":  _corp_row[3],
                        "review_date":     _corp_row[4],
                    }
            except Exception:
                db.rollback()

        # Single-page PDF extract
        if doc_id and isinstance(page_num, int):
            _doc_path = (_CORPUS_ROOT / "active" / doc_id).resolve()
            if _doc_path.exists() and _doc_path.suffix.lower() == ".pdf":
                try:
                    from pypdf import PdfReader, PdfWriter
                    _reader = PdfReader(str(_doc_path))
                    if 1 <= page_num <= len(_reader.pages):
                        _writer = PdfWriter()
                        _writer.add_page(_reader.pages[page_num - 1])
                        _pdf_buf = io.BytesIO()
                        _writer.write(_pdf_buf)
                        cited_page_pdf = _pdf_buf.getvalue()
                except Exception:
                    pass

    pdf_included = cited_page_pdf is not None
    return guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta


def _build_manifest(
    query_id: str,
    generated_utc: str,
    file_entries: list[dict],
    pdf_deterministic: bool,
    corpus_doc_meta: "dict | None",
    signed: bool = False,
) -> dict:
    return {
        "schema": "evidence-manifest/v1",
        "query_id": query_id,
        "generated_utc": generated_utc,
        "git": {
            "repo": "keystone-gov",
            "commit": _VERSION,
            "dirty": False,
        },
        "pdf_deterministic": pdf_deterministic,
        "signed": signed,
        "files": file_entries,
        "corpus_document": corpus_doc_meta,
    }


@app.get("/evidence/public-key")
def get_evidence_public_key():
    """Return the Ed25519 public key PEM used to sign evidence manifests.
    No authentication required — the public key is not sensitive.
    """
    _require_signing_key()
    return Response(
        content=_SIGNING_PUBKEY_PEM,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="evidence_ed25519_public.pem"'},
    )


def _build_evidence_files(
    guidance: dict,
    audit_dict: dict,
    verify_dict: dict,
    excerpt_text: str,
    cited_page_pdf: "bytes | None",
) -> "list[tuple[str, bytes]]":
    """Build sorted list of (filename, bytes) for all content files."""
    _guidance_bytes = json.dumps(guidance,    sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _audit_bytes    = json.dumps(audit_dict,  sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _verify_bytes   = json.dumps(verify_dict, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _excerpt_bytes  = excerpt_text.encode() if isinstance(excerpt_text, str) else excerpt_text

    _files: list[tuple[str, bytes]] = [
        ("audit.json",               _audit_bytes),
        ("cited_source_excerpt.txt", _excerpt_bytes),
        ("guidance.json",            _guidance_bytes),
        ("verify.json",              _verify_bytes),
    ]
    if cited_page_pdf is not None:
        page_label = guidance.get("document", {}).get("page", "0")
        _files.append((f"cited_page_{page_label}.pdf", cited_page_pdf))

    # pubkey.pem is included so its hash is in the signed manifest
    if _SIGNING_PUBKEY_PEM is not None:
        _files.append(("pubkey.pem", _SIGNING_PUBKEY_PEM))

    _files.sort(key=lambda x: x[0])
    return _files


@app.get("/evidence/{query_id}/manifest")
def get_evidence_manifest(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Return the evidence manifest JSON for a query (any authenticated role)."""
    _require_signing_key()
    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)

    _files = _build_evidence_files(guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf)

    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]

    # Use audit timestamp as generated_utc so the manifest is deterministic
    # across multiple downloads (not tied to wall-clock time of the request).
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    # Sign the canonical manifest bytes
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]
    manifest["manifest_sig_hex"] = sig_bytes.hex()
    return manifest


@app.get("/evidence/{query_id}.zip")
def get_evidence_zip(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """
    Build and return a deterministic ZIP bundle for a single query (admin only).

    Bundle contents (written in sorted alphabetical order):
      audit.json              — audit receipt fields
      cited_source_excerpt.txt — full text of the cited corpus chunk
      cited_page_<N>.pdf      — single-page PDF extract (if PDF + page known)
      guidance.json           — stored guidance_json for the query
      verify.json             — HMAC chain verification result
      manifest.json           — sha256 of all above files (written last)

    All ZipInfo entries use date_time=(1980,1,1,0,0,0) for determinism.
    JSON files use sort_keys=True for canonical form.
    """
    _require_signing_key()
    if not _has_perm(current_session, "audit_export_governance"):
        raise HTTPException(status_code=403, detail="audit_export_governance permission required")

    # ── Evidence approval gate ─────────────────────────────────────────────────
    _approval_row = None
    if _REQUIRE_EVIDENCE_APPROVAL:
        from datetime import timedelta
        now_utc = datetime.now(timezone.utc)
        try:
            _approval_row = db.execute(text("""
                SELECT id, requested_by, decided_by, decided_at, approved_ttl_seconds,
                       reason, decision_reason
                FROM evidence_export_requests
                WHERE query_id = :qid AND status = 'approved'
                ORDER BY decided_at DESC LIMIT 1
            """), {"qid": query_id}).fetchone()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error checking approval: {exc}")
        if not _approval_row:
            raise HTTPException(status_code=403, detail="APPROVAL_REQUIRED: No approved export request found for this query")
        _decided_at    = _approval_row[3]
        _ttl_secs      = _approval_row[4]
        _expires_at    = _decided_at + timedelta(seconds=_ttl_secs)
        if now_utc > _expires_at:
            raise HTTPException(status_code=403, detail=f"APPROVAL_EXPIRED: Approval expired at {_expires_at.isoformat()}")
        if _TWO_PERSON_CONTROL and _approval_row[1] == _approval_row[2]:
            raise HTTPException(status_code=403, detail="TWO_PERSON_REQUIRED: Requester and approver must be different users")

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)

    _files = _build_evidence_files(guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf)

    # Include approval.json if approval workflow is active and approval exists
    if _REQUIRE_EVIDENCE_APPROVAL and _approval_row is not None:
        from datetime import timedelta as _td
        _dec_at = _approval_row[3]
        _ttl    = _approval_row[4]
        _approval_data = {
            "request_id":      str(_approval_row[0]),
            "query_id":        query_id,
            "requested_by":    _approval_row[1],
            "approved_by":     _approval_row[2],
            "approved_at":     _dec_at.isoformat() if _dec_at else None,
            "ttl_seconds":     _ttl,
            "expires_at":      (_dec_at + _td(seconds=_ttl)).isoformat() if _dec_at else None,
            "reason":          _approval_row[5],
            "decision_reason": _approval_row[6],
        }
        _approval_bytes = json.dumps(_approval_data, sort_keys=True, indent=2, separators=(',', ': ')).encode()
        _files.append(("approval.json", _approval_bytes))
        _files.sort(key=lambda x: x[0])

    # Build manifest using sha256 of each file's bytes.
    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]
    # Use audit timestamp as generated_utc so the manifest is deterministic
    # across multiple downloads (not tied to wall-clock time of the request).
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]

    # Assemble ZIP in memory — sorted content files, manifest.json, manifest.sig last.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)
        _zip_writestr_det(zf, "manifest.sig", sig_bytes)

    filename = f"evidence-{query_id[:8]}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Request body models (KDAT-005)
# ---------------------------------------------------------------------------

class ChangeRequestBody(BaseModel):
    patch: dict
    reason: str = ""

class DecisionBody(BaseModel):
    decision_reason: str = ""

class ExportRequestBody(BaseModel):
    reason: str = ""

class OperatorDecisionBody(BaseModel):
    decision: str  # followed | partial | overridden | no_action
    decision_reason: str = ""
    actions_taken: list = []
    notes: str = ""
    attachments: list = []

class ReviewBody(BaseModel):
    supervisor_reviewed: bool = True

class FeedbackRequest(BaseModel):
    signal_type: str
    comment: "str | None" = None

class CreateCaseBody(BaseModel):
    title: str
    summary: str = ""
    severity: str = "low"
    assigned_to: "str | None" = None
    query_ids: list = []

class PatchCaseBody(BaseModel):
    title: "str | None" = None
    summary: "str | None" = None
    severity: "str | None" = None
    status: "str | None" = None
    assigned_to: "str | None" = None

class AddQueryBody(BaseModel):
    query_id: str


class _ChangeRoleBody(BaseModel):
    role: str  # member | officer | authority


# ---------------------------------------------------------------------------
# Evidence export approval (KDAT-005)
# ---------------------------------------------------------------------------


def _export_req_to_dict(row: tuple) -> dict:
    (req_id, query_id, requested_by, requested_by_role, requested_at,
     reason, status, decided_by, decided_by_role, decided_at,
     decision_reason, approved_ttl_seconds) = row
    expires_at = None
    if status == "approved" and decided_at and approved_ttl_seconds:
        from datetime import timedelta
        expires_at = (decided_at + timedelta(seconds=approved_ttl_seconds)).isoformat()
    return {
        "request_id":         str(req_id),
        "query_id":           query_id,
        "requested_by":       requested_by,
        "requested_by_role":  requested_by_role,
        "requested_at":       requested_at.isoformat() if requested_at else None,
        "reason":             reason,
        "status":             status,
        "decided_by":         decided_by,
        "decided_by_role":    decided_by_role,
        "decided_at":         decided_at.isoformat() if decided_at else None,
        "decision_reason":    decision_reason,
        "approved_ttl_seconds": approved_ttl_seconds,
        "expires_at":         expires_at,
    }


@app.post("/evidence/{query_id}/export-requests")
def create_export_request(
    query_id: str,
    body: ExportRequestBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "audit_export_governance"):
        raise HTTPException(status_code=403, detail="audit_export_governance permission required")
    # Verify query exists
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    try:
        result = db.execute(text("""
            INSERT INTO evidence_export_requests
                (query_id, requested_by, requested_by_role, reason, approved_ttl_seconds)
            VALUES (:qid, :uname, :role, :reason, :ttl)
            RETURNING id
        """), {
            "qid":    query_id,
            "uname":  current_session.username,
            "role":   current_session.role,
            "reason": body.reason,
            "ttl":    _EVIDENCE_APPROVAL_TTL_SECS,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"created": True, "request_id": str(result[0]), "status": "pending"}


@app.get("/evidence/{query_id}/export-requests")
def get_export_requests_for_query(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "audit_export_governance"):
        raise HTTPException(status_code=403, detail="audit_export_governance permission required")
    try:
        rows = db.execute(text("""
            SELECT id, query_id, requested_by, requested_by_role, requested_at,
                   reason, status, decided_by, decided_by_role, decided_at,
                   decision_reason, approved_ttl_seconds
            FROM evidence_export_requests
            WHERE query_id = :qid
            ORDER BY requested_at DESC
        """), {"qid": query_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"query_id": query_id, "requests": [_export_req_to_dict(r) for r in rows]}


@app.post("/evidence/export-requests/{req_id}/approve")
def approve_export_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "audit_export_governance"):
        raise HTTPException(status_code=403, detail="audit_export_governance permission required")
    try:
        row = db.execute(
            text("SELECT id, status, requested_by FROM evidence_export_requests WHERE id=:id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Export request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    if _TWO_PERSON_CONTROL and row[2] == current_session.username:
        raise HTTPException(
            status_code=403,
            detail="TWO_PERSON_REQUIRED: The approver must differ from the requester",
        )
    try:
        db.execute(text("""
            UPDATE evidence_export_requests
            SET status='approved', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"approved": True, "request_id": req_id}


@app.post("/evidence/export-requests/{req_id}/reject")
def reject_export_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "audit_export_governance"):
        raise HTTPException(status_code=403, detail="audit_export_governance permission required")
    try:
        row = db.execute(
            text("SELECT id, status FROM evidence_export_requests WHERE id=:id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Export request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    try:
        db.execute(text("""
            UPDATE evidence_export_requests
            SET status='rejected', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"rejected": True, "request_id": req_id}


# ---------------------------------------------------------------------------
# Operator decisions + incident pack (KDAT-006)
# ---------------------------------------------------------------------------

_DECISION_VALUES = {"followed", "partial", "overridden", "no_action"}

_RUN_ID_RE = re.compile(r'^[a-zA-Z0-9._:\-]{1,80}$')


def _validate_run_id(value: "str | None") -> "str | None":
    """Return value if valid run_id, None if absent, raises 422 if malformed."""
    if not value:
        return None
    if not _RUN_ID_RE.match(value):
        raise HTTPException(
            status_code=422,
            detail="X-Keystone-Run-Id: invalid format (allowed: [a-zA-Z0-9._:-], max 80 chars)",
        )
    return value


def _decision_to_dict(row: tuple) -> dict:
    (dec_id, query_id, created_at_utc, created_by_username, created_by_role,
     decision, decision_reason, actions_taken, notes, attachments,
     supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc) = row
    return {
        "id":                         str(dec_id),
        "query_id":                   query_id,
        "created_at_utc":             created_at_utc.isoformat() if created_at_utc else None,
        "created_by_username":        created_by_username,
        "created_by_role":            created_by_role,
        "decision":                   decision,
        "decision_reason":            decision_reason,
        "actions_taken":              actions_taken or [],
        "notes":                      notes,
        "attachments":                attachments or [],
        "supervisor_reviewed":        supervisor_reviewed,
        "supervisor_username":        supervisor_username,
        "supervisor_reviewed_at_utc": supervisor_reviewed_at_utc.isoformat() if supervisor_reviewed_at_utc else None,
    }


@app.post("/decisions/{query_id}")
def create_operator_decision(
    query_id: str,
    body: OperatorDecisionBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
    x_keystone_run_id: "str | None" = Header(default=None),
):
    """Record an operator decision for a query (member/officer/admin)."""
    run_id = _validate_run_id(x_keystone_run_id)
    if body.decision not in _DECISION_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"decision must be one of: {', '.join(sorted(_DECISION_VALUES))}",
        )
    if body.decision != "followed" and not body.decision_reason.strip():
        raise HTTPException(
            status_code=422,
            detail="decision_reason is required when decision is not 'followed'",
        )
    # Verify query exists
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    # One decision per query
    try:
        existing = db.execute(
            text("SELECT id FROM operator_decisions WHERE query_id = :qid"),
            {"qid": query_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if existing:
        raise HTTPException(status_code=409, detail="A decision already exists for this query")
    try:
        result = db.execute(text("""
            INSERT INTO operator_decisions
                (query_id, created_by_username, created_by_role,
                 decision, decision_reason, actions_taken, notes, attachments,
                 run_id)
            VALUES (:qid, :uname, :role, :decision, :reason,
                    CAST(:actions AS jsonb), :notes, CAST(:attachments AS jsonb),
                    :run_id)
            RETURNING id
        """), {
            "qid":        query_id,
            "uname":      current_session.username,
            "role":       current_session.role,
            "decision":   body.decision,
            "reason":     body.decision_reason,
            "actions":    json.dumps(body.actions_taken),
            "notes":      body.notes,
            "attachments":json.dumps(body.attachments),
            "run_id":     run_id,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"created": True, "decision_id": str(result[0]), "query_id": query_id}


@app.get("/decisions/{query_id}")
def get_operator_decision(
    query_id: str,
    nullable: int = 0,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    """Return the operator decision for a query (any authenticated role).

    nullable=0 (default): 404 when no decision exists (legacy behaviour).
    nullable=1: always 200; body is {"exists": false, "decision": null} when
                no decision has been recorded, or {"exists": true, "decision":
                <full decision object>} when one exists.
    Auth is enforced identically in both modes.
    """
    try:
        row = db.execute(text("""
            SELECT id, query_id, created_at_utc, created_by_username, created_by_role,
                   decision, decision_reason, actions_taken, notes, attachments,
                   supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id = :qid
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        if nullable:
            return {"exists": False, "decision": None}
        raise HTTPException(status_code=404, detail="No decision recorded for this query")
    if nullable:
        return {"exists": True, "decision": _decision_to_dict(row)}
    return _decision_to_dict(row)


@app.patch("/decisions/{query_id}/review")
def review_operator_decision(
    query_id: str,
    body: ReviewBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Supervisor review sign-off (decision_review permission)."""
    if not _has_perm(current_session, "decision_review"):
        raise HTTPException(status_code=403, detail="decision_review permission required")
    try:
        row = db.execute(
            text("SELECT id FROM operator_decisions WHERE query_id = :qid"),
            {"qid": query_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="No decision recorded for this query")
    try:
        db.execute(text("""
            UPDATE operator_decisions
            SET supervisor_reviewed = :reviewed,
                supervisor_username = :uname,
                supervisor_reviewed_at_utc = CASE WHEN :reviewed THEN now() ELSE NULL END
            WHERE query_id = :qid
        """), {
            "reviewed": body.supervisor_reviewed,
            "uname":    current_session.username if body.supervisor_reviewed else None,
            "qid":      query_id,
        })
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"reviewed": True, "query_id": query_id, "supervisor": current_session.username}


# ---------------------------------------------------------------------------
# Feedback signals (KDAT-B)
# ---------------------------------------------------------------------------

_FEEDBACK_SIGNAL_VALUES = {"helpful", "not_helpful"}


@app.post("/feedback/{query_id}", status_code=201)
def create_feedback(
    query_id: str,
    body: FeedbackRequest,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Record a helpfulness signal for a query result."""
    if body.signal_type not in _FEEDBACK_SIGNAL_VALUES:
        raise HTTPException(
            status_code=400,
            detail=f"signal_type must be one of: {', '.join(sorted(_FEEDBACK_SIGNAL_VALUES))}",
        )
    # One feedback entry per user per query
    try:
        existing = db.execute(
            text("SELECT id FROM feedback_signals WHERE query_id = :qid AND created_by = :uid"),
            {"qid": query_id, "uid": current_session.user_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if existing:
        raise HTTPException(status_code=409, detail="Feedback already submitted for this query")
    # Fetch guidance metadata from the stored query
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    guidance = q.guidance_json or {}
    doc_title  = (guidance.get("document") or {}).get("title")
    ans_source = guidance.get("answer_source")
    fcs        = guidance.get("factual_consistency_score")
    try:
        row = db.execute(text("""
            INSERT INTO feedback_signals
                (query_id, signal_type, comment, created_by, created_by_role,
                 document_title, answer_source, factual_consistency_score)
            VALUES (:query_id, :signal_type, :comment, :user_id, :role,
                    :doc_title, :answer_source, :fcs)
            RETURNING id, created_at_utc
        """), {
            "query_id":     query_id,
            "signal_type":  body.signal_type,
            "comment":      body.comment,
            "user_id":      current_session.user_id,
            "role":         current_session.role,
            "doc_title":    doc_title,
            "answer_source": ans_source,
            "fcs":          fcs,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    # Auto-create review task for not_helpful feedback
    review_task_id = None
    if body.signal_type == "not_helpful":
        try:
            # Find the document referenced in the query guidance
            _guidance = q.guidance_json or {}
            _doc_info = _guidance.get("document") or {}
            _doc_title = _doc_info.get("title") or doc_title
            # Try to find corpus_documents row by title
            _corpus_doc = None
            if _doc_title:
                _corpus_doc = db.execute(
                    text("SELECT id FROM corpus_documents WHERE title = :title LIMIT 1"),
                    {"title": _doc_title}
                ).fetchone()
            # Try to find active version for this document
            _source_version_id = None
            if _corpus_doc:
                _ver_row = db.execute(
                    text("SELECT id FROM document_versions WHERE doc_id = :did AND status = 'active' LIMIT 1"),
                    {"did": _corpus_doc[0]}
                ).fetchone()
                _source_version_id = _ver_row[0] if _ver_row else None
            _task_row = db.execute(text("""
                INSERT INTO review_tasks (feedback_signal_id, doc_id, source_version_id, status)
                VALUES (:fid, :did, :vid, 'open')
                RETURNING id
            """), {
                "fid": str(row[0]),
                "did": _corpus_doc[0] if _corpus_doc else 0,
                "vid": _source_version_id,
            }).fetchone()
            db.commit()
            review_task_id = str(_task_row[0]) if _task_row else None
        except Exception:
            # Migration 24 may not yet be applied; degrade gracefully
            db.rollback()
            review_task_id = None

    return {
        "id":                       str(row[0]),
        "query_id":                 query_id,
        "signal_type":              body.signal_type,
        "comment":                  body.comment,
        "created_by":               current_session.user_id,
        "created_by_role":          current_session.role,
        "created_at_utc":           row[1].isoformat() if row[1] else None,
        "document_title":           doc_title,
        "answer_source":            ans_source,
        "factual_consistency_score": fcs,
        "review_task_id":           review_task_id,
    }


@app.get("/feedback/{query_id}")
def get_feedback(
    query_id: str,
    nullable: int = 0,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    """Return the most recent feedback signal for a query.

    nullable=0 (default): 404 when no feedback exists.
    nullable=1: always 200; body is null when no feedback has been recorded.
    """
    try:
        row = db.execute(text("""
            SELECT id, query_id, signal_type, comment, created_by, created_by_role,
                   created_at_utc, document_title, answer_source, factual_consistency_score
            FROM feedback_signals
            WHERE query_id = :qid
            ORDER BY created_at_utc DESC
            LIMIT 1
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        if nullable:
            return None
        raise HTTPException(status_code=404, detail="No feedback recorded for this query")
    signal = {
        "id":                       str(row[0]),
        "query_id":                 row[1],
        "signal_type":              row[2],
        "comment":                  row[3],
        "created_by":               row[4],
        "created_by_role":          row[5],
        "created_at_utc":           row[6].isoformat() if row[6] else None,
        "document_title":           row[7],
        "answer_source":            row[8],
        "factual_consistency_score": row[9],
    }
    if nullable:
        return signal
    return signal


# ---------------------------------------------------------------------------
# Document Version Tracking
# ---------------------------------------------------------------------------

_VERSION_CREATE_ROLES = {"custodian", "authority"}
_VERSION_APPROVE_ROLES = {"authority"}


def _version_to_dict(row: tuple) -> dict:
    """Convert a document_versions SELECT row to dict.

    Columns (positional):
      0  id, 1 doc_id, 2 version_number, 3 status,
      4  effective_from, 5 effective_to, 6 supersedes_version_id,
      7  content_hash, 8 file_path, 9 change_summary,
      10 created_by, 11 approved_by, 12 published_at, 13 created_at
    """
    (vid, doc_id, version_number, status,
     effective_from, effective_to, supersedes_version_id,
     content_hash, file_path, change_summary,
     created_by, approved_by, published_at, created_at) = row
    return {
        "id":                    vid,
        "doc_id":                doc_id,
        "version_number":        version_number,
        "status":                status,
        "effective_from":        effective_from.isoformat() if effective_from else None,
        "effective_to":          effective_to.isoformat() if effective_to else None,
        "supersedes_version_id": supersedes_version_id,
        "content_hash":          content_hash,
        "file_path":             file_path,
        "change_summary":        change_summary,
        "created_by":            created_by,
        "approved_by":           approved_by,
        "published_at":          published_at.isoformat() if published_at else None,
        "created_at":            created_at.isoformat() if created_at else None,
    }


_VERSION_SELECT = """
    SELECT id, doc_id, version_number, status,
           effective_from, effective_to, supersedes_version_id,
           content_hash, file_path, change_summary,
           created_by, approved_by, published_at, created_at
    FROM document_versions
"""


@app.get("/versions/{doc_id}")
def list_versions(
    doc_id: int,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    """List all versions for a corpus document, ordered by version_number desc."""
    try:
        doc_row = db.execute(
            text("SELECT id FROM corpus_documents WHERE id = :doc_id"),
            {"doc_id": doc_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not doc_row:
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        rows = db.execute(
            text(f"{_VERSION_SELECT} WHERE doc_id = :doc_id ORDER BY version_number DESC"),
            {"doc_id": doc_id},
        ).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"doc_id": doc_id, "versions": [_version_to_dict(r) for r in rows]}


@app.get("/versions/{doc_id}/current")
def get_current_version(
    doc_id: int,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    """Get the currently active version for a document."""
    try:
        row = db.execute(
            text(f"{_VERSION_SELECT} WHERE doc_id = :doc_id AND status = 'active'"),
            {"doc_id": doc_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="No active version for this document")
    return _version_to_dict(row)


@app.get("/versions/{doc_id}/at/{as_of}")
def get_version_at(
    doc_id: int,
    as_of: str,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    """Get the version that was active at a specific point in time."""
    try:
        as_of_dt = datetime.fromisoformat(as_of)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid as_of datetime: {as_of!r}")
    try:
        row = db.execute(
            text(f"""
                {_VERSION_SELECT}
                WHERE doc_id = :doc_id
                  AND effective_from <= :as_of
                  AND (effective_to IS NULL OR effective_to > :as_of)
            """),
            {"doc_id": doc_id, "as_of": as_of_dt},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail=f"No version active at {as_of}")
    return _version_to_dict(row)


@app.post("/versions", status_code=201)
def create_version(
    body: CreateVersionRequest,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Create a new draft version for a document (custodian or authority)."""
    if current_session.role not in _VERSION_CREATE_ROLES:
        raise HTTPException(status_code=403, detail="custodian or authority role required")

    # Verify corpus document exists
    try:
        doc_row = db.execute(
            text("SELECT id, sha256 FROM corpus_documents WHERE id = :doc_id"),
            {"doc_id": body.doc_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not doc_row:
        raise HTTPException(status_code=404, detail="Document not found")

    doc_sha256 = doc_row[1]

    # Find next version_number
    try:
        max_row = db.execute(
            text("SELECT MAX(version_number) FROM document_versions WHERE doc_id = :doc_id"),
            {"doc_id": body.doc_id},
        ).fetchone()
        next_version = (max_row[0] or 0) + 1

        actor = current_session.email

        new_ver = db.execute(
            text("""
                INSERT INTO document_versions
                    (doc_id, version_number, status, content_hash, change_summary, created_by, created_at)
                VALUES
                    (:doc_id, :version_number, 'draft', :content_hash, :change_summary, :created_by, now())
                RETURNING id, doc_id, version_number, status,
                          effective_from, effective_to, supersedes_version_id,
                          content_hash, file_path, change_summary,
                          created_by, approved_by, published_at, created_at
            """),
            {
                "doc_id":         body.doc_id,
                "version_number": next_version,
                "content_hash":   doc_sha256,
                "change_summary": body.change_summary,
                "created_by":     actor,
            },
        ).fetchone()

        db.execute(
            text("""
                INSERT INTO version_events (version_id, event_type, actor, actor_role, created_at)
                VALUES (:version_id, 'created', :actor, :actor_role, now())
            """),
            {
                "version_id": new_ver[0],
                "actor":      actor,
                "actor_role": current_session.role,
            },
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _version_to_dict(new_ver)


@app.post("/versions/{version_id}/approve")
def approve_version(
    version_id: int,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Approve a version, activating it and superseding the previous active version."""
    if current_session.role not in _VERSION_APPROVE_ROLES:
        raise HTTPException(status_code=403, detail="authority role required")

    try:
        ver_row = db.execute(
            text(f"{_VERSION_SELECT} WHERE id = :vid"),
            {"vid": version_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not ver_row:
        raise HTTPException(status_code=404, detail="Version not found")

    ver = _version_to_dict(ver_row)

    # Separation of duties: approver must not be the creator
    if ver["created_by"] == current_session.email:
        raise HTTPException(
            status_code=403,
            detail="Separation of duties: version creator cannot approve their own version",
        )

    if ver["status"] not in ("draft", "pending_review"):
        raise HTTPException(
            status_code=400,
            detail=f"Version status is '{ver['status']}'; only draft or pending_review can be approved",
        )

    actor = current_session.email
    actor_role = current_session.role

    try:
        # Find current active version for this doc (if any)
        old_row = db.execute(
            text(f"{_VERSION_SELECT} WHERE doc_id = :doc_id AND status = 'active'"),
            {"doc_id": ver["doc_id"]},
        ).fetchone()
        old_ver = _version_to_dict(old_row) if old_row else None

        if old_ver:
            # Supersede the old active version
            db.execute(
                text("""
                    UPDATE document_versions
                    SET status = 'superseded', effective_to = now()
                    WHERE id = :old_id
                """),
                {"old_id": old_ver["id"]},
            )
            db.execute(
                text("""
                    INSERT INTO version_events (version_id, event_type, actor, actor_role, created_at)
                    VALUES (:version_id, 'superseded', :actor, :actor_role, now())
                """),
                {"version_id": old_ver["id"], "actor": actor, "actor_role": actor_role},
            )

        # Activate the new version
        db.execute(
            text("""
                UPDATE document_versions
                SET status = 'active',
                    effective_from = now(),
                    approved_by = :approved_by,
                    published_at = now(),
                    supersedes_version_id = :supersedes_id
                WHERE id = :vid
            """),
            {
                "approved_by":    actor,
                "supersedes_id":  old_ver["id"] if old_ver else None,
                "vid":            version_id,
            },
        )
        db.execute(
            text("""
                INSERT INTO version_events (version_id, event_type, actor, actor_role, created_at)
                VALUES (:version_id, 'approved', :actor, :actor_role, now())
            """),
            {"version_id": version_id, "actor": actor, "actor_role": actor_role},
        )
        db.execute(
            text("""
                INSERT INTO version_events (version_id, event_type, actor, actor_role, created_at)
                VALUES (:version_id, 'published', :actor, :actor_role, now())
            """),
            {"version_id": version_id, "actor": actor, "actor_role": actor_role},
        )
        db.commit()

        # Reload activated version
        new_row = db.execute(
            text(f"{_VERSION_SELECT} WHERE id = :vid"),
            {"vid": version_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {
        "version":    _version_to_dict(new_row),
        "superseded": old_ver,
    }


# ---------------------------------------------------------------------------
# Review Workflow
# ---------------------------------------------------------------------------

_REVIEW_MIN_ROLE_LEVEL = 1   # custodian (0), officer (1), authority (2)
_RESOLUTION_TYPE_TO_DECISION = {
    "new_version_published": "publish_new_version",
    "no_change_needed":      "no_change",
    "escalated":             "escalate",
    "duplicate":             "no_change",
}


def _task_to_dict(row: tuple) -> dict:
    """Convert a review_tasks SELECT row to dict.

    Columns (positional):
      0  id, 1 feedback_signal_id, 2 doc_id, 3 source_version_id,
      4  status, 5 assigned_to, 6 priority,
      7  resolution_type, 8 resolution_note, 9 resolved_by,
      10 created_at, 11 assigned_at, 12 resolved_at
    """
    (tid, feedback_signal_id, doc_id, source_version_id,
     status, assigned_to, priority,
     resolution_type, resolution_note, resolved_by,
     created_at, assigned_at, resolved_at) = row[:13]
    return {
        "id":                  str(tid),
        "feedback_signal_id":  str(feedback_signal_id),
        "doc_id":              doc_id,
        "source_version_id":   source_version_id,
        "status":              status,
        "assigned_to":         assigned_to,
        "priority":            priority,
        "resolution_type":     resolution_type,
        "resolution_note":     resolution_note,
        "resolved_by":         resolved_by,
        "created_at":          created_at.isoformat() if created_at else None,
        "assigned_at":         assigned_at.isoformat() if assigned_at else None,
        "resolved_at":         resolved_at.isoformat() if resolved_at else None,
    }


_TASK_SELECT = """
    SELECT id, feedback_signal_id, doc_id, source_version_id,
           status, assigned_to, priority,
           resolution_type, resolution_note, resolved_by,
           created_at, assigned_at, resolved_at
    FROM review_tasks
"""


def _comment_to_dict(row: tuple) -> dict:
    (cid, task_id, author, author_role, body, created_at) = row
    return {
        "id":          str(cid),
        "task_id":     str(task_id),
        "author":      author,
        "author_role": author_role,
        "body":        body,
        "created_at":  created_at.isoformat() if created_at else None,
    }


def _pub_decision_to_dict(row: tuple) -> dict:
    (did, review_task_id, old_vid, new_vid,
     decision, decided_by, decided_by_role, decided_at) = row
    return {
        "id":              str(did),
        "review_task_id":  str(review_task_id),
        "old_version_id":  old_vid,
        "new_version_id":  new_vid,
        "decision":        decision,
        "decided_by":      decided_by,
        "decided_by_role": decided_by_role,
        "decided_at":      decided_at.isoformat() if decided_at else None,
    }


@app.get("/review/tasks")
def list_review_tasks(
    status: "str | None" = QueryParam(default=None),
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """List review tasks with optional status filter (custodian, officer, or authority)."""
    if _ROLE_LEVEL.get(current_session.role, -1) < _REVIEW_MIN_ROLE_LEVEL:
        raise HTTPException(status_code=403, detail="officer or authority role required")

    params: dict = {}
    where = ""
    if status:
        where = "WHERE rt.status = :status"
        params["status"] = status

    try:
        rows = db.execute(text(f"""
            SELECT rt.id, rt.feedback_signal_id, rt.doc_id, rt.source_version_id,
                   rt.status, rt.assigned_to, rt.priority,
                   rt.resolution_type, rt.resolution_note, rt.resolved_by,
                   rt.created_at, rt.assigned_at, rt.resolved_at,
                   cd.title AS document_title,
                   fs.comment AS feedback_comment
            FROM review_tasks rt
            LEFT JOIN corpus_documents cd ON cd.id = rt.doc_id
            LEFT JOIN feedback_signals fs ON fs.id = rt.feedback_signal_id
            {where}
            ORDER BY rt.created_at DESC
        """), params).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    items = []
    for r in rows:
        task = _task_to_dict(r[:13])
        task["document_title"]    = r[13]
        task["feedback_snippet"]  = (r[14] or "")[:100] if r[14] else None
        items.append(task)
    return {"tasks": items}


@app.get("/review/tasks/{task_id}")
def get_review_task(
    task_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Full task detail including feedback, source version, and comments."""
    if _ROLE_LEVEL.get(current_session.role, -1) < _REVIEW_MIN_ROLE_LEVEL:
        raise HTTPException(status_code=403, detail="officer or authority role required")

    try:
        task_row = db.execute(
            text(f"{_TASK_SELECT} WHERE id = :tid"),
            {"tid": task_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not task_row:
        raise HTTPException(status_code=404, detail="Review task not found")

    task = _task_to_dict(task_row)

    # Feedback detail
    feedback = None
    try:
        fb_row = db.execute(text("""
            SELECT fs.id, fs.query_id, fs.signal_type, fs.comment,
                   fs.created_by, fs.created_by_role, fs.created_at_utc,
                   fs.document_title, fs.answer_source, fs.factual_consistency_score,
                   q.question
            FROM feedback_signals fs
            LEFT JOIN queries q ON q.id = fs.query_id
            WHERE fs.id = :fid
        """), {"fid": task["feedback_signal_id"]}).fetchone()
        if fb_row:
            feedback = {
                "id":                       str(fb_row[0]),
                "query_id":                 fb_row[1],
                "signal_type":              fb_row[2],
                "comment":                  fb_row[3],
                "created_by":               fb_row[4],
                "created_by_role":          fb_row[5],
                "created_at_utc":           fb_row[6].isoformat() if fb_row[6] else None,
                "document_title":           fb_row[7],
                "answer_source":            fb_row[8],
                "factual_consistency_score": fb_row[9],
                "question":                 fb_row[10],
            }
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    # Source version info
    source_version = None
    if task.get("source_version_id"):
        try:
            ver_row = db.execute(
                text(f"{_VERSION_SELECT} WHERE id = :vid"),
                {"vid": task["source_version_id"]},
            ).fetchone()
            if ver_row:
                source_version = _version_to_dict(ver_row)
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    # Comments
    try:
        comment_rows = db.execute(text("""
            SELECT id, task_id, author, author_role, body, created_at
            FROM review_comments
            WHERE task_id = :tid
            ORDER BY created_at ASC
        """), {"tid": task_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {
        "task":           task,
        "feedback":       feedback,
        "source_version": source_version,
        "comments":       [_comment_to_dict(r) for r in comment_rows],
    }


@app.post("/review/tasks/{task_id}/assign")
def assign_review_task(
    task_id: str,
    body: AssignTaskRequest,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Assign a review task to a user (authority only)."""
    if current_session.role != "authority":
        raise HTTPException(status_code=403, detail="authority role required")

    try:
        task_row = db.execute(
            text(f"{_TASK_SELECT} WHERE id = :tid"),
            {"tid": task_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not task_row:
        raise HTTPException(status_code=404, detail="Review task not found")

    task = _task_to_dict(task_row)
    if task["status"] != "open":
        raise HTTPException(status_code=400, detail=f"Task status is '{task['status']}'; only open tasks can be assigned")

    try:
        updated = db.execute(text("""
            UPDATE review_tasks
            SET status = 'assigned', assigned_to = :assigned_to, assigned_at = now()
            WHERE id = :tid
            RETURNING id, feedback_signal_id, doc_id, source_version_id,
                      status, assigned_to, priority,
                      resolution_type, resolution_note, resolved_by,
                      created_at, assigned_at, resolved_at
        """), {"assigned_to": body.assigned_to, "tid": task_id}).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _task_to_dict(updated)


@app.post("/review/tasks/{task_id}/comment", status_code=201)
def add_review_comment(
    task_id: str,
    body: ReviewCommentRequest,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Add a comment to a review task (custodian, officer, or authority)."""
    if _ROLE_LEVEL.get(current_session.role, -1) < _REVIEW_MIN_ROLE_LEVEL:
        raise HTTPException(status_code=403, detail="officer or authority role required")

    try:
        task_row = db.execute(
            text(f"{_TASK_SELECT} WHERE id = :tid"),
            {"tid": task_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not task_row:
        raise HTTPException(status_code=404, detail="Review task not found")

    task = _task_to_dict(task_row)
    if task["status"] not in ("open", "assigned", "in_review"):
        raise HTTPException(
            status_code=400,
            detail=f"Task status is '{task['status']}'; comments are not allowed on resolved or dismissed tasks",
        )

    try:
        comment_row = db.execute(text("""
            INSERT INTO review_comments (task_id, author, author_role, body, created_at)
            VALUES (:tid, :author, :author_role, :body, now())
            RETURNING id, task_id, author, author_role, body, created_at
        """), {
            "tid":         task_id,
            "author":      current_session.user_id,
            "author_role": current_session.role,
            "body":        body.body,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _comment_to_dict(comment_row)


@app.post("/review/tasks/{task_id}/resolve")
def resolve_review_task(
    task_id: str,
    body: ResolveTaskRequest,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Resolve a review task (custodian, officer, or authority). Separation of duties enforced."""
    if _ROLE_LEVEL.get(current_session.role, -1) < _REVIEW_MIN_ROLE_LEVEL:
        raise HTTPException(status_code=403, detail="officer or authority role required")

    valid_resolution_types = {"new_version_published", "no_change_needed", "escalated", "duplicate"}
    if body.resolution_type not in valid_resolution_types:
        raise HTTPException(
            status_code=400,
            detail=f"resolution_type must be one of: {', '.join(sorted(valid_resolution_types))}",
        )

    try:
        task_row = db.execute(
            text(f"{_TASK_SELECT} WHERE id = :tid"),
            {"tid": task_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not task_row:
        raise HTTPException(status_code=404, detail="Review task not found")

    task = _task_to_dict(task_row)
    if task["status"] not in ("open", "assigned", "in_review"):
        raise HTTPException(
            status_code=400,
            detail=f"Task status is '{task['status']}'; only open, assigned, or in_review tasks can be resolved",
        )

    # Separation of duties: look up feedback submitter
    try:
        fb_row = db.execute(
            text("SELECT created_by FROM feedback_signals WHERE id = :fid"),
            {"fid": task["feedback_signal_id"]},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if fb_row and fb_row[0] == current_session.user_id:
        raise HTTPException(
            status_code=403,
            detail="Separation of duties: feedback submitter cannot resolve their own task",
        )

    # If publishing a new version, verify it exists
    if body.resolution_type == "new_version_published":
        if not body.new_version_id:
            raise HTTPException(status_code=400, detail="new_version_id required when resolution_type is 'new_version_published'")
        try:
            ver_check = db.execute(
                text("SELECT id FROM document_versions WHERE id = :vid"),
                {"vid": body.new_version_id},
            ).fetchone()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error: {exc}")
        if not ver_check:
            raise HTTPException(status_code=404, detail=f"document_versions id {body.new_version_id} not found")

    decision_value = _RESOLUTION_TYPE_TO_DECISION.get(body.resolution_type, "no_change")
    actor = current_session.user_id

    try:
        pub_row = db.execute(text("""
            INSERT INTO publication_decisions
                (review_task_id, old_version_id, new_version_id, decision, decided_by, decided_by_role, decided_at)
            VALUES
                (:tid, :old_vid, :new_vid, :decision, :decided_by, :decided_by_role, now())
            RETURNING id, review_task_id, old_version_id, new_version_id,
                      decision, decided_by, decided_by_role, decided_at
        """), {
            "tid":            task_id,
            "old_vid":        task["source_version_id"],
            "new_vid":        body.new_version_id,
            "decision":       decision_value,
            "decided_by":     actor,
            "decided_by_role": current_session.role,
        }).fetchone()

        updated = db.execute(text("""
            UPDATE review_tasks
            SET status = 'resolved',
                resolution_type = :resolution_type,
                resolution_note = :resolution_note,
                resolved_by = :resolved_by,
                resolved_at = now()
            WHERE id = :tid
            RETURNING id, feedback_signal_id, doc_id, source_version_id,
                      status, assigned_to, priority,
                      resolution_type, resolution_note, resolved_by,
                      created_at, assigned_at, resolved_at
        """), {
            "resolution_type": body.resolution_type,
            "resolution_note": body.resolution_note,
            "resolved_by":     actor,
            "tid":             task_id,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {
        "task":                 _task_to_dict(updated),
        "publication_decision": _pub_decision_to_dict(pub_row),
    }


@app.post("/review/tasks/{task_id}/dismiss")
def dismiss_review_task(
    task_id: str,
    body: DismissTaskRequest,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Dismiss a review task (authority only)."""
    if current_session.role != "authority":
        raise HTTPException(status_code=403, detail="authority role required")

    try:
        task_row = db.execute(
            text(f"{_TASK_SELECT} WHERE id = :tid"),
            {"tid": task_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not task_row:
        raise HTTPException(status_code=404, detail="Review task not found")

    task = _task_to_dict(task_row)
    if task["status"] not in ("open", "assigned", "in_review"):
        raise HTTPException(
            status_code=400,
            detail=f"Task status is '{task['status']}'; only open, assigned, or in_review tasks can be dismissed",
        )

    try:
        updated = db.execute(text("""
            UPDATE review_tasks
            SET status = 'dismissed',
                resolution_note = :resolution_note,
                resolved_by = :resolved_by,
                resolved_at = now()
            WHERE id = :tid
            RETURNING id, feedback_signal_id, doc_id, source_version_id,
                      status, assigned_to, priority,
                      resolution_type, resolution_note, resolved_by,
                      created_at, assigned_at, resolved_at
        """), {
            "resolution_note": body.resolution_note,
            "resolved_by":     current_session.user_id,
            "tid":             task_id,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _task_to_dict(updated)


@app.get("/audit/chain/{feedback_signal_id}")
def get_audit_chain(
    feedback_signal_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Reconstruct full governance chain from a feedback signal (authority only)."""
    if current_session.role != "authority":
        raise HTTPException(status_code=403, detail="authority role required")

    try:
        fb_row = db.execute(text("""
            SELECT id, query_id, signal_type, comment, created_by, created_by_role,
                   created_at_utc, document_title, answer_source, factual_consistency_score
            FROM feedback_signals
            WHERE id = :fid
        """), {"fid": feedback_signal_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not fb_row:
        raise HTTPException(status_code=404, detail="Feedback signal not found")

    feedback = {
        "id":                       str(fb_row[0]),
        "query_id":                 fb_row[1],
        "signal_type":              fb_row[2],
        "comment":                  fb_row[3],
        "created_by":               fb_row[4],
        "created_by_role":          fb_row[5],
        "created_at_utc":           fb_row[6].isoformat() if fb_row[6] else None,
        "document_title":           fb_row[7],
        "answer_source":            fb_row[8],
        "factual_consistency_score": fb_row[9],
    }

    try:
        task_rows = db.execute(
            text(f"{_TASK_SELECT} WHERE feedback_signal_id = :fid ORDER BY created_at ASC"),
            {"fid": feedback_signal_id},
        ).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    tasks_out = []
    versions_seen: dict = {}

    for task_row in task_rows:
        task = _task_to_dict(task_row)

        # Comments for this task
        try:
            comment_rows = db.execute(text("""
                SELECT id, task_id, author, author_role, body, created_at
                FROM review_comments
                WHERE task_id = :tid
                ORDER BY created_at ASC
            """), {"tid": task["id"]}).fetchall()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error: {exc}")

        # Publication decisions for this task
        try:
            pd_rows = db.execute(text("""
                SELECT id, review_task_id, old_version_id, new_version_id,
                       decision, decided_by, decided_by_role, decided_at
                FROM publication_decisions
                WHERE review_task_id = :tid
                ORDER BY decided_at ASC
            """), {"tid": task["id"]}).fetchall()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error: {exc}")

        decisions = []
        for pd in pd_rows:
            decisions.append(_pub_decision_to_dict(pd))
            for vid in (pd[2], pd[3]):  # old_version_id, new_version_id
                if vid and vid not in versions_seen:
                    try:
                        vrow = db.execute(
                            text(f"{_VERSION_SELECT} WHERE id = :vid"),
                            {"vid": vid},
                        ).fetchone()
                        if vrow:
                            versions_seen[vid] = _version_to_dict(vrow)
                    except Exception:
                        pass

        task["comments"]             = [_comment_to_dict(r) for r in comment_rows]
        task["publication_decisions"] = decisions
        tasks_out.append(task)

    return {
        "feedback":     feedback,
        "review_tasks": tasks_out,
        "versions":     versions_seen,
    }


def _build_incident_files(
    guidance: dict,
    audit_dict: dict,
    verify_dict: dict,
    excerpt_text: str,
    cited_page_pdf: "bytes | None",
    decision_dict: dict,
    approval_row: "tuple | None" = None,
) -> "list[tuple[str, bytes]]":
    """Build sorted (name, bytes) list for incident pack content files."""
    _files = _build_evidence_files(guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf)

    # operator_decision.json
    _dec_bytes = json.dumps(decision_dict, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _files.append(("operator_decision.json", _dec_bytes))

    # approval.json if present
    if approval_row is not None:
        from datetime import timedelta as _td
        _dec_at = approval_row[3]
        _ttl    = approval_row[4]
        _appr_data = {
            "request_id":      str(approval_row[0]),
            "query_id":        audit_dict.get("queryId", ""),
            "requested_by":    approval_row[1],
            "approved_by":     approval_row[2],
            "approved_at":     _dec_at.isoformat() if _dec_at else None,
            "ttl_seconds":     _ttl,
            "expires_at":      (_dec_at + _td(seconds=_ttl)).isoformat() if _dec_at else None,
            "reason":          approval_row[5],
            "decision_reason": approval_row[6],
        }
        _appr_bytes = json.dumps(_appr_data, sort_keys=True, indent=2, separators=(',', ': ')).encode()
        _files.append(("approval.json", _appr_bytes))

    _files.sort(key=lambda x: x[0])
    return _files


@app.get("/incident/{query_id}/manifest")
def get_incident_manifest(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Return the incident pack manifest JSON (decision_review permission)."""
    _require_signing_key()
    if not _has_perm(current_session, "decision_review"):
        raise HTTPException(status_code=403, detail="decision_review permission required")

    # Require decision
    try:
        dec_row = db.execute(text("""
            SELECT id, query_id, created_at_utc, created_by_username, created_by_role,
                   decision, decision_reason, actions_taken, notes, attachments,
                   supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id = :qid
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not dec_row:
        raise HTTPException(status_code=409, detail="No operator decision recorded for this query — record a decision before exporting an incident pack")

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)
    decision_dict = _decision_to_dict(dec_row)

    _files = _build_incident_files(
        guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, decision_dict
    )
    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    manifest["schema"] = "incident-manifest/v1"
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]
    manifest["manifest_sig_hex"] = sig_bytes.hex()
    return manifest


def _build_incident_pack_zip(query_id: str, db: DBSession) -> bytes:
    """
    Core builder: deterministic signed incident pack ZIP bytes.
    Raises HTTPException(409) if no decision.
    Raises HTTPException(403) if REQUIRE_EVIDENCE_APPROVAL=1 and approval missing/expired.
    Called by both the HTTP handler and the case pack builder.
    """
    try:
        dec_row = db.execute(text("""
            SELECT id, query_id, created_at_utc, created_by_username, created_by_role,
                   decision, decision_reason, actions_taken, notes, attachments,
                   supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id = :qid
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not dec_row:
        raise HTTPException(
            status_code=409,
            detail=f"No operator decision recorded for query {query_id[:8]}… — record a decision first",
        )

    _approval_row = None
    if _REQUIRE_EVIDENCE_APPROVAL:
        from datetime import timedelta
        now_utc = datetime.now(timezone.utc)
        try:
            _approval_row = db.execute(text("""
                SELECT id, requested_by, decided_by, decided_at, approved_ttl_seconds,
                       reason, decision_reason
                FROM evidence_export_requests
                WHERE query_id = :qid AND status = 'approved'
                ORDER BY decided_at DESC LIMIT 1
            """), {"qid": query_id}).fetchone()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error checking approval: {exc}")
        if not _approval_row:
            raise HTTPException(
                status_code=403,
                detail=f"APPROVAL_REQUIRED: No approved export request for query {query_id[:8]}…",
            )
        _decided_at = _approval_row[3]
        _ttl_secs   = _approval_row[4]
        _expires_at = _decided_at + timedelta(seconds=_ttl_secs)
        if now_utc > _expires_at:
            raise HTTPException(
                status_code=403,
                detail=f"APPROVAL_EXPIRED: Approval for query {query_id[:8]}… expired at {_expires_at.isoformat()}",
            )

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)
    decision_dict = _decision_to_dict(dec_row)
    _files = _build_incident_files(
        guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf,
        decision_dict, _approval_row,
    )

    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    manifest["schema"] = "incident-manifest/v1"
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)
        _zip_writestr_det(zf, "manifest.sig", sig_bytes)
    return buf.getvalue()


@app.get("/incident/{query_id}/pack.zip")
def get_incident_pack(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Build and return a signed incident pack ZIP (decision_review permission)."""
    _require_signing_key()
    if not _has_perm(current_session, "decision_review"):
        raise HTTPException(status_code=403, detail="decision_review permission required")
    zip_bytes = _build_incident_pack_zip(query_id, db)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="incident-{query_id[:8]}.zip"'},
    )


# ---------------------------------------------------------------------------
# Supervisor review queue + incident cases (KDAT-007)
# ---------------------------------------------------------------------------

_CASE_SEVERITIES = {"low", "med", "high", "critical"}
_CASE_STATUSES   = {"open", "closed"}


def _case_to_dict(row: tuple, query_count: int = 0) -> dict:
    (case_id, created_at_utc, created_by, status, severity, title,
     summary, assigned_to, closed_at_utc) = row[:9]
    return {
        "case_id":        str(case_id),
        "created_at_utc": created_at_utc.isoformat() if created_at_utc else None,
        "created_by":     created_by,
        "status":         status,
        "severity":       severity,
        "title":          title,
        "summary":        summary,
        "assigned_to":    assigned_to,
        "closed_at_utc":  closed_at_utc.isoformat() if closed_at_utc else None,
        "query_count":    query_count,
    }


# ── Review queue ──────────────────────────────────────────────────────────────

@app.get("/review-queue")
def get_supervisor_review_queue(
    limit: int = QueryParam(default=25, ge=1, le=200),
    offset: int = QueryParam(default=0, ge=0),
    decision: "str | None" = QueryParam(default=None),
    unreviewed_only: int = QueryParam(default=0),
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """
    List queries that have an operator decision, optionally filtered to
    those not yet reviewed by a supervisor (decision_review permission).
    """
    if not _has_perm(current_session, "decision_review"):
        raise HTTPException(status_code=403, detail="decision_review permission required")

    where_clauses = []
    params: dict = {"limit": limit, "offset": offset}
    if unreviewed_only:
        where_clauses.append("od.supervisor_reviewed = FALSE")
    if decision:
        where_clauses.append("od.decision = :decision")
        params["decision"] = decision

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        rows = db.execute(text(f"""
            SELECT q.id, q.question, q.scenario_key, q.mode,
                   od.decision, od.decision_reason,
                   od.created_by_username, od.created_by_role, od.created_at_utc,
                   od.supervisor_reviewed, od.supervisor_username, od.supervisor_reviewed_at_utc,
                   al.role_used, al.policy_outcome, al.timestamp AS audit_ts
            FROM queries q
            JOIN operator_decisions od ON od.query_id = q.id
            LEFT JOIN audit_log al ON al.query_id = q.id
            {where_sql}
            ORDER BY od.created_at_utc DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()

        count_row = db.execute(text(f"""
            SELECT COUNT(*)
            FROM queries q
            JOIN operator_decisions od ON od.query_id = q.id
            {where_sql}
        """), {k: v for k, v in params.items() if k not in ("limit", "offset")}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    total = count_row[0] if count_row else 0

    items = []
    for r in rows:
        items.append({
            "query_id":                   r[0],
            "question":                   r[1],
            "scenario_key":               r[2],
            "mode":                       r[3],
            "decision":                   r[4],
            "decision_reason":            r[5],
            "decision_by":                r[6],
            "decision_by_role":           r[7],
            "decision_at":                r[8].isoformat() if r[8] else None,
            "supervisor_reviewed":        r[9],
            "supervisor_username":        r[10],
            "supervisor_reviewed_at_utc": r[11].isoformat() if r[11] else None,
            "role_used":                  r[12],
            "policy_outcome":             r[13],
            "audit_timestamp":            r[14],
        })

    return {"total": total, "offset": offset, "limit": limit, "items": items}


# ── Cases CRUD ────────────────────────────────────────────────────────────────

@app.post("/cases")
def create_case(
    body: CreateCaseBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
    x_keystone_run_id: "str | None" = Header(default=None),
):
    """Create a new incident case (case_management permission)."""
    run_id = _validate_run_id(x_keystone_run_id)
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")
    if body.severity not in _CASE_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of: {', '.join(sorted(_CASE_SEVERITIES))}")

    try:
        result = db.execute(text("""
            INSERT INTO incident_cases (created_by, status, severity, title, summary, assigned_to, run_id)
            VALUES (:created_by, 'open', :severity, :title, :summary, :assigned_to, :run_id)
            RETURNING case_id
        """), {
            "created_by":  current_session.username,
            "severity":    body.severity,
            "title":       body.title,
            "summary":     body.summary,
            "assigned_to": body.assigned_to,
            "run_id":      run_id,
        }).fetchone()
        case_id = str(result[0])

        for qid in body.query_ids:
            q = db.query(Query).filter(Query.id == qid).first()
            if q:
                db.execute(text("""
                    INSERT INTO incident_case_queries (case_id, query_id, added_by, run_id)
                    VALUES (:case_id, :qid, :uname, :run_id)
                    ON CONFLICT DO NOTHING
                """), {"case_id": case_id, "qid": qid, "uname": current_session.username, "run_id": run_id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"created": True, "case_id": case_id}


@app.get("/cases")
def list_cases(
    status: "str | None" = QueryParam(default=None),
    severity: "str | None" = QueryParam(default=None),
    q: "str | None" = QueryParam(default=None),
    limit: int = QueryParam(default=25, ge=1, le=200),
    offset: int = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """List incident cases with optional filters (case_management permission)."""
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")

    where_clauses = []
    params: dict = {"limit": limit, "offset": offset}
    if status:
        where_clauses.append("ic.status = :status")
        params["status"] = status
    if severity:
        where_clauses.append("ic.severity = :severity")
        params["severity"] = severity
    if q:
        where_clauses.append("(ic.title ILIKE :q OR ic.summary ILIKE :q)")
        params["q"] = f"%{q}%"

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        rows = db.execute(text(f"""
            SELECT ic.case_id, ic.created_at_utc, ic.created_by, ic.status,
                   ic.severity, ic.title, ic.summary, ic.assigned_to, ic.closed_at_utc,
                   COUNT(icq.query_id) AS query_count
            FROM incident_cases ic
            LEFT JOIN incident_case_queries icq ON icq.case_id = ic.case_id
            {where_sql}
            GROUP BY ic.case_id
            ORDER BY ic.created_at_utc DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()

        count_row = db.execute(text(f"""
            SELECT COUNT(*) FROM incident_cases ic {where_sql}
        """), {k: v for k, v in params.items() if k not in ("limit", "offset")}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    total = count_row[0] if count_row else 0
    items = [_case_to_dict(r, int(r[9])) for r in rows]
    return {"total": total, "offset": offset, "limit": limit, "items": items}


@app.get("/cases/{case_id}/timeline")
def get_case_timeline(
    case_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Return a merged, time-sorted timeline of events for a case (case_management permission)."""
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")

    try:
        query_rows = db.execute(text("""
            SELECT query_id FROM incident_case_queries WHERE case_id = :cid
        """), {"cid": case_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    query_ids = [str(r[0]) for r in query_rows]
    if not query_ids:
        return {"case_id": case_id, "generated_at": datetime.now(timezone.utc).isoformat(), "items": []}

    # Build IN clause safely using numbered params
    in_params = {f"qid{i}": qid for i, qid in enumerate(query_ids)}
    in_clause = ", ".join(f":qid{i}" for i in range(len(query_ids)))

    items: list[dict] = []

    try:
        # query — one row per linked query (from audit_log)
        audit_rows = db.execute(text(f"""
            SELECT query_id, timestamp, role_used, policy_outcome
            FROM audit_log WHERE query_id IN ({in_clause})
        """), in_params).fetchall()
        for r in audit_rows:
            items.append({
                "ts":          r[1].isoformat() if hasattr(r[1], "isoformat") else str(r[1]),
                "type":        "query",
                "title":       f"Query created — outcome: {r[3]}",
                "detail":      {"role_used": r[2], "policy_outcome": r[3], "actor": r[2]},
                "query_id":    r[0],
                "document_id": None,
            })

        # decision + review — from operator_decisions
        dec_rows = db.execute(text(f"""
            SELECT query_id, created_at_utc, created_by_username, created_by_role,
                   decision, supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id IN ({in_clause})
        """), in_params).fetchall()
        for r in dec_rows:
            items.append({
                "ts":          r[1].isoformat() if r[1] else None,
                "type":        "decision",
                "title":       f"Decision recorded: {r[4]} by {r[2]}",
                "detail":      {"decision": r[4], "role": r[3], "actor": r[2]},
                "query_id":    r[0],
                "document_id": None,
            })
            if r[5] and r[7]:
                items.append({
                    "ts":          r[7].isoformat() if r[7] else None,
                    "type":        "review",
                    "title":       f"Supervisor review by {r[6]}",
                    "detail":      {"actor": r[6] or ""},
                    "query_id":    r[0],
                    "document_id": None,
                })

        # evidence — from evidence_export_requests
        exp_rows = db.execute(text(f"""
            SELECT query_id, requested_by, requested_at, status, decided_by, decided_at
            FROM evidence_export_requests WHERE query_id IN ({in_clause})
        """), in_params).fetchall()
        for r in exp_rows:
            items.append({
                "ts":          r[2].isoformat() if r[2] else None,
                "type":        "evidence",
                "title":       f"Evidence export requested by {r[1]}",
                "detail":      {"actor": r[1]},
                "query_id":    r[0],
                "document_id": None,
            })
            if r[3] in ("approved", "rejected") and r[5]:
                items.append({
                    "ts":          r[5].isoformat() if r[5] else None,
                    "type":        "evidence",
                    "title":       f"Evidence export {r[3]} by {r[4]}",
                    "detail":      {"status": r[3], "actor": r[4] or ""},
                    "query_id":    r[0],
                    "document_id": None,
                })
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error building timeline: {exc}")

    # Stable sort: ts asc (nulls last), then type, then query_id
    items.sort(key=lambda e: (e["ts"] is None, e["ts"] or "", e["type"], e.get("query_id") or ""))

    return {
        "case_id":      case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "items":        items,
    }


@app.get("/cases/{case_id}/pack.zip")
def get_case_pack(
    case_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """
    Build and return a deterministic signed case pack ZIP (officer/admin).

    Contents:
      case.json, timeline.json, pubkey.pem,
      incident/<query_id>/incident-<qid[:8]>.zip  (one per query, sorted),
      manifest.json (signed, schema=case-manifest/v1), manifest.sig
    """
    _require_signing_key()
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")

    try:
        case_row = db.execute(text("""
            SELECT case_id, created_at_utc, created_by, status, severity,
                   title, summary, assigned_to, closed_at_utc
            FROM incident_cases WHERE case_id = :cid
        """), {"cid": case_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        query_rows = db.execute(text("""
            SELECT query_id, added_at_utc, added_by
            FROM incident_case_queries
            WHERE case_id = :cid
            ORDER BY added_at_utc ASC
        """), {"cid": case_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    query_ids = [str(r[0]) for r in query_rows]

    # Fixed generation timestamp — derived from case creation time, never from now().
    # Every field that embeds this (timeline, manifest) uses the same value so
    # repeated downloads produce byte-identical ZIPs.
    case_created = case_row[1]
    generated_utc = case_created.isoformat() if case_created else datetime.now(timezone.utc).isoformat()

    # Build timeline for embedding.
    # Override generated_at with the fixed case creation timestamp for determinism.
    timeline_resp = get_case_timeline(case_id, db, current_session)
    timeline_resp["generated_at"] = generated_utc
    timeline_bytes = json.dumps(timeline_resp, sort_keys=True, indent=2, separators=(',', ': ')).encode()

    # Build case.json
    case_dict = _case_to_dict(case_row, len(query_ids))
    case_dict["queries"] = [
        {"query_id": str(r[0]), "added_at_utc": r[1].isoformat() if r[1] else None, "added_by": r[2]}
        for r in query_rows
    ]
    case_bytes = json.dumps(case_dict, sort_keys=True, indent=2, separators=(',', ': ')).encode()

    # Build one incident pack per query (sorted by query_id for determinism)
    incident_zips: list[tuple[str, bytes]] = []
    errors_for_queries: list[str] = []
    for qid in sorted(query_ids):
        try:
            zb = _build_incident_pack_zip(qid, db)
            incident_zips.append((f"incident/{qid}/incident-{qid[:8]}.zip", zb))
        except HTTPException as he:
            errors_for_queries.append(f"{qid[:8]}: {he.detail}")

    if errors_for_queries:
        raise HTTPException(
            status_code=409,
            detail="Cannot build case pack — some queries are missing decisions or approvals: "
                   + "; ".join(errors_for_queries),
        )

    # Case metadata files — covered by the manifest signature.
    # Incident packs are NOT hashed here: each carries its own Ed25519 signature
    # and is verified independently by the offline case pack verifier (KDAT-008).
    _signed_files: list[tuple[str, bytes]] = [
        ("case.json",     case_bytes),
        ("timeline.json", timeline_bytes),
    ]
    if _SIGNING_PUBKEY_PEM is not None:
        _signed_files.append(("pubkey.pem", _SIGNING_PUBKEY_PEM))
    _signed_files.sort(key=lambda x: x[0])

    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _signed_files
    ]

    # All files written to the ZIP (metadata + incident packs, sorted alphabetically)
    _content_files = sorted(_signed_files + list(incident_zips), key=lambda x: x[0])
    manifest = {
        "schema":       "case-manifest/v1",
        "case_id":      case_id,
        "generated_utc": generated_utc,
        "git":          {"repo": "keystone-gov", "commit": _VERSION, "dirty": False},
        "signed":       True,
        "files":        file_entries,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _content_files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)
        _zip_writestr_det(zf, "manifest.sig", sig_bytes)

    filename = f"case-{case_id[:8]}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/cases/{case_id}")
def get_case(
    case_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Return case detail including linked query list (case_management permission)."""
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")

    try:
        row = db.execute(text("""
            SELECT case_id, created_at_utc, created_by, status, severity,
                   title, summary, assigned_to, closed_at_utc
            FROM incident_cases WHERE case_id = :cid
        """), {"cid": case_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")

        query_rows = db.execute(text("""
            SELECT query_id, added_at_utc, added_by
            FROM incident_case_queries
            WHERE case_id = :cid
            ORDER BY added_at_utc ASC
        """), {"cid": case_id}).fetchall()
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    result = _case_to_dict(row, len(query_rows))
    result["queries"] = [
        {"query_id": str(r[0]), "added_at_utc": r[1].isoformat() if r[1] else None, "added_by": r[2]}
        for r in query_rows
    ]
    return result


@app.patch("/cases/{case_id}")
def patch_case(
    case_id: str,
    body: PatchCaseBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Update case fields (case_management permission). Setting status=closed sets closed_at_utc."""
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")
    if body.severity is not None and body.severity not in _CASE_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of: {', '.join(sorted(_CASE_SEVERITIES))}")
    if body.status is not None and body.status not in _CASE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of: {', '.join(sorted(_CASE_STATUSES))}")

    try:
        row = db.execute(
            text("SELECT case_id FROM incident_cases WHERE case_id = :cid"),
            {"cid": case_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")

    updates: dict = {}
    if body.title     is not None: updates["title"]       = body.title
    if body.summary   is not None: updates["summary"]     = body.summary
    if body.severity  is not None: updates["severity"]    = body.severity
    if body.assigned_to is not None: updates["assigned_to"] = body.assigned_to
    if body.status    is not None:
        updates["status"] = body.status
        if body.status == "closed":
            updates["closed_at_utc"] = "now()"

    if not updates:
        raise HTTPException(status_code=422, detail="No updatable fields provided")

    set_parts = []
    params: dict = {"cid": case_id}
    for k, v in updates.items():
        if v == "now()":
            set_parts.append(f"{k} = now()")
        else:
            set_parts.append(f"{k} = :{k}")
            params[k] = v
    set_sql = ", ".join(set_parts)

    try:
        db.execute(text(f"UPDATE incident_cases SET {set_sql} WHERE case_id = :cid"), params)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"updated": True, "case_id": case_id}


@app.post("/cases/{case_id}/queries")
def add_query_to_case(
    case_id: str,
    body: AddQueryBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
    x_keystone_run_id: "str | None" = Header(default=None),
):
    """Add a query to a case (case_management permission)."""
    run_id = _validate_run_id(x_keystone_run_id)
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")
    try:
        case_row = db.execute(
            text("SELECT case_id FROM incident_cases WHERE case_id = :cid"),
            {"cid": case_id},
        ).fetchone()
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")
        q = db.query(Query).filter(Query.id == body.query_id).first()
        if not q:
            raise HTTPException(status_code=404, detail="Query not found")
        db.execute(text("""
            INSERT INTO incident_case_queries (case_id, query_id, added_by, run_id)
            VALUES (:cid, :qid, :uname, :run_id)
            ON CONFLICT DO NOTHING
        """), {"cid": case_id, "qid": body.query_id, "uname": current_session.username, "run_id": run_id})
        db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"added": True, "case_id": case_id, "query_id": body.query_id}


@app.delete("/cases/{case_id}/queries/{query_id}")
def remove_query_from_case(
    case_id: str,
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Remove a query from a case (case_management permission)."""
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")
    try:
        db.execute(text("""
            DELETE FROM incident_case_queries
            WHERE case_id = :cid AND query_id = :qid
        """), {"cid": case_id, "qid": query_id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"removed": True, "case_id": case_id, "query_id": query_id}


# ---------------------------------------------------------------------------
# Admin: tamper endpoint (demo proof — admin token required)
# ---------------------------------------------------------------------------


@app.post("/admin/tamper/{query_id}")
def tamper_audit_entry(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """
    Demo-only endpoint. Corrupts the stored policy_outcome for a given query,
    causing HMAC verification to return valid=false. Admin token required.
    Uses DB owner credentials (TAMPER_DATABASE_URL) to simulate a privileged
    insider threat — proving tamper-evidence holds even against owner-level edits.
    """
    if not _has_perm(current_session, "case_management"):
        raise HTTPException(status_code=403, detail="case_management permission required")

    # Verify the entry exists via runtime connection first.
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    original_outcome = entry.policy_outcome

    # Perform the tamper using DB owner credentials (keystone_app cannot UPDATE).
    tamper_url = os.environ.get("TAMPER_DATABASE_URL", "")
    if not tamper_url:
        raise HTTPException(status_code=501, detail="TAMPER_DATABASE_URL not configured")

    tamper_engine = create_engine(tamper_url)
    try:
        with tamper_engine.connect() as conn:
            conn.execute(
                text("UPDATE audit_log SET policy_outcome='TAMPERED' WHERE query_id=:qid"),
                {"qid": query_id},
            )
            conn.commit()
    finally:
        tamper_engine.dispose()

    return {
        "tampered": True,
        "query_id": query_id,
        "original_outcome": original_outcome,
        "detail": "policy_outcome field corrupted; HMAC verification will now return valid=false",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_audit_dict(entry: AuditEntry) -> dict:
    d = {
        "receiptId": entry.receipt_id,
        "timestamp": entry.timestamp,
        "roleUsed": entry.role_used,
        "modeUsed": entry.mode_used,
        "policyOutcome": entry.policy_outcome,
        "sourcesConsidered": entry.sources_considered_json,
        "citationsReturned": entry.citations_returned_json,
    }
    if entry.user_email:
        d["userId"] = entry.user_id
        d["userEmail"] = entry.user_email
        d["userDisplayName"] = entry.user_display_name
        d["authSource"] = entry.auth_source
        if entry.simulated_role_used:
            d["simulatedRoleUsed"] = entry.simulated_role_used
    return d


def _change_req_to_dict(row: tuple) -> dict:
    (req_id, document_id, requested_by, requested_by_role, requested_at,
     patch_json, reason, status, decided_by, decided_by_role, decided_at,
     decision_reason, applied_at, before_json, after_json) = row
    return {
        "request_id":        str(req_id),
        "document_id":       document_id,
        "requested_by":      requested_by,
        "requested_by_role": requested_by_role,
        "requested_at":      requested_at.isoformat() if requested_at else None,
        "patch":             patch_json if isinstance(patch_json, dict) else json.loads(patch_json or "{}"),
        "reason":            reason,
        "status":            status,
        "decided_by":        decided_by,
        "decided_by_role":   decided_by_role,
        "decided_at":        decided_at.isoformat() if decided_at else None,
        "decision_reason":   decision_reason,
        "applied_at":        applied_at.isoformat() if applied_at else None,
        "before_json":       before_json if isinstance(before_json, dict) else json.loads(before_json or "{}"),
        "after_json":        after_json if isinstance(after_json, dict) else (json.loads(after_json) if after_json else None),
    }


# ---------------------------------------------------------------------------
# Document registry (requires auth)
# ---------------------------------------------------------------------------

_ALLOWED_STATUS_OVERRIDES = {"", "active", "superseded", "draft", "restricted"}
_ALLOWED_DOMAINS        = {
    "fire_ops", "medical_emr", "lrfd_protocol",
    "ohs_regulation", "industry_reference", "training_material", "guide",
}
_ALLOWED_CONTENT_KINDS  = {
    "procedure", "requirements", "reference",
    "regulation", "guide", "training",
}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class DocMetadataPatch(BaseModel):
    status_override: str | None = None
    owner: str | None = None
    effective_date: str | None = None
    review_date: str | None = None
    title_override: str | None = None
    domain: str | None = None
    content_kind: str | None = None


def _corpus_doc_to_dict(row: tuple, today: str) -> dict:
    """Convert a corpus_documents SELECT row to API dict.

    Expected columns (positional):
      0  id
      1  rel_path
      2  sha256
      3  size_bytes
      4  title
      5  owner
      6  effective_date
      7  review_date
      8  status_override
      9  created_utc
      10 domain
      11 content_kind
    """
    (_id, rel_path, sha256, _size, title,
     owner, eff_date, rev_date, status_ov, created_utc,
     domain, content_kind) = row
    status = status_ov if status_ov else "active"
    review_overdue = bool(rev_date and rev_date < today)
    return {
        "documentId":       rel_path,
        "title":            title or rel_path,
        "rel_path":         rel_path,
        "status":           status,
        "owner":            owner or "",
        "effectiveDate":    eff_date or "",
        "reviewDate":       rev_date or "",
        "reviewOverdue":    review_overdue,
        "sha256":           sha256 or "",
        "last_ingested_utc": created_utc.isoformat() if created_utc else "",
        "domain":           domain or "fire_ops",
        "content_kind":     content_kind or "procedure",
    }


_DOC_SELECT = """
    SELECT id, rel_path, sha256, size_bytes, title, owner,
           effective_date, review_date, status_override, created_utc,
           domain, content_kind
    FROM corpus_documents
"""


@app.get("/documents")
def list_documents(
    q:            str | None = QueryParam(default=None),
    status:       str | None = QueryParam(default=None),
    owner:        str | None = QueryParam(default=None),
    domain:       str | None = QueryParam(default=None),
    content_kind: str | None = QueryParam(default=None),
    overdue_only: int         = QueryParam(default=0),
    limit:        int         = QueryParam(default=50, ge=1, le=200),
    offset:       int         = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    today = datetime.now(timezone.utc).date().isoformat()
    filters: list[str] = []
    params: dict = {}

    if q:
        filters.append("(rel_path ILIKE :q OR title ILIKE :q)")
        params["q"] = f"%{q}%"
    if status:
        if status == "active":
            # Documents are "active" when status_override is NULL, empty string,
            # or the literal value 'active' (ingest may write either convention).
            filters.append("(status_override IS NULL OR status_override IN ('', 'active'))")
        else:
            filters.append("status_override = :status")
            params["status"] = status
    if owner:
        filters.append("owner ILIKE :owner")
        params["owner"] = f"%{owner}%"
    if domain:
        filters.append("domain = :domain")
        params["domain"] = domain
    if content_kind:
        filters.append("content_kind = :content_kind")
        params["content_kind"] = content_kind
    if overdue_only:
        filters.append("review_date != '' AND review_date < :today")
        params["today"] = today

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    try:
        rows = db.execute(text(f"""
            {_DOC_SELECT}
            {where}
            ORDER BY rel_path ASC
            LIMIT :limit OFFSET :offset
        """), {**params, "limit": limit, "offset": offset}).fetchall()
        total_row = db.execute(
            text(f"SELECT COUNT(*) FROM corpus_documents {where}"),
            params,
        ).fetchone()
        total = total_row[0] if total_row else 0
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error listing documents: {exc}")

    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [_corpus_doc_to_dict(r, today) for r in rows],
    }


@app.get("/documents/review-queue")
def get_review_queue(
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        all_rows = db.execute(
            text(f"{_DOC_SELECT} ORDER BY rel_path ASC")
        ).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error fetching review queue: {exc}")

    overdue_review: list[dict] = []
    missing_owner: list[dict] = []
    missing_review_date: list[dict] = []
    draft_or_superseded: list[dict] = []

    for row in all_rows:
        d = _corpus_doc_to_dict(row, today)
        if d["reviewOverdue"]:
            overdue_review.append(d)
        if not d["owner"]:
            missing_owner.append(d)
        if not d["reviewDate"]:
            missing_review_date.append(d)
        if d["status"] in ("draft", "superseded"):
            draft_or_superseded.append(d)

    return {
        "overdue_review":      overdue_review,
        "missing_owner":       missing_owner,
        "missing_review_date": missing_review_date,
        "draft_or_superseded": draft_or_superseded,
        "counts": {
            "overdue_review":      len(overdue_review),
            "missing_owner":       len(missing_owner),
            "missing_review_date": len(missing_review_date),
            "draft_or_superseded": len(draft_or_superseded),
        },
    }


@app.get("/documents/change-requests")
def list_change_requests(
    status:   str | None  = QueryParam(default=None),
    document_id: str | None = QueryParam(default=None),
    limit:    int          = QueryParam(default=50, ge=1, le=200),
    offset:   int          = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "promote_document"):
        raise HTTPException(status_code=403, detail="promote_document permission required")
    filters: list[str] = []
    params: dict = {"limit": limit, "offset": offset}
    if status:
        filters.append("status = :status")
        params["status"] = status
    if document_id:
        filters.append("document_id = :document_id")
        params["document_id"] = document_id
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    try:
        rows = db.execute(text(f"""
            SELECT id, document_id, requested_by, requested_by_role, requested_at,
                   patch, reason, status, decided_by, decided_by_role, decided_at,
                   decision_reason, applied_at, before_json, after_json
            FROM corpus_doc_change_requests
            {where}
            ORDER BY requested_at DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()
        total = db.execute(
            text(f"SELECT COUNT(*) FROM corpus_doc_change_requests {where}"),
            {k: v for k, v in params.items() if k not in ("limit", "offset")},
        ).fetchone()[0]
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"total": total, "offset": offset, "limit": limit, "items": [_change_req_to_dict(r) for r in rows]}


@app.get("/documents/change-requests/{req_id}")
def get_change_request(
    req_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "promote_document"):
        raise HTTPException(status_code=403, detail="promote_document permission required")
    try:
        row = db.execute(text("""
            SELECT id, document_id, requested_by, requested_by_role, requested_at,
                   patch, reason, status, decided_by, decided_by_role, decided_at,
                   decision_reason, applied_at, before_json, after_json
            FROM corpus_doc_change_requests WHERE id = :id
        """), {"id": req_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")
    return _change_req_to_dict(row)


@app.get("/documents/{document_id}")
def get_document_registry(
    document_id: str,
    db: DBSession = Depends(get_db),
    _session: AppUser = Depends(get_current_user),
):
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        row = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Document not found")

    d = _corpus_doc_to_dict(row, today)

    try:
        stats = db.execute(text("""
            SELECT
                COUNT(*)          AS chunk_count,
                COUNT(cc.page)    AS pages_indexed,
                COUNT(*) - COUNT(cc.page) AS pages_null,
                MAX(cc.page)      AS max_page
            FROM corpus_chunks cc
            JOIN corpus_documents cd ON cd.id = cc.doc_id
            WHERE cd.rel_path = :rel
        """), {"rel": document_id}).fetchone()
        d["chunk_count"]         = stats[0] if stats else 0
        d["pages_indexed_count"] = stats[1] if stats else 0
        d["pages_null_count"]    = stats[2] if stats else 0
        d["max_page"]            = stats[3] if stats else None
    except Exception:
        db.rollback()
        d["chunk_count"]         = None
        d["pages_indexed_count"] = None
        d["pages_null_count"]    = None
        d["max_page"]            = None

    return d


@app.patch("/documents/{document_id}/metadata")
def patch_document_metadata(
    document_id: str,
    patch: DocMetadataPatch,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "edit_corpus_metadata"):
        raise HTTPException(status_code=403, detail="edit_corpus_metadata permission required")
    # If approval workflow is enabled, users without promote_document must use change requests
    if _REQUIRE_DOC_CHANGE_APPROVAL and not _has_perm(current_session, "promote_document"):
        raise HTTPException(
            status_code=403,
            detail="APPROVAL_REQUIRED: Use POST /documents/{id}/change-requests instead",
        )

    if patch.status_override is not None:
        if patch.status_override not in _ALLOWED_STATUS_OVERRIDES:
            raise HTTPException(
                status_code=422,
                detail=f"status_override must be one of {sorted(_ALLOWED_STATUS_OVERRIDES)}",
            )
    if patch.domain is not None:
        if patch.domain not in _ALLOWED_DOMAINS:
            raise HTTPException(
                status_code=422,
                detail=f"domain must be one of {sorted(_ALLOWED_DOMAINS)}",
            )
    if patch.content_kind is not None:
        if patch.content_kind not in _ALLOWED_CONTENT_KINDS:
            raise HTTPException(
                status_code=422,
                detail=f"content_kind must be one of {sorted(_ALLOWED_CONTENT_KINDS)}",
            )
    for field_name, field_val in [
        ("effective_date", patch.effective_date),
        ("review_date",    patch.review_date),
    ]:
        if field_val is not None and field_val != "" and not _DATE_RE.match(field_val):
            raise HTTPException(status_code=422, detail=f"{field_name} must be yyyy-mm-dd or empty")

    today = datetime.now(timezone.utc).date().isoformat()

    try:
        row = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Document not found")

    before = _corpus_doc_to_dict(row, today)

    updates: dict = {}
    if patch.status_override is not None:
        updates["status_override"] = patch.status_override
    if patch.owner is not None:
        updates["owner"] = patch.owner
    if patch.effective_date is not None:
        updates["effective_date"] = patch.effective_date
    if patch.review_date is not None:
        updates["review_date"] = patch.review_date
    if patch.title_override is not None:
        updates["title"] = patch.title_override
    if patch.domain is not None:
        updates["domain"] = patch.domain
    if patch.content_kind is not None:
        updates["content_kind"] = patch.content_kind

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)

    try:
        db.execute(
            text(f"UPDATE corpus_documents SET {set_clause} WHERE rel_path = :rel"),
            {**updates, "rel": document_id},
        )
        row_after = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
        after = _corpus_doc_to_dict(row_after, today) if row_after else before

        db.execute(text("""
            INSERT INTO corpus_doc_events
                (ts_utc, actor_username, actor_role, document_id, action, before_json, after_json)
            VALUES
                (now(), :uname, :role, :doc_id, 'metadata_patch',
                 CAST(:before_j AS jsonb), CAST(:after_j AS jsonb))
        """), {
            "uname":    current_session.username,
            "role":     current_session.role,
            "doc_id":   document_id,
            "before_j": json.dumps(before, sort_keys=True),
            "after_j":  json.dumps(after,  sort_keys=True),
        })
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error during update: {exc}")

    return {"updated": True, "document": after}


@app.post("/documents/{document_id}/change-requests")
def create_change_request(
    document_id: str,
    body: ChangeRequestBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "edit_corpus_metadata"):
        raise HTTPException(status_code=403, detail="edit_corpus_metadata permission required")

    # Validate patch fields
    allowed_keys = {"owner", "status_override", "effective_date", "review_date", "title_override",
                    "domain", "content_kind"}
    bad = set(body.patch.keys()) - allowed_keys
    if bad:
        raise HTTPException(status_code=422, detail=f"Unknown patch fields: {bad}")
    if not body.patch:
        raise HTTPException(status_code=422, detail="patch must have at least one field")

    today = datetime.now(timezone.utc).date().isoformat()
    try:
        row = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Document not found")

    before = _corpus_doc_to_dict(row, today)

    try:
        result = db.execute(text("""
            INSERT INTO corpus_doc_change_requests
                (document_id, requested_by, requested_by_role, patch, reason, before_json)
            VALUES (:doc_id, :uname, :role, CAST(:patch AS jsonb), :reason, CAST(:before_j AS jsonb))
            RETURNING id
        """), {
            "doc_id":   document_id,
            "uname":    current_session.username,
            "role":     current_session.role,
            "patch":    json.dumps(body.patch, sort_keys=True),
            "reason":   body.reason,
            "before_j": json.dumps(before, sort_keys=True),
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {"created": True, "request_id": str(result[0]), "status": "pending"}


@app.post("/documents/change-requests/{req_id}/approve")
def approve_change_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "promote_document"):
        raise HTTPException(status_code=403, detail="promote_document permission required")
    try:
        row = db.execute(
            text("SELECT id, status FROM corpus_doc_change_requests WHERE id = :id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    try:
        db.execute(text("""
            UPDATE corpus_doc_change_requests
            SET status='approved', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"approved": True, "request_id": req_id}


@app.post("/documents/change-requests/{req_id}/reject")
def reject_change_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "reject_document"):
        raise HTTPException(status_code=403, detail="reject_document permission required")
    try:
        row = db.execute(
            text("SELECT id, status FROM corpus_doc_change_requests WHERE id = :id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    try:
        db.execute(text("""
            UPDATE corpus_doc_change_requests
            SET status='rejected', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"rejected": True, "request_id": req_id}


@app.post("/documents/change-requests/{req_id}/apply")
def apply_change_request(
    req_id: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_session, "promote_document"):
        raise HTTPException(status_code=403, detail="promote_document permission required")

    try:
        row = db.execute(text("""
            SELECT id, document_id, patch, status, before_json
            FROM corpus_doc_change_requests WHERE id = :id
        """), {"id": req_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")

    _req_id, document_id, patch_json, status, before_json = row
    if status != "approved":
        raise HTTPException(status_code=409, detail=f"Request must be approved before apply (status={status})")

    patch = patch_json if isinstance(patch_json, dict) else json.loads(patch_json)

    # Validate patch fields
    if patch.get("status_override") is not None:
        if patch["status_override"] not in _ALLOWED_STATUS_OVERRIDES:
            raise HTTPException(status_code=422, detail="Invalid status_override in patch")
    for field_name in ("effective_date", "review_date"):
        val = patch.get(field_name)
        if val is not None and val != "" and not _DATE_RE.match(val):
            raise HTTPException(status_code=422, detail=f"{field_name} must be yyyy-mm-dd or empty")

    today = datetime.now(timezone.utc).date().isoformat()
    doc_row = db.execute(
        text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
        {"rel": document_id},
    ).fetchone()
    if not doc_row:
        raise HTTPException(status_code=404, detail="Document not found")

    # Map patch keys to column names
    _patch_col_map = {
        "owner": "owner",
        "status_override": "status_override",
        "effective_date": "effective_date",
        "review_date": "review_date",
        "title_override": "title",
    }
    updates: dict = {}
    for k, v in patch.items():
        col = _patch_col_map.get(k)
        if col:
            updates[col] = v

    if not updates:
        raise HTTPException(status_code=422, detail="Patch has no applicable fields")

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)

    try:
        db.execute(
            text(f"UPDATE corpus_documents SET {set_clause} WHERE rel_path = :rel"),
            {**updates, "rel": document_id},
        )
        row_after = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
        after = _corpus_doc_to_dict(row_after, today) if row_after else {}

        db.execute(text("""
            INSERT INTO corpus_doc_events
                (ts_utc, actor_username, actor_role, document_id, action, before_json, after_json)
            VALUES
                (now(), :uname, :role, :doc_id, 'change_request_applied',
                 CAST(:before_j AS jsonb), CAST(:after_j AS jsonb))
        """), {
            "uname":    current_session.username,
            "role":     current_session.role,
            "doc_id":   document_id,
            "before_j": json.dumps(before_json if isinstance(before_json, dict) else json.loads(before_json), sort_keys=True),
            "after_j":  json.dumps(after, sort_keys=True),
        })

        db.execute(text("""
            UPDATE corpus_doc_change_requests
            SET status='applied', applied_at=now(),
                after_json=CAST(:after_j AS jsonb)
            WHERE id=:id
        """), {"id": req_id, "after_j": json.dumps(after, sort_keys=True)})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error during apply: {exc}")

    return {"applied": True, "request_id": req_id, "document": after}


# ---------------------------------------------------------------------------
# Upload workflow  (Steps 3-6)
# ---------------------------------------------------------------------------
#
# POST   /uploads                    custodian or admin; synchronous extract
# GET    /uploads                    custodian sees own + all pending; admin sees all
# GET    /uploads/{id}               custodian own + admin any
# PATCH  /uploads/{id}               metadata correction before activation
# POST   /uploads/{id}/activate      admin only; temp-file + rename atomicity
# POST   /uploads/{id}/reject        admin or custodian own; non-empty reason required
# DELETE /uploads/{id}               pending/failed/rejected only; admin or custodian own
# POST   /uploads/{id}/retry         failed only; re-runs extraction
#
# Staging directory: $CORPUS_ROOT/staging/
# Max upload size  : 20 MB (enforced in handler before writing to disk)
# ---------------------------------------------------------------------------

_UPLOAD_MAX_BYTES = 20 * 1024 * 1024   # 20 MB
_STAGING_DIR      = _CORPUS_ROOT / "staging"
_ACTIVE_DIR_UPLOAD = _CORPUS_ROOT / "active"

_UPLOAD_MIN_ROLE_VALUES = {"member", "custodian", "officer", "authority"}


class _UploadMetaPatch(BaseModel):
    title:          str | None = None
    owner:          str | None = None
    effective_date: str | None = None
    review_date:    str | None = None
    domain:         str | None = None
    content_kind:   str | None = None
    min_role:       str | None = None


class _ActivateBody(BaseModel):
    supersede_document_id: str | None = None   # rel_path of existing doc to mark superseded


class _RejectBody(BaseModel):
    reason: str


def _upload_to_dict(row: tuple) -> dict:
    """Convert a staged_uploads SELECT row to API dict.

    Columns (positional):
      0  id, 1 uploaded_at, 2 uploader_username, 3 uploader_role,
      4  original_filename, 5 stored_filename, 6 sha256, 7 size_bytes, 8 mime,
      9  title, 10 owner, 11 effective_date, 12 review_date,
      13 domain, 14 content_kind, 15 min_role,
      16 status, 17 failure_reason, 18 failure_detail,
      19 rejection_reason, 20 rejected_by, 21 rejected_at,
      22 activated_at, 23 activated_by, 24 activated_rel_path, 25 activation_error,
      26 processing_started_at, 27 processing_completed_at
    """
    (uid, uploaded_at, uploader_username, uploader_role,
     original_filename, stored_filename, sha256, size_bytes, mime,
     title, owner, effective_date, review_date,
     domain, content_kind, min_role,
     status, failure_reason, failure_detail,
     rejection_reason, rejected_by, rejected_at,
     activated_at, activated_by, activated_rel_path, activation_error,
     processing_started_at, processing_completed_at) = row
    return {
        "id":                       str(uid),
        "uploaded_at":              uploaded_at.isoformat() if uploaded_at else None,
        "uploader_username":        uploader_username,
        "uploader_role":            uploader_role,
        "original_filename":        original_filename,
        "stored_filename":          stored_filename,
        "sha256":                   sha256,
        "size_bytes":               size_bytes,
        "mime":                     mime,
        "title":                    title,
        "owner":                    owner,
        "effective_date":           effective_date,
        "review_date":              review_date,
        "domain":                   domain,
        "content_kind":             content_kind,
        "min_role":                 min_role,
        "status":                   status,
        "failure_reason":           failure_reason,
        "failure_detail":           failure_detail,
        "rejection_reason":         rejection_reason,
        "rejected_by":              rejected_by,
        "rejected_at":              rejected_at.isoformat() if rejected_at else None,
        "activated_at":             activated_at.isoformat() if activated_at else None,
        "activated_by":             activated_by,
        "activated_rel_path":       activated_rel_path,
        "activation_error":         activation_error,
        "processing_started_at":    processing_started_at.isoformat() if processing_started_at else None,
        "processing_completed_at":  processing_completed_at.isoformat() if processing_completed_at else None,
    }


_UPLOAD_SELECT = """
    SELECT id, uploaded_at, uploader_username, uploader_role,
           original_filename, stored_filename, sha256, size_bytes, mime,
           title, owner, effective_date, review_date,
           domain, content_kind, min_role,
           status, failure_reason, failure_detail,
           rejection_reason, rejected_by, rejected_at,
           activated_at, activated_by, activated_rel_path, activation_error,
           processing_started_at, processing_completed_at
    FROM staged_uploads
"""


def _validate_upload_meta(
    title: str, domain: str, content_kind: str,
    effective_date: str, review_date: str, min_role: str,
) -> None:
    """Raise HTTPException(422) if any required metadata field is invalid."""
    if not title.strip():
        raise HTTPException(status_code=422, detail="title is required")
    if domain not in _ALLOWED_DOMAINS:
        raise HTTPException(
            status_code=422,
            detail=f"domain must be one of {sorted(_ALLOWED_DOMAINS)}",
        )
    if content_kind not in _ALLOWED_CONTENT_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"content_kind must be one of {sorted(_ALLOWED_CONTENT_KINDS)}",
        )
    for field_name, field_val in [("effective_date", effective_date), ("review_date", review_date)]:
        if field_val and not _DATE_RE.match(field_val):
            raise HTTPException(status_code=422, detail=f"{field_name} must be yyyy-mm-dd or empty")
    if min_role not in _UPLOAD_MIN_ROLE_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"min_role must be one of {sorted(_UPLOAD_MIN_ROLE_VALUES)}",
        )


@app.post("/uploads", status_code=201)
def upload_document(
    file:           UploadFile = File(...),
    title:          str        = File(default=""),
    owner:          str        = File(default=""),
    effective_date: str        = File(default=""),
    review_date:    str        = File(default=""),
    domain:         str        = File(default=""),
    content_kind:   str        = File(default="procedure"),
    min_role:       str        = File(default="member"),
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "upload_to_staging"):
        raise HTTPException(status_code=403, detail="upload_to_staging permission required")

    # Read file content into memory (enforces size cap without streaming to disk)
    raw = file.file.read(_UPLOAD_MAX_BYTES + 1)
    if len(raw) > _UPLOAD_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {_UPLOAD_MAX_BYTES // (1024*1024)} MB limit",
        )

    original_filename = file.filename or "upload"
    # Sanitise: keep only safe characters, collapse sequences
    safe_name = re.sub(r"[^\w.\-]", "_", original_filename)
    safe_name = re.sub(r"_+", "_", safe_name).strip("_")
    if not safe_name:
        safe_name = "upload"

    # Infer MIME from filename extension (more reliable than Content-Type header)
    upload_id    = str(uuid.uuid4())
    staging_path = _STAGING_DIR / f"{safe_name}.staging_{upload_id[:8]}"
    mime         = _ingest_mime_for(Path(safe_name))

    # Use filename-derived title when caller omits it
    if not title.strip():
        title = Path(safe_name).stem.replace("_", " ").replace("-", " ")

    # Infer domain from filename/title when caller omits it
    if not domain:
        domain = _ingest_infer_domain(safe_name, title)

    _validate_upload_meta(title, domain, content_kind, effective_date, review_date, min_role)

    if not _ingest_is_supported_mime(mime):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file type: {mime}. Accepted: PDF, DOCX, TXT, MD",
        )

    # Ensure staging/ exists
    _STAGING_DIR.mkdir(parents=True, exist_ok=True)

    # Write to staging (temp name to avoid partial-file races)
    staging_path.write_bytes(raw)
    sha256 = _ingest_sha256_file(staging_path)
    size_bytes = len(raw)

    # Synchronous extraction
    import time as _time
    t0 = _time.monotonic()
    extraction_error: str = ""
    failure_reason:   str = ""
    chunks_data: list[tuple[int, int | None, str]] = []
    try:
        if mime == "application/pdf":
            chunks_data = _ingest_build_chunks_pdf(staging_path)
        else:
            chunks_data = _ingest_build_chunks_other(staging_path, mime)
    except Exception as exc:
        extraction_error = str(exc)
        failure_reason   = "EXTRACTION_ERROR"

    if not extraction_error and not chunks_data:
        failure_reason = "NO_TEXT_EXTRACTED"

    status = "failed" if failure_reason else "pending"
    t1 = _time.monotonic()

    # Write DB row
    try:
        row = db.execute(text("""
            INSERT INTO staged_uploads (
                id, uploader_username, uploader_role,
                original_filename, stored_filename,
                sha256, size_bytes, mime,
                title, owner, effective_date, review_date,
                domain, content_kind, min_role,
                status, failure_reason, failure_detail,
                processing_started_at, processing_completed_at
            ) VALUES (
                :uid, :uname, :role,
                :orig, :stored,
                :sha256, :size, :mime,
                :title, :owner, :eff, :rev,
                :domain, :ck, :min_role,
                :status, :freason, :fdetail,
                now() - :elapsed_start * interval '1 second',
                now()
            ) RETURNING id
        """), {
            "uid":           upload_id,
            "uname":         current_user.username,
            "role":          current_user.role,
            "orig":          original_filename,
            "stored":        safe_name,
            "sha256":        sha256,
            "size":          size_bytes,
            "mime":          mime,
            "title":         title,
            "owner":         owner,
            "eff":           effective_date,
            "rev":           review_date,
            "domain":        domain,
            "ck":            content_kind,
            "min_role":      min_role,
            "status":        status,
            "freason":       failure_reason,
            "fdetail":       extraction_error,
            "elapsed_start": round(t1 - t0, 3),
        })

        if status == "pending" and chunks_data:
            for ci, pg, ct in chunks_data:
                db.execute(text("""
                    INSERT INTO staged_upload_chunks (upload_id, chunk_index, page, text)
                    VALUES (:uid, :ci, :pg, :ct)
                """), {"uid": upload_id, "ci": ci, "pg": pg, "ct": ct})
        db.commit()
    except Exception as exc:
        db.rollback()
        try:
            staging_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    # On failure, clean up staging file
    if status == "failed":
        try:
            staging_path.unlink(missing_ok=True)
        except Exception:
            pass

    preview_chunks = [
        {"chunk_index": c[0], "page": c[1], "text": c[2][:300]}
        for c in chunks_data[:5]
    ]
    return {
        "id":               upload_id,
        "status":           status,
        "mime":             mime,
        "size_bytes":       size_bytes,
        "sha256":           sha256,
        "title":            title,
        "domain":           domain,
        "content_kind":     content_kind,
        "chunk_count":      len(chunks_data),
        "failure_reason":   failure_reason,
        "failure_detail":   extraction_error,
        "preview_chunks":   preview_chunks,
    }


@app.get("/uploads")
def list_uploads(
    status:  str | None = QueryParam(default=None),
    limit:   int         = QueryParam(default=50, ge=1, le=200),
    offset:  int         = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "view_staging_queue"):
        raise HTTPException(status_code=403, detail="view_staging_queue permission required")

    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    # custodians see their own uploads; authority (view_all_user_activity) sees all
    if not _has_perm(current_user, "view_all_user_activity"):
        conditions.append("uploader_username = :uname")
        params["uname"] = current_user.username

    if status:
        conditions.append("status = :status")
        params["status"] = status

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"{_UPLOAD_SELECT} {where} ORDER BY uploaded_at DESC LIMIT :limit OFFSET :offset"

    try:
        rows = db.execute(text(sql), params).fetchall()
        total_row = db.execute(
            text(f"SELECT COUNT(*) FROM staged_uploads {where}"),
            {k: v for k, v in params.items() if k not in ("limit", "offset")},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {
        "total": total_row[0] if total_row else 0,
        "items": [_upload_to_dict(r) for r in rows],
    }


@app.get("/uploads/{upload_id}")
def get_upload(
    upload_id: str,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "view_staging_queue"):
        raise HTTPException(status_code=403, detail="view_staging_queue permission required")

    try:
        row = db.execute(
            text(f"{_UPLOAD_SELECT} WHERE id = :uid"),
            {"uid": upload_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    d = _upload_to_dict(row)
    # users without view_all_user_activity may only view their own uploads
    if not _has_perm(current_user, "view_all_user_activity") and d["uploader_username"] != current_user.username:
        raise HTTPException(status_code=403, detail="Not your upload")

    # Attach preview chunks
    try:
        chunk_rows = db.execute(
            text("SELECT chunk_index, page, text FROM staged_upload_chunks "
                 "WHERE upload_id = :uid ORDER BY chunk_index LIMIT 10"),
            {"uid": upload_id},
        ).fetchall()
    except Exception:
        db.rollback()
        chunk_rows = []

    d["preview_chunks"] = [
        {"chunk_index": r[0], "page": r[1], "text": r[2][:300]}
        for r in chunk_rows
    ]
    return d


@app.patch("/uploads/{upload_id}")
def patch_upload(
    upload_id: str,
    patch: _UploadMetaPatch,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "upload_to_staging"):
        raise HTTPException(status_code=403, detail="upload_to_staging permission required")

    try:
        row = db.execute(
            text("SELECT id, uploader_username, status, title, domain, content_kind, "
                 "effective_date, review_date, min_role FROM staged_uploads WHERE id = :uid"),
            {"uid": upload_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    (_, uploader, status, cur_title, cur_domain, cur_ck,
     cur_eff, cur_rev, cur_min_role) = row

    if current_user.role == "custodian" and uploader != current_user.username:
        raise HTTPException(status_code=403, detail="Not your upload")
    if status not in ("pending", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot patch upload in status '{status}'",
        )

    updates: dict = {}
    if patch.title          is not None: updates["title"]          = patch.title
    if patch.owner          is not None: updates["owner"]          = patch.owner
    if patch.effective_date is not None: updates["effective_date"] = patch.effective_date
    if patch.review_date    is not None: updates["review_date"]    = patch.review_date
    if patch.domain         is not None: updates["domain"]         = patch.domain
    if patch.content_kind   is not None: updates["content_kind"]   = patch.content_kind
    if patch.min_role       is not None: updates["min_role"]       = patch.min_role

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    # Validate the merged state
    _validate_upload_meta(
        title          = updates.get("title", cur_title),
        domain         = updates.get("domain", cur_domain),
        content_kind   = updates.get("content_kind", cur_ck),
        effective_date = updates.get("effective_date", cur_eff),
        review_date    = updates.get("review_date", cur_rev),
        min_role       = updates.get("min_role", cur_min_role),
    )

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    try:
        db.execute(
            text(f"UPDATE staged_uploads SET {set_clause} WHERE id = :uid"),
            {**updates, "uid": upload_id},
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {"updated": True, "upload_id": upload_id, "fields": list(updates.keys())}


@app.post("/uploads/{upload_id}/activate", status_code=201)
def activate_upload(
    upload_id: str,
    body: _ActivateBody,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "promote_document"):
        raise HTTPException(status_code=403, detail="promote_document permission required")

    try:
        row = db.execute(
            text(f"{_UPLOAD_SELECT} WHERE id = :uid"),
            {"uid": upload_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    d = _upload_to_dict(row)
    if d["status"] != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot activate upload in status '{d['status']}'",
        )

    stored_filename = d["stored_filename"]
    staging_path    = _STAGING_DIR / f"{stored_filename}.staging_{upload_id[:8]}"
    active_path     = _ACTIVE_DIR_UPLOAD / stored_filename

    # Path traversal guard (same pattern as existing /document/ endpoint)
    active_root = _ACTIVE_DIR_UPLOAD.resolve()
    target      = active_path.resolve()
    if not str(target).startswith(str(active_root) + os.sep) and target != active_root:
        raise HTTPException(status_code=400, detail="Invalid document path")

    if not staging_path.exists():
        raise HTTPException(
            status_code=409,
            detail="Staging file missing — upload may have been cleaned up",
        )

    today = datetime.now(timezone.utc).date().isoformat()

    # ── DB transaction (must commit before rename) ────────────────────────────
    rel_path = stored_filename
    try:
        # Upsert corpus_documents
        existing = db.execute(
            text("SELECT id FROM corpus_documents WHERE rel_path = :rel"),
            {"rel": rel_path},
        ).fetchone()
        if existing:
            doc_id = existing[0]
            db.execute(text("""
                UPDATE corpus_documents
                   SET sha256=:sha256, size_bytes=:size, mime=:mime, title=:title,
                       owner=:owner, effective_date=:eff, review_date=:rev,
                       status_override='active', domain=:domain,
                       content_kind=:ck, min_role=:min_role
                 WHERE id=:doc_id
            """), {
                "sha256": d["sha256"], "size": d["size_bytes"], "mime": d["mime"],
                "title": d["title"], "owner": d["owner"],
                "eff": d["effective_date"], "rev": d["review_date"],
                "domain": d["domain"], "ck": d["content_kind"],
                "min_role": d["min_role"], "doc_id": doc_id,
            })
            db.execute(text("DELETE FROM corpus_chunks WHERE doc_id = :doc_id"), {"doc_id": doc_id})
        else:
            result = db.execute(text("""
                INSERT INTO corpus_documents
                    (rel_path, sha256, size_bytes, mtime_utc, mime, title,
                     owner, effective_date, review_date, status_override,
                     domain, content_kind, min_role)
                VALUES (:rel, :sha256, :size, now(), :mime, :title,
                        :owner, :eff, :rev, 'active',
                        :domain, :ck, :min_role)
                RETURNING id
            """), {
                "rel": rel_path, "sha256": d["sha256"], "size": d["size_bytes"],
                "mime": d["mime"], "title": d["title"], "owner": d["owner"],
                "eff": d["effective_date"], "rev": d["review_date"],
                "domain": d["domain"], "ck": d["content_kind"],
                "min_role": d["min_role"],
            })
            doc_id = result.fetchone()[0]

        # Copy staging chunks to corpus_chunks
        chunk_rows = db.execute(
            text("SELECT chunk_index, page, text FROM staged_upload_chunks "
                 "WHERE upload_id = :uid ORDER BY chunk_index"),
            {"uid": upload_id},
        ).fetchall()
        for chunk_index, page, chunk_text_val in chunk_rows:
            db.execute(text("""
                INSERT INTO corpus_chunks (doc_id, chunk_index, page, text)
                VALUES (:doc_id, :ci, :page, :text)
                ON CONFLICT (doc_id, chunk_index) DO UPDATE
                    SET text = EXCLUDED.text, page = EXCLUDED.page
            """), {"doc_id": doc_id, "ci": chunk_index, "page": page, "text": chunk_text_val})

        # Mark superseded document if requested
        if body.supersede_document_id:
            db.execute(text("""
                UPDATE corpus_documents SET status_override='superseded'
                WHERE rel_path = :rel AND rel_path != :new_rel
            """), {"rel": body.supersede_document_id, "new_rel": rel_path})

        # Audit event
        db.execute(text("""
            INSERT INTO corpus_doc_events
                (ts_utc, actor_username, actor_role, document_id, action,
                 before_json, after_json, upload_id)
            VALUES
                (now(), :uname, :role, :doc_id, 'activated',
                 '{}', CAST(:after_j AS jsonb), CAST(:upload_id AS uuid))
        """), {
            "uname":     current_user.username,
            "role":      current_user.role,
            "doc_id":    rel_path,
            "after_j":   json.dumps({k: d[k] for k in
                             ("title","domain","content_kind","sha256","min_role")},
                             sort_keys=True),
            "upload_id": upload_id,
        })

        # Mark staged_uploads as activated
        db.execute(text("""
            UPDATE staged_uploads
               SET status='activated', activated_at=now(),
                   activated_by=:uname, activated_rel_path=:rel
             WHERE id=:uid
        """), {"uname": current_user.username, "rel": rel_path, "uid": upload_id})

        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error during activation: {exc}")

    # ── Rename staging file to active/ (after DB commit) ─────────────────────
    try:
        _ACTIVE_DIR_UPLOAD.mkdir(parents=True, exist_ok=True)
        staging_path.rename(active_path)
    except Exception as exc:
        # DB is committed; file rename failed — mark for operator attention.
        try:
            db.execute(text("""
                UPDATE staged_uploads
                   SET status='activation_file_error', activation_error=:err
                 WHERE id=:uid
            """), {"err": str(exc), "uid": upload_id})
            db.commit()
        except Exception:
            db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"DB committed but file rename failed: {exc}. "
                   "Upload marked activation_file_error — operator action required.",
        )

    # Write sidecar (non-fatal)
    try:
        sidecar_path = active_path.with_suffix(active_path.suffix + ".metadata.json")
        sidecar_data = {
            "title":        d["title"],
            "owner":        d["owner"],
            "effectiveDate": d["effective_date"],
            "reviewDate":   d["review_date"],
            "domain":       d["domain"],
            "content_kind": d["content_kind"],
        }
        sidecar_path.write_text(json.dumps(sidecar_data, indent=2))
    except Exception as sidecar_exc:
        import logging as _logging
        _logging.getLogger("keystone.uploads").warning(
            "Sidecar write failed for %s: %s", rel_path, sidecar_exc
        )

    return {
        "activated":    True,
        "upload_id":    upload_id,
        "rel_path":     rel_path,
        "chunk_count":  len(chunk_rows),
    }


@app.post("/uploads/{upload_id}/reject", status_code=200)
def reject_upload(
    upload_id: str,
    body: _RejectBody,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "upload_to_staging") and not _has_perm(current_user, "reject_document"):
        raise HTTPException(status_code=403, detail="upload_to_staging or reject_document permission required")

    if not body.reason.strip():
        raise HTTPException(status_code=422, detail="reason is required")

    try:
        row = db.execute(
            text("SELECT id, uploader_username, status FROM staged_uploads WHERE id = :uid"),
            {"uid": upload_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    _, uploader, status = row
    # custodians may only reject their own uploads; authority (reject_document) may reject any
    if _has_perm(current_user, "upload_to_staging") and not _has_perm(current_user, "reject_document") and uploader != current_user.username:
        raise HTTPException(status_code=403, detail="Not your upload")
    if status not in ("pending", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot reject upload in status '{status}'",
        )

    try:
        db.execute(text("""
            UPDATE staged_uploads
               SET status='rejected', rejection_reason=:reason,
                   rejected_by=:uname, rejected_at=now()
             WHERE id=:uid
        """), {"reason": body.reason.strip(), "uname": current_user.username, "uid": upload_id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    # Clean up staging file (best-effort)
    try:
        staging_path = _STAGING_DIR / f"{row[0]}.staging_{upload_id[:8]}"
        staging_path.unlink(missing_ok=True)
    except Exception:
        pass

    return {"rejected": True, "upload_id": upload_id}


@app.delete("/uploads/{upload_id}", status_code=200)
def delete_upload(
    upload_id: str,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    if not _has_perm(current_user, "upload_to_staging"):
        raise HTTPException(status_code=403, detail="upload_to_staging permission required")

    try:
        row = db.execute(
            text("SELECT id, uploader_username, status, stored_filename "
                 "FROM staged_uploads WHERE id = :uid"),
            {"uid": upload_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    _, uploader, status, stored_filename = row
    if not _has_perm(current_user, "view_all_user_activity") and uploader != current_user.username:
        raise HTTPException(status_code=403, detail="Not your upload")
    if status not in ("pending", "failed", "rejected"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete upload in status '{status}' — only pending/failed/rejected may be deleted",
        )

    try:
        db.execute(text("DELETE FROM staged_uploads WHERE id = :uid"), {"uid": upload_id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    # Clean up staging file (best-effort)
    try:
        staging_path = _STAGING_DIR / f"{stored_filename}.staging_{upload_id[:8]}"
        staging_path.unlink(missing_ok=True)
    except Exception:
        pass

    return {"deleted": True, "upload_id": upload_id}


@app.post("/uploads/{upload_id}/retry", status_code=200)
def retry_upload(
    upload_id: str,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    """Re-run extraction for a failed upload (e.g. after installing a missing extractor)."""
    if not _has_perm(current_user, "upload_to_staging"):
        raise HTTPException(status_code=403, detail="upload_to_staging permission required")

    try:
        row = db.execute(
            text("SELECT id, uploader_username, status, stored_filename, mime "
                 "FROM staged_uploads WHERE id = :uid"),
            {"uid": upload_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    _, uploader, status, stored_filename, mime = row
    if not _has_perm(current_user, "view_all_user_activity") and uploader != current_user.username:
        raise HTTPException(status_code=403, detail="Not your upload")
    if status != "failed":
        raise HTTPException(
            status_code=409,
            detail=f"Retry only applies to failed uploads (current status: '{status}')",
        )

    staging_path = _STAGING_DIR / f"{stored_filename}.staging_{upload_id[:8]}"
    if not staging_path.exists():
        raise HTTPException(
            status_code=409,
            detail="Staging file missing — cannot retry",
        )

    import time as _time
    t0 = _time.monotonic()
    extraction_error = ""
    failure_reason   = ""
    chunks_data: list[tuple[int, int | None, str]] = []
    try:
        if mime == "application/pdf":
            chunks_data = _ingest_build_chunks_pdf(staging_path)
        else:
            chunks_data = _ingest_build_chunks_other(staging_path, mime)
    except Exception as exc:
        extraction_error = str(exc)
        failure_reason   = "EXTRACTION_ERROR"

    if not extraction_error and not chunks_data:
        failure_reason = "NO_TEXT_EXTRACTED"

    new_status = "failed" if failure_reason else "pending"
    t1 = _time.monotonic()

    try:
        db.execute(text("DELETE FROM staged_upload_chunks WHERE upload_id = :uid"), {"uid": upload_id})
        db.execute(text("""
            UPDATE staged_uploads
               SET status=:status, failure_reason=:freason, failure_detail=:fdetail,
                   processing_started_at=now() - :elapsed * interval '1 second',
                   processing_completed_at=now()
             WHERE id=:uid
        """), {
            "status":  new_status,
            "freason": failure_reason,
            "fdetail": extraction_error,
            "elapsed": round(t1 - t0, 3),
            "uid":     upload_id,
        })

        if new_status == "pending" and chunks_data:
            for ci, pg, ct in chunks_data:
                db.execute(text("""
                    INSERT INTO staged_upload_chunks (upload_id, chunk_index, page, text)
                    VALUES (:uid, :ci, :pg, :ct)
                """), {"uid": upload_id, "ci": ci, "pg": pg, "ct": ct})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {
        "upload_id":       upload_id,
        "status":          new_status,
        "chunk_count":     len(chunks_data),
        "failure_reason":  failure_reason,
        "failure_detail":  extraction_error,
    }


# ---------------------------------------------------------------------------
# Step 7: min_role additive check in _corpus_fts_retrieve
# ---------------------------------------------------------------------------
# Applied inline in _corpus_fts_retrieve via SQL — the WHERE clause
# already filters on cd.domain; we add a min_role gate here by patching
# the FTS SQL at the module level after all definitions are complete.
#
# Pattern: AND _ROLE_LEVEL[requester_role] >= _role_level_for(cd.min_role)
# Implemented as a helper used when the FTS path is called.

# ---------------------------------------------------------------------------
# User management (KDAT-059) — Authority role only
# ---------------------------------------------------------------------------


def _managed_user_to_dict(row: "ManagedUser", query_count: int = 0) -> dict:
    return {
        "email":          row.email,
        "display_name":   row.display_name,
        "role":           row.role,
        "status":         row.status,
        "provisioned_at": row.provisioned_at.isoformat() if row.provisioned_at else None,
        "enabled_at":     row.enabled_at.isoformat() if row.enabled_at else None,
        "disabled_at":    row.disabled_at.isoformat() if row.disabled_at else None,
        "enabled_by":     row.enabled_by,
        "disabled_by":    row.disabled_by,
        "last_login":     row.last_login.isoformat() if row.last_login else None,
        "query_count":    query_count,
    }


def _log_user_mgmt_event(
    db: "DBSession",
    actor: "AppUser",
    subject_email: str,
    action: str,
    old_value: "str | None" = None,
    new_value: "str | None" = None,
    note: "str | None" = None,
) -> None:
    """Write a user_management_events row."""
    db.execute(text("""
        INSERT INTO user_management_events
            (id, ts_utc, actor_email, actor_role, subject_email, action, old_value, new_value, note)
        VALUES
            (:id, now(), :actor_email, :actor_role, :subject_email, :action, :old_value, :new_value, :note)
    """), {
        "id":            str(uuid.uuid4()),
        "actor_email":   actor.email,
        "actor_role":    actor.role,
        "subject_email": subject_email,
        "action":        action,
        "old_value":     old_value,
        "new_value":     new_value,
        "note":          note,
    })


@app.get("/users")
def list_managed_users(
    role:   "str | None" = QueryParam(default=None),
    status: "str | None" = QueryParam(default=None),
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Return full user roster with activity summary (approve_role_assignments)."""
    if not _has_perm(current_session, "approve_role_assignments"):
        raise HTTPException(status_code=403, detail="approve_role_assignments permission required")

    # Build filters
    where_clauses: list[str] = []
    params: dict = {}
    if role:
        where_clauses.append("mu.role = :role")
        params["role"] = role
    if status:
        where_clauses.append("mu.status = :status")
        params["status"] = status

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        rows = db.execute(text(f"""
            SELECT mu.email, mu.display_name, mu.role, mu.status,
                   mu.provisioned_at, mu.enabled_at, mu.disabled_at,
                   mu.enabled_by, mu.disabled_by, mu.last_login,
                   COUNT(al.id) AS query_count
            FROM managed_users mu
            LEFT JOIN audit_log al ON al.user_email = mu.email
            {where_sql}
            GROUP BY mu.email, mu.display_name, mu.role, mu.status,
                     mu.provisioned_at, mu.enabled_at, mu.disabled_at,
                     mu.enabled_by, mu.disabled_by, mu.last_login
            ORDER BY
                CASE mu.role
                    WHEN 'authority' THEN 0
                    WHEN 'custodian' THEN 1
                    WHEN 'officer'   THEN 2
                    ELSE 3
                END,
                mu.email ASC
        """), params).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {
        "total": len(rows),
        "items": [
            {
                "email":          r[0],
                "display_name":   r[1],
                "role":           r[2],
                "status":         r[3],
                "provisioned_at": r[4].isoformat() if r[4] else None,
                "enabled_at":     r[5].isoformat() if r[5] else None,
                "disabled_at":    r[6].isoformat() if r[6] else None,
                "enabled_by":     r[7],
                "disabled_by":    r[8],
                "last_login":     r[9].isoformat() if r[9] else None,
                "query_count":    int(r[10]),
            }
            for r in rows
        ],
    }


@app.post("/users/{email}/enable")
def enable_managed_user(
    email: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Enable a provisioned user (approve_role_assignments)."""
    if not _has_perm(current_session, "approve_role_assignments"):
        raise HTTPException(status_code=403, detail="approve_role_assignments permission required")

    email = email.lower().strip()

    try:
        mu = db.query(ManagedUser).filter(ManagedUser.email == email).first()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not mu:
        raise HTTPException(status_code=404, detail=f"User {email!r} not found in roster")
    if mu.status == "enabled":
        raise HTTPException(status_code=409, detail=f"User {email!r} is already enabled")

    now = datetime.now(timezone.utc)
    mu.status = "enabled"
    mu.enabled_at = now
    mu.enabled_by = current_session.email

    try:
        _log_user_mgmt_event(db, current_session, email, "enabled", old_value="disabled", new_value="enabled")
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _managed_user_to_dict(mu)


@app.post("/users/{email}/disable")
def disable_managed_user(
    email: str,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Disable a user (approve_role_assignments). Cannot disable self or custodians."""
    if not _has_perm(current_session, "approve_role_assignments"):
        raise HTTPException(status_code=403, detail="approve_role_assignments permission required")

    email = email.lower().strip()

    if email == current_session.email.lower():
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    try:
        mu = db.query(ManagedUser).filter(ManagedUser.email == email).first()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not mu:
        raise HTTPException(status_code=404, detail=f"User {email!r} not found in roster")
    if mu.role == "custodian":
        raise HTTPException(status_code=403, detail="Cannot disable Custodian accounts — system operator access is not managed by Authority")
    if mu.status == "disabled":
        raise HTTPException(status_code=409, detail=f"User {email!r} is already disabled")

    now = datetime.now(timezone.utc)
    mu.status = "disabled"
    mu.disabled_at = now
    mu.disabled_by = current_session.email

    # Invalidate any active demo sessions for this email
    try:
        db.execute(text("DELETE FROM sessions WHERE username = :email"), {"email": email})
        _log_user_mgmt_event(db, current_session, email, "disabled", old_value="enabled", new_value="disabled")
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _managed_user_to_dict(mu)


@app.post("/users/{email}/role")
def change_managed_user_role(
    email: str,
    body: _ChangeRoleBody,
    db: DBSession = Depends(get_db),
    current_session: AppUser = Depends(get_current_user),
):
    """Change a user's role (approve_role_assignments). Cannot change own role or custodian role."""
    if not _has_perm(current_session, "approve_role_assignments"):
        raise HTTPException(status_code=403, detail="approve_role_assignments permission required")

    email = email.lower().strip()

    if email == current_session.email.lower():
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    allowed_target_roles = {"member", "officer", "authority"}
    if body.role not in allowed_target_roles:
        raise HTTPException(status_code=422, detail=f"role must be one of: {sorted(allowed_target_roles)}")

    try:
        mu = db.query(ManagedUser).filter(ManagedUser.email == email).first()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not mu:
        raise HTTPException(status_code=404, detail=f"User {email!r} not found in roster")
    if mu.role == "custodian":
        raise HTTPException(status_code=403, detail="Cannot change Custodian role — system operator roles are not managed by Authority")
    if body.role == "custodian":
        raise HTTPException(status_code=403, detail="Cannot assign Custodian role — contact system operator")
    if mu.role == body.role:
        raise HTTPException(status_code=409, detail=f"User {email!r} already has role {body.role!r}")

    old_role = mu.role
    mu.role = body.role

    # Sync cf_users record if present
    try:
        db.execute(
            text("UPDATE cf_users SET assigned_role = :role, updated_at = now() WHERE email = :email"),
            {"role": body.role, "email": email},
        )
        # Invalidate sessions so user re-authenticates with new role
        db.execute(text("DELETE FROM sessions WHERE username = :email"), {"email": email})
        _log_user_mgmt_event(
            db, current_session, email, "role_changed",
            old_value=old_role, new_value=body.role,
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return _managed_user_to_dict(mu)


def _min_role_level_sql_expr(role_param: str) -> str:
    """Return a SQL snippet that compares the requester's role level against cd.min_role."""
    # Use CASE to translate min_role TEXT to integer inline in SQL
    return (
        f"AND CASE cd.min_role "
        f"    WHEN 'member' THEN 0 "
        f"    WHEN 'custodian' THEN 0 "
        f"    WHEN 'officer' THEN 1 "
        f"    WHEN 'authority' THEN 2 "
        f"    ELSE 0 END <= :{role_param}"
    )
