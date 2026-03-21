"""
Sanitize user query input to mitigate LLM prompt injection.

Strategy: detect patterns that attempt to override the system
prompt, and either strip them or reject the query entirely.
"""
import re
import logging

log = logging.getLogger("keystone.sanitizer")

# Patterns that indicate prompt injection attempts
_INJECTION_PATTERNS = [
    r'ignore\s+(previous|above|all|prior)\s+(instructions?|prompts?|rules?|constraints?)',
    r'disregard\s+(previous|above|all|prior)',
    r'forget\s+(previous|above|all|your)\s+(instructions?|prompts?|rules?)',
    r'you\s+are\s+now\s+a',
    r'new\s+instructions?\s*:',
    r'system\s*:\s*',
    r'<\s*system\s*>',
    r'<<\s*SYS\s*>>',
    r'\[INST\]',
    r'\[\/INST\]',
    r'###\s*(system|instruction|human|assistant)',
    r'respond\s+as\s+if\s+you\s+are',
    r'pretend\s+(you\s+are|to\s+be)',
    r'act\s+as\s+if',
    r'override\s+(your|the|all)\s+(rules?|instructions?|constraints?)',
    r'do\s+not\s+follow\s+(your|the|previous)',
    r'list\s+all\s+(documents?|files?|titles?|chunks?)',
    r'show\s+(me\s+)?(all|every)\s+(documents?|files?|titles?)',
    r'what\s+(documents?|files?)\s+(do\s+you|are\s+in)',
    r'dump\s+(all|the|your)',
    r'reveal\s+(your|the)\s+(prompt|instructions?|system)',
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


def check_injection(query: str) -> tuple[bool, str]:
    """
    Returns (is_safe, reason).
    is_safe=True means the query is OK to process.
    is_safe=False means injection was detected.
    """
    for pattern in _COMPILED:
        if pattern.search(query):
            log.warning("Prompt injection detected: %r", query[:200])
            return False, "Query rejected: input contains patterns that could manipulate the system."
    return True, ""
