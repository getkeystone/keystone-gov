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
    # SQL injection patterns
    r';\s*(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE)\s+',
    r'UNION\s+(ALL\s+)?SELECT',
    r"'\s*(OR|AND)\s+'?\s*\d+\s*[='<>]",
    r'--\s*$',
    # XSS patterns
    r'<\s*script',
    r'javascript\s*:',
    r'on(load|error|click|mouseover|submit)\s*=',
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


_MAX_LLM_QUERY_LEN = 500

# Lines that look like injected instructions rather than user questions
_INJECTION_LINE_PATTERN = re.compile(
    r'(ignore\s+(previous|above|all|prior)|new\s+instructions?|system\s*:|'
    r'you\s+are\s+now|override\s+(your|the)|forget\s+(previous|above))',
    re.IGNORECASE,
)


def sanitize_query_for_llm(text: str) -> str:
    """Return a sanitized version of text safe to embed in an LLM prompt.

    Strips lines that match injection patterns, removes code fences, and
    truncates to _MAX_LLM_QUERY_LEN characters.  Only used for the text
    passed to the LLM -- check_injection() is still the gate for blocking.
    """
    lines = text.splitlines()
    clean_lines = []
    for line in lines:
        if _INJECTION_LINE_PATTERN.search(line):
            log.warning("sanitize_query_for_llm: stripped injection line: %r", line[:120])
            continue
        # Strip code fence markers
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            continue
        clean_lines.append(line)
    result = "\n".join(clean_lines).strip()
    if len(result) > _MAX_LLM_QUERY_LEN:
        log.warning("sanitize_query_for_llm: truncated query from %d to %d chars", len(result), _MAX_LLM_QUERY_LEN)
        result = result[:_MAX_LLM_QUERY_LEN]
    return result


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
