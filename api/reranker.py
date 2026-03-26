"""
Generic procedural reranker for Keystone hybrid search.

Replaces the LRFD-specific reranker removed in dev/keystone-next.
See feature/pilot-enhancements for the original fire-service reranker.

Takes hybrid search results (already scored by FTS + vector merge),
applies quality filters, and returns the top_k chunks for the LLM
evidence pack.  No domain-specific logic lives here.
"""

import re

STOP_WORDS = {
    'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be',
    'been', 'being', 'have', 'has', 'had', 'do', 'does',
    'did', 'will', 'would', 'could', 'should', 'may',
    'might', 'shall', 'can', 'need', 'dare', 'ought',
    'used', 'to', 'of', 'in', 'for', 'on', 'with', 'at',
    'by', 'from', 'as', 'into', 'through', 'during',
    'before', 'after', 'above', 'below', 'between',
    'out', 'off', 'over', 'under', 'again', 'further',
    'then', 'once', 'here', 'there', 'when', 'where',
    'why', 'how', 'all', 'each', 'every', 'both', 'few',
    'more', 'most', 'other', 'some', 'such', 'no', 'nor',
    'not', 'only', 'own', 'same', 'so', 'than', 'too',
    'very', 'just', 'because', 'but', 'and', 'or', 'if',
    'while', 'what', 'which', 'who', 'whom', 'this',
    'that', 'these', 'those', 'i', 'me', 'my', 'we',
    'our', 'you', 'your', 'he', 'him', 'his', 'she',
    'her', 'it', 'its', 'they', 'them', 'their',
}


def rerank_chunks(
    chunks: list[dict],
    query: str,
    top_k: int = 5,
) -> list[dict]:
    """
    Generic procedural reranker.

    Takes hybrid search results (already scored by FTS + vector),
    applies quality filters, and returns the top_k chunks for
    the LLM evidence pack.

    Each chunk dict must have:
        text  (str)   — chunk body
        score (float) — hybrid merge score

    Each returned chunk gains:
        rerank_score  (float) — final adjusted score
        rerank_reason (str)   — debug string for confidence block
    """
    query_terms = {
        w for w in re.findall(r'[a-z0-9]+', query.lower())
        if w not in STOP_WORDS and len(w) > 2
    }

    scored = []
    for chunk in chunks:
        text = chunk.get('text', '')
        base_score = chunk.get('score', 0.0)
        multiplier = 1.0

        # 1. TOC / boilerplate filter
        lines = text.strip().split('\n')
        short_lines = sum(1 for l in lines if len(l.strip()) < 40)
        if len(lines) > 3 and short_lines / len(lines) > 0.7:
            multiplier *= 0.3
        if any(marker in text.lower() for marker in [
            'table of contents', '©', 'all rights reserved',
            'isbn', 'printed in',
        ]):
            multiplier *= 0.3

        # 2. Length normalization
        text_len = len(text.strip())
        if text_len < 200:
            multiplier *= 0.7
        # Above 1200: no adjustment — long chunks don't get a bonus

        # 3. Query term overlap boost
        text_lower = text.lower()
        overlap = sum(1 for t in query_terms if t in text_lower)
        if overlap >= 3:
            multiplier *= 1.2
        elif overlap >= 1:
            multiplier *= 1.1

        # 4. Document title match boost
        # If query terms appear in the document title, boost this chunk.
        # A document titled "H2S Exposure Limits Supplement" is more likely
        # to be the right source for a query about "H2S exposure limits"
        # than a general document that happens to mention H2S.
        title_lower = chunk.get('title', '').lower()
        title_overlap = sum(1 for t in query_terms if t in title_lower)
        if title_overlap >= 3:
            multiplier *= 1.5
        elif title_overlap >= 2:
            multiplier *= 1.3
        elif title_overlap >= 1:
            multiplier *= 1.15

        # 5. Chunk quality
        alnum = sum(c.isalnum() or c == ' ' for c in text)
        density = alnum / max(len(text), 1)
        if density < 0.5:
            multiplier *= 0.5
        if '.' not in text:
            multiplier *= 0.7

        final_score = base_score * multiplier
        chunk['rerank_score'] = final_score
        chunk['rerank_reason'] = (
            f"base={base_score:.4f} mult={multiplier:.2f} "
            f"overlap={overlap} density={density:.2f}"
        )
        scored.append(chunk)

    scored.sort(key=lambda c: c['rerank_score'], reverse=True)
    return scored[:top_k]
