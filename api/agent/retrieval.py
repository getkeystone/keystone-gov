"""
Thin retrieval helper for the agent lookup_procedure tool.

Implements hybrid FTS + vector search using the same building blocks as
api/main.py (_corpus_fts_retrieve, _hybrid_merge) without importing from
that module. Reuses ollama_client.embed() and reranker.rerank_chunks().

ACL note: all KDAT-002 roles (operator/supervisor/custodian/admin) map to
req_level=0 for corpus access — the full 53-document Alberta OHS corpus has
min_role='member', so all agent roles can read it. Higher-level ACL
enforcement (min_role='officer'/'authority') is preserved by the SQL WHERE
clause.
"""
import logging

from sqlalchemy import text
from sqlalchemy.orm import Session as DBSession

log = logging.getLogger("keystone.agent.retrieval")

_FTS_RANK_MIN = 0.05
_HYBRID_W_FTS = 0.50
_HYBRID_W_VEC = 0.50
_VEC_FLOOR = 0.20
_TOP_K = 5

# Map KDAT-002 roles to corpus ACL level.
_AGENT_ROLE_LEVEL = {
    "operator": 0,
    "supervisor": 0,
    "custodian": 0,
    "admin": 0,
}

_FTS_SQL = """
    SELECT
        cd.rel_path,
        cd.title,
        cc.chunk_index,
        cc.text,
        ts_rank_cd(cc.tsv, query) AS rank,
        cc.page,
        cd.effective_date,
        cd.review_date,
        cd.owner
    FROM corpus_chunks cc
    JOIN corpus_documents cd ON cd.id = cc.doc_id
    CROSS JOIN websearch_to_tsquery('english', :q) query
    WHERE cc.tsv @@ query
      AND CASE cd.min_role
            WHEN 'member'    THEN 0
            WHEN 'custodian' THEN 0
            WHEN 'officer'   THEN 1
            WHEN 'authority' THEN 2
            ELSE 0 END <= :req_level
      AND (cd.status_override IS DISTINCT FROM 'restricted' OR :req_level >= 1)
      AND (cd.status_override IS DISTINCT FROM 'draft')
    ORDER BY rank DESC
    LIMIT 50
"""

_VEC_SQL = """
    SELECT
        cd.rel_path,
        cd.title,
        cc.chunk_index,
        cc.text,
        1.0 - (cc.embedding <=> CAST(:embedding AS vector)) AS cosine_sim,
        cc.page,
        cd.effective_date,
        cd.review_date,
        cd.owner
    FROM corpus_chunks cc
    JOIN corpus_documents cd ON cd.id = cc.doc_id
    WHERE cc.embedding IS NOT NULL
      AND CASE cd.min_role
            WHEN 'member'    THEN 0
            WHEN 'custodian' THEN 0
            WHEN 'officer'   THEN 1
            WHEN 'authority' THEN 2
            ELSE 0 END <= :req_level
      AND (cd.status_override IS DISTINCT FROM 'restricted' OR :req_level >= 1)
      AND (cd.status_override IS DISTINCT FROM 'draft')
    ORDER BY cc.embedding <=> CAST(:embedding AS vector)
    LIMIT 50
"""


def _fts_retrieve(query: str, req_level: int, db: DBSession) -> list:
    try:
        rows = db.execute(
            text(_FTS_SQL), {"q": query, "req_level": req_level}
        ).fetchall()
        return [r for r in rows if r[4] >= _FTS_RANK_MIN]
    except Exception as exc:
        log.warning("FTS retrieval failed: %s", exc)
        db.rollback()
        return []


def _vec_retrieve(query: str, req_level: int, db: DBSession) -> list:
    try:
        import ollama_client
        vec = ollama_client.embed(query)
    except Exception:
        return []
    if vec is None:
        return []
    pg_vec = "[" + ",".join(str(v) for v in vec) + "]"
    try:
        rows = db.execute(
            text(_VEC_SQL), {"embedding": pg_vec, "req_level": req_level}
        ).fetchall()
        return [r for r in rows if r[4] >= _VEC_FLOOR]
    except Exception as exc:
        log.warning("Vector retrieval failed: %s", exc)
        db.rollback()
        return []


def _hybrid_merge(fts_rows: list, vec_rows: list) -> list:
    """Weighted min-max normalized hybrid merge (mirrors main.py logic)."""
    if not vec_rows:
        return list(fts_rows)
    if not fts_rows:
        return list(vec_rows)

    fts_mn = min(r[4] for r in fts_rows)
    fts_mx = max(r[4] for r in fts_rows)
    vec_mn = min(r[4] for r in vec_rows)
    vec_mx = max(r[4] for r in vec_rows)

    def _n_fts(s: float) -> float:
        return (s - fts_mn) / (fts_mx - fts_mn) if fts_mx > fts_mn else 1.0

    def _n_vec(s: float) -> float:
        return (s - vec_mn) / (vec_mx - vec_mn) if vec_mx > vec_mn else 1.0

    merged: dict = {}
    for row in fts_rows:
        key = (row[0], row[2])
        merged[key] = {"row": row, "score": _HYBRID_W_FTS * _n_fts(row[4])}
    for row in vec_rows:
        key = (row[0], row[2])
        if key in merged:
            merged[key]["score"] += _HYBRID_W_VEC * _n_vec(row[4])
        else:
            merged[key] = {"row": row, "score": _HYBRID_W_VEC * _n_vec(row[4])}

    return sorted(
        [(e["row"][0], e["row"][1], e["row"][2], e["row"][3],
          e["score"], e["row"][5], e["row"][6], e["row"][7], e["row"][8])
         for e in merged.values()],
        key=lambda r: r[4],
        reverse=True,
    )


def retrieve_for_topic(
    topic: str,
    facility_type: str,
    role: str,
    db: DBSession,
    top_k: int = _TOP_K,
) -> dict:
    """
    Hybrid retrieval for lookup_procedure.

    Returns:
        {
          "found": bool,
          "topic": str,
          "facility_type": str,
          "content": str,           # top chunk text
          "citations": list[dict],  # [{document_id, title, chunk_index, page}]
          "evidence_score": float,
        }
    """
    req_level = _AGENT_ROLE_LEVEL.get(role, 0)
    query = f"{topic} {facility_type}".strip()

    # Check whether corpus is populated; fall back to empty result if not.
    try:
        count = db.execute(text("SELECT COUNT(*) FROM corpus_chunks LIMIT 1")).scalar()
    except Exception:
        db.rollback()
        count = 0

    if not count:
        return {
            "found": False,
            "topic": topic,
            "facility_type": facility_type,
            "content": "",
            "citations": [],
            "evidence_score": 0.0,
            "note": "corpus_empty",
        }

    fts_rows = _fts_retrieve(query, req_level, db)
    vec_rows = _vec_retrieve(query, req_level, db)
    rows = _hybrid_merge(fts_rows, vec_rows)

    if not rows:
        return {
            "found": False,
            "topic": topic,
            "facility_type": facility_type,
            "content": "",
            "citations": [],
            "evidence_score": 0.0,
        }

    # Rerank to surface most relevant chunks.
    try:
        from reranker import rerank_chunks
        chunk_dicts = [
            {"rel_path": r[0], "title": r[1], "chunk_index": r[2],
             "text": r[3], "score": r[4], "page": r[5]}
            for r in rows
        ]
        reranked = rerank_chunks(chunk_dicts, query, top_k=top_k)
    except Exception as exc:
        log.warning("Reranker failed, using raw merge order: %s", exc)
        reranked = [
            {"rel_path": r[0], "title": r[1], "chunk_index": r[2],
             "text": r[3], "score": r[4], "page": r[5]}
            for r in rows[:top_k]
        ]

    top = reranked[0]
    citations = [
        {
            "document_id": c["rel_path"],
            "title": c["title"],
            "chunk_index": c["chunk_index"],
            "page": c.get("page"),
        }
        for c in reranked[:top_k]
    ]

    return {
        "found": True,
        "topic": topic,
        "facility_type": facility_type,
        "content": top["text"],
        "citations": citations,
        "evidence_score": float(top["score"]),
    }
