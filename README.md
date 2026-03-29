# Keystone Gov

Core API engine for Keystone AI. Governed procedure retrieval with evidence-backed answers, query-time access control, and tamper-evident audit logging.

Runs entirely on customer infrastructure. No external API calls. Air-gap compatible.

## What it does

- **Retrieval pipeline**: Hybrid search (FTS + vector via pgvector) with LLM synthesis (Ollama)
- **Query-time ACL**: Role-based content filtering enforced before the LLM sees any evidence
- **Fail-closed behavior**: Refuses when evidence is insufficient, jurisdiction is wrong, or input is flagged
- **Factual consistency scoring**: HHEM-2.1-Open scores every LLM-generated answer
- **Feedback capture**: Thumbs up/down with auto-creation of review tasks on negative signals
- **Document version tracking**: Create, approve (with separation of duties), temporal lookup ("which version was active on date X?")
- **Review workflow**: Feedback -> review task -> assign -> comment -> resolve/dismiss -> publication decision
- **Audit trail**: HMAC-SHA256 hash-chained audit log, tamper-evident, verifiable per-entry
- **Evidence export**: Cryptographically signed evidence bundles for compliance review

## Architecture

- **Framework**: FastAPI (Python 3.12)
- **Database**: PostgreSQL 16 + pgvector
- **Inference**: Ollama (qwen2.5:7b-instruct for generation, nomic-embed-text for embeddings)
- **Auth**: Password-based demo sessions + Cloudflare Access (production)
- **Two DB roles**: keystone (owner, migrations) and keystone_app (runtime, restricted privileges)

## Branches

| Branch | Purpose |
|--------|---------|
| main | Last stable release (v0.4.2-compliance) |
| dev/keystone-next | Active development (v0.5.1-review) |

## Current deployment

- demo.getkeystone.ai runs v0.5.1-review (Alberta OHS corpus, 54 documents)
- lrfd.getkeystone.ai runs v0.3.1 (frozen pilot)

## KDAT milestones delivered

101 milestones tracked. Key recent milestones:
- KDAT-096: Document version tracking schema + 5 API endpoints
- KDAT-098: Review workflow + 7 API endpoints + feedback auto-task
- KDAT-100: Governed learning loop end-to-end (46/46 tests)

## License

Keystone Gov is licensed under the [Business Source License 1.1](LICENSE).

**Non-production use is free:**
- Development, testing, and evaluation environments only
- Up to 100 internal users

**Production use requires a commercial license.**

**Change Date:** 2030-01-01
After this date, the license automatically converts to Apache License 2.0.

For commercial licensing: arnaldo@getkeystone.ai
