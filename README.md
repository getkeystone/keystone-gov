# Keystone Gov

Governed retrieval API for regulated industries. Hybrid search, LLM generation, query-time access control, and tamper-evident audit logging.

## What this is

A RAG system built with a different set of constraints than typical AI retrieval tools:

- Evidence-backed answers tied to specific source documents and sections
- Role-based access control enforced at query time, before results return
- Domain scope guard: pre-retrieval refusal for out-of-corpus queries
- Fail-closed refusal when evidence is insufficient
- Factual consistency scoring on every response (HHEM-2.1-Open)
- Hash-chained, tamper-evident audit trail (HMAC-SHA256, INSERT-only database role)
- Document version tracking with point-in-time retrieval
- Config-driven multi-deployment architecture

The system runs entirely on customer-controlled infrastructure with no external API dependencies for inference or embedding.

## Query pipeline

Pre-retrieval gates: input validation, prompt injection check, jurisdiction guard, domain scope guard, RBAC.
Retrieval: hybrid (pgvector + full-text search), ACL filtering, reranking.
Post-retrieval: evidence thresholding, LLM synthesis, factual consistency scoring (HHEM-2.1-Open), fail-closed gate.
Audit: hash-chained, tamper-evident logging on every query and every refusal.

## Evaluation baseline (KDAT-001B, 2026-04-11)

| Metric | Result |
|--------|--------|
| Corpus | 53 Alberta OHS safety documents, 2,674 chunks |
| Retrieval P@1 | 0.75 |
| MRR | 0.79 |
| Adversarial ACL | 8/8 blocked, 0 leaks |
| Fail-closed | 5/6 (83%) |
| Audit chain | Intact, immutable |

**FC-005 remediation (2026-05-17, v0.5.2-fc005):** Pre-retrieval domain scope guard refusing out-of-corpus queries. Closes the KDAT-001B FC-005 failure where a TIER greenhouse gas query returned Part 36 mine gas chunks via embedding overlap. Validated manually against the probe set. Full taxonomy-based two-stage gate scoped for KDAT-002. Commit: [38ef89f](https://github.com/getkeystone/keystone-gov/commit/38ef89f).

Full eval methodology and ledger: [getkeystone/keystone-kdat](https://github.com/getkeystone/keystone-kdat)

## Stack

Python, FastAPI, PostgreSQL 16 + pgvector, Ollama (nomic-embed-text, qwen2.5:7b-instruct), Docker Compose, Caddy.

## Running locally

Requires Docker and Docker Compose.

```bash
cp .env.example .env
# Edit .env with your configuration
docker compose up -d
```

See .env.example for required environment variables.

## In development

Governed agent extension (KDAT-002): tool authorization by role, action audit trails, HITL approval gates, multi-step reasoning with per-step evidence.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Links

| | |
|---|---|
| Live demo | [demo.getkeystone.ai](https://demo.getkeystone.ai) |
| Eval ledger | [getkeystone/keystone-kdat](https://github.com/getkeystone/keystone-kdat) |
| Org profile | [github.com/getkeystone](https://github.com/getkeystone) |
| Contact | [arnaldo@getkeystone.ai](mailto:arnaldo@getkeystone.ai) |
