# Keystone Gov

Governed retrieval API for regulated industries. Hybrid search, LLM generation, query-time access control, and tamper-evident audit logging.

## What this is

A RAG system built with a different set of constraints than typical AI retrieval tools:

- Evidence-backed answers tied to specific source documents and sections
- Role-based access control enforced at query time, before results return
- Fail-closed refusal when evidence is insufficient
- Factual consistency scoring on every response (HHEM-2.1-Open)
- Hash-chained, tamper-evident audit trail (HMAC-SHA256, INSERT-only database role)
- Document version tracking with point-in-time retrieval
- Config-driven multi-deployment architecture

The system runs entirely on customer-controlled infrastructure with no external API dependencies for inference or embedding.

## Query pipeline

11 steps: input validation, jurisdiction scoping, RBAC, hybrid retrieval (pgvector + full-text search), ACL filtering, reranking, evidence thresholding, LLM synthesis, factual consistency scoring, fail-closed gate, hash-chained audit logging.

## Evaluation baseline (KDAT-001B, 2026-04-11)

| Metric | Result |
|--------|--------|
| Corpus | 53 Alberta OHS safety documents, 2,674 chunks |
| Retrieval P@1 | 0.75 |
| MRR | 0.79 |
| Adversarial ACL | 8/8 blocked, 0 leaks |
| Fail-closed | 5/6 (83%) |
| Audit chain | Intact, immutable |

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
