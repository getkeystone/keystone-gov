# Keystone Gov

Governed retrieval and agent API for regulated industries. Hybrid search, LLM generation, query-time ACL, per-step evidence gating, HITL routing, and tamper-evident audit logging.

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

## Evaluation baselines

**keystone-core/agent-v1 (formerly KDAT-002D) (2026-05-20, v0.6.1):** Governed agent extension, canonical eval. 186 eval cases across 12 categories, 558 executions (3 runs), 0 failures. All keystone-core/agent-v0 bugs fixed and re-verified. Audit chain intact across all 558 executions. 135 documents, 23,684 chunks.

**keystone-core/agent-v0 (formerly KDAT-002C):** 66-case agent eval that identified 4 system bugs: HMAC timestamp verification mismatch, 3 injection scanner gaps. Published as the failing run alongside agent-v1. All bugs fixed in agent-v1 and re-verified.

**keystone-core/agent-v0-pre (formerly KDAT-002B) (2026-05-20, v0.6.1):** Governed agent extension baseline. 159 unit tests. 66 eval cases × 3 runs = 198 executions, 0 failures. H1 confirmed: governance primitives extend to tool-using agents without redesign. All adversarial categories at 100% strict pass. All STRIDE categories and all 4 severity tiers covered. Audit chain intact across all 198 executions.

**keystone-core/retrieval-v1 (formerly KDAT-001B) (2026-04-11):**

| Metric | Result |
|--------|--------|
| Corpus | 53 Alberta OHS safety documents, 2,674 chunks |
| Retrieval P@1 | 0.75 |
| MRR | 0.79 |
| Adversarial ACL | 8/8 blocked, 0 leaks |
| Fail-closed | 5/6 (83%). FC-005 remediated 2026-05-17 (v0.5.2-fc005). |
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

## Governed agent extension (keystone-core/agent)

Tool authorization by role, per-step evidence gating, HITL approval routing, and action audit chain. Same governance controller as the retrieval path — no redesign required. Shipped 2026-05-20 (v0.6.1).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Links

| | |
|---|---|
| Live demo | [demo.getkeystone.ai](https://demo.getkeystone.ai) |
| Eval ledger | [getkeystone/keystone-kdat](https://github.com/getkeystone/keystone-kdat) |
| Org profile | [github.com/getkeystone](https://github.com/getkeystone) |
| Contact | [arnaldo@getkeystone.ai](mailto:arnaldo@getkeystone.ai) |
