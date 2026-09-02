# Keystone Gov

Governed RAG for regulated enterprise content.

## What this is

Regulated enterprises need retrieval that does more than find relevant text. It has to enforce who is allowed to see what, refuse when the evidence is insufficient, judge whether a generated answer is actually supported by its sources, and leave a record that holds up under scrutiny. Most RAG systems treat access control, refusal, and audit as things to add later.

Keystone Gov is built the other way around. Role-based access control is enforced at query time as a WHERE clause in the database, so documents above the caller's role level are never returned. Answers are refused at several independent gates rather than guessed. A dedicated model scores factual consistency and withholds answers the evidence does not support. Every query and every refusal is written to an audit trail with a keyed HMAC-SHA256 integrity check.

The system runs on customer-controlled infrastructure with local models through Ollama and factual consistency scoring via HHEM-2.1-Open on CPU. There is no external API dependency for core operation.

## Architecture

A request to `POST /query` (`api/main.py`, `submit_query`) runs through a fixed pipeline:

1. Rate limiting per session token.
2. Role is derived from the authenticated session. The role in the request body is ignored.
3. Prompt-injection check. A detected injection returns a refusal and is written to the audit trail without exposing any corpus data.
4. Jurisdiction guard. The current corpus covers Alberta OHS only, so queries that reference other jurisdictions are refused and audited.
5. Hybrid retrieval over full-text search and pgvector. Both queries carry the role-level ACL as a WHERE clause, plus domain and jurisdiction constraints. Documents above the caller's role level are excluded in the database and never reach the application.
6. Evidence threshold. If nothing meets the threshold, the query is refused as insufficient evidence and audited.
7. Answer synthesis from the retrieved evidence by a local LLM.
8. Factual consistency scoring with HHEM-2.1-Open. A score below threshold produces a `LOW_FACTUAL_CONSISTENCY` refusal and the answer is withheld.
9. The query and its outcome are written as an audit entry with a per-record HMAC-SHA256 integrity check, linked to the prior entry by its hash.

The response returns a query id. The answer and the audit receipt are fetched separately (`GET /guidance/{query_id}`, `GET /audit/{query_id}`). Every outcome, allowed or refused, is audited with the same detail, and each gate produces its own specific refusal reason.

## Governance controls

These are the controls enforced in the served path.

**Query-time role-based access control.** Enforced as a WHERE clause in both the full-text and pgvector retrieval queries. Documents above the caller's role level are never returned. Domain and jurisdiction constraints are applied at the same layer. This is not a post-retrieval filter in application code.

**Fail-closed refusal.** Several independent gates can refuse a query: prompt-injection detection, the jurisdiction guard, the insufficient-evidence threshold, and the factual-consistency threshold. Each gate produces a specific refusal reason, and a refused query is audited with the same detail as an allowed one.

**Factual consistency scoring.** Vectara HHEM-2.1-Open runs as a separate model-based factual-consistency scorer, checking whether the generated answer is supported by the retrieved evidence. Two thresholds are used because the answer source predicts the score range: a deterministic default of 0.5 and an LLM default of 0.20, both configurable by environment variable. Answers below the applicable threshold are withheld with a `LOW_FACTUAL_CONSISTENCY` refusal. This is a design choice, not independent validation of correctness: the scorer is not a correctness oracle, and a passing score does not prove the answer is factually correct. The scorer runs on CPU with no external API dependency. If the scorer model fails to load or errors at runtime, scoring degrades open rather than refusing: the score field records `None`, and the pipeline does not block solely because the scorer was unavailable.

**Per-record HMAC-SHA256 audit trail.** Every query and every refusal writes an audit entry with a keyed HMAC-SHA256 integrity check. Entries are linked at write time, each recording the prior entry's hash, which forms a structural chain. The shipped verifier (`verify_entry`) checks one record at a time by recomputing its HMAC from that record's stored fields. There is no chain-walk verifier that validates linkage across the full ledger.

The HMAC covers the query id, timestamp, role used, mode used, policy outcome, and the prior entry's hash. It does not cover the answer text, the cited document ids, or the factual consistency score. Those fields are stored on the audit row but sit outside the signature, so altering them would not be detected by the current verifier. The service refuses to start with a weak or short HMAC key.

## Evaluation

Published baselines and the eval ledger live in [`keystone-ledger`](https://github.com/getkeystone/keystone-ledger). These are retained internal evaluation results tied to a specific evaluated commit and configuration, not independent validation, and a passing run does not establish that every current keystone-gov behavior is covered.

**keystone-core/agent-v1** (historical id KDAT-002D, governed agent extension, 2026-05-20): 186 cases across 12 categories, 558 executions, 153 strict pass, 33 characterization, 0 strict failures. A preceding run, keystone-core/agent-v0 (KDAT-002C), had found 9 failing cases traced to 4 root-cause defects; those were fixed before agent-v1 was recorded.

**keystone-core/retrieval-v1** (historical id KDAT-001B, 2026-04-11), measured on this codebase's retrieval pipeline:

| Metric | Result |
| --- | --- |
| Corpus | 53 Alberta OHS documents, 2,674 chunks |
| Retrieval P@1 | 0.75 |
| MRR | 0.79 |
| Adversarial ACL | 8/8 blocked, 0 leaks |
| Fail-closed | 5/6 (83%). FC-005 domain-scope guard merged 2026-05-17 (demo-grade remediation); a passing re-verification is not yet recorded. |

## Contact-center heritage

Keystone Gov draws on operational patterns familiar from enterprise contact-center systems, not on the claim that those systems solved the same problem with the same tools:

- Query-time role-level access control resembles need-to-know access on regulated records.
- Fail-closed refusal resembles refusing under uncertainty rather than guessing.
- The per-record HMAC audit trail resembles compliance logging.
- Model-based factual-consistency scoring resembles quality monitoring of what was said, applied to a generated answer rather than a human one.

## Getting started

Prerequisites: Python 3.12, PostgreSQL 16 with the pgvector extension, and Ollama serving `nomic-embed-text` and `qwen2.5:7b-instruct`. The HHEM-2.1-Open model is downloaded from Hugging Face on first load and cached on the host.

Configure the API by copying `api/.env.example` to `api/.env` and filling in the values (database URL, `AUDIT_HMAC_KEY`, HHEM threshold, and related settings).

Install dependencies and run the API from the `api` directory:

```bash
cd api
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

A `Dockerfile` is provided in `api/` for building a container image that runs the same `uvicorn` command.

## Related repos

- [`keystone-ledger`](https://github.com/getkeystone/keystone-ledger): retained internal evaluation artifacts and lineage. Public.
- [`keystone-verify`](https://github.com/getkeystone/keystone-verify): the evaluation framework as a standalone tool. Public.
- [`keystone-engage`](https://github.com/getkeystone/keystone-engage): governed conversational agent for regulated customer interaction. Public.
- [`keystone-counsel`](https://github.com/getkeystone/keystone-counsel): authorization-first retrieval for regulated content. Public.

Live demo: [demo.getkeystone.ai](https://demo.getkeystone.ai). Contact: [arnaldo@getkeystone.ai](mailto:arnaldo@getkeystone.ai).

## License

Apache-2.0. See [LICENSE](LICENSE).
