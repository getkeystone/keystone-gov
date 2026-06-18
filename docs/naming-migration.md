# Eval Ledger Naming Migration

Effective: 2026-05-31

## Convention

New format: `keystone-{component}/{type}-v{n}`

Each component carries independent version lineage. Old versions stay published as reference. Hash-chained audit log entries are never renamed; they retain their original identifiers as sealed artifacts.

## Migration table

| Old identifier | New identifier | Description |
|---|---|---|
| KDAT-001B | keystone-core/retrieval-v1 | Retrieval baseline (P@1=0.75, MRR=0.79) |
| KDAT-002C | keystone-core/agent-v0 | Agent eval, 66 cases, found 4 bugs (published failing run) |
| KDAT-002D | keystone-core/agent-v1 | Agent eval, 186 cases, 558 executions, 0 failures (canonical) |
| KDAT-002 | keystone-core/agent | Governed agent extension project |
| KDAT-002-SPEC v1.2 | keystone-core/agent-spec v1.2 | Agent extension specification |

## Planned entries

| Identifier | Description |
|---|---|
| keystone-engage/agent-v1 | Governed conversational agent for regulated customer interaction |
| keystone-counsel/retrieval-v1 | Regulated content RAG for legal/financial advisory |
| keystone-verify/framework-v1 | Standalone eval harness, public release |

## Why

The old KDAT-NNNL codes were internal shorthand that required a lookup table to understand. The new naming is self-describing: the component, the artifact type, and the version are all in the name. External links or citations using old KDAT codes remain valid as historical references.
