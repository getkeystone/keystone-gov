# Eval Ledger Naming Migration

Effective: 2026-05-31

## Convention

New format: `keystone-{component}/{type}-v{n}`

Each component carries independent version lineage. Old versions stay published as reference. Hash-chained audit log entries are never renamed.

## Migration table

| Old | New | Description |
|---|---|---|
| KDAT-001B | keystone-core/retrieval-v1 | Retrieval baseline (P@1=0.75, MRR=0.79) |
| KDAT-002B | keystone-core/agent-v0-pre | Earlier agent eval (historical) |
| KDAT-002C | keystone-core/agent-v0 | Agent eval, 66 cases, found 4 bugs (published failing run) |
| KDAT-002D | keystone-core/agent-v1 | Agent eval, 186 cases, 558 executions, 0 failures (canonical) |
| KDAT-002 | keystone-core/agent | Governed agent extension project |

## Why

Old KDAT-NNNL codes required a lookup table. New naming is self-describing.
