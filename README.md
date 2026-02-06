# Keystone Gov

Authorization and audit subsystem for Keystone AI.

Runs fully on customer infrastructure. No external API calls. Air-gap compatible.

## What This Does

### Access Control
- Maps user identities to organizational roles and attributes
- Enforces authorization at query time (permission-aware retrieval)
- Preserves ACL fidelity from source systems (SharePoint, file shares)
- Supports RBAC, ABAC, and policy-based controls

### Audit Records
- Logs every query (user, timestamp, query text)
- Logs every retrieval (sources accessed, permission checks performed)
- Logs every response (answer generated, citations returned, model version)
- Supports tamper-evident audit records using a verifiable hash chain

### Policy Enforcement
- Query-time authorization (users only see permitted content)
- Metadata-based filtering (department, classification, project)
- Time-based constraints (embargo periods, retention policies)
- Redaction rules for sensitive content (where required)

## Architecture

```
User Identity → Role/Policy Mapping → Permission Check → Vector Filter Metadata
↓
Query Result → Citation Validation → Audit Record → Response
```

## Audit Record Shape (Example)

```json
{
  "query_id": "uuid",
  "timestamp": "2026-01-10T14:23:45Z",
  "user": "user@company.com",
  "user_roles": ["engineer", "safety_officer"],
  "query_text": "What is the confined space procedure?",
  "retrieval": [
    {"doc_id": "doc_123", "chunk_id": "chunk_5", "allowed": true, "reason": "role:safety_officer"},
    {"doc_id": "doc_789", "chunk_id": "chunk_2", "allowed": false, "reason": "requires_clearance:2"}
  ],
  "response_generated": true,
  "model_version": "local-llm",
  "citations": ["doc_123:chunk_5", "doc_456:chunk_12"]
}
```

### Tamper-Evident Boundary (Be Honest)

Tamper-evident means: if an audit row is modified, the verifier detects it.
It does not mean: a database superuser cannot delete the table. Production-grade anchoring (WORM storage, external attestations) is a separate step.

### Technology Stack

- PostgreSQL (permissions database, audit record storage)
- JWT (user authentication tokens)
- Keycloak (optional SSO integration)
- SOPS + age (secrets encryption)

### Development Status

🚧 Active Development

- Current milestone: tamper-evident audit records and verifier in the single-machine proof (KDAT-001A)
- Next: policy expansion and production hardening

## License

Keystone Deploy is licensed under the [Business Source License 1.1](LICENSE).

**Non-production use is free:**
- Development, testing, and evaluation environments only
- Up to 100 internal users

**Production use requires a commercial license.**

**Change Date:** 2030-01-01  
After this date, the license automatically converts to Apache License 2.0.

For commercial licensing: arnaldo@getkeystone.ai
