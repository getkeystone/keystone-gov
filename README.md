# Keystone Gov

Access control and audit logging subsystem for Keystone AI.

## What This Does

**Access Control:**
- Maps user identities to organizational roles
- Enforces permission policies at query time
- Inherits ACLs from source systems (SharePoint, file shares)
- Supports RBAC, ABAC, and custom policy models

**Audit Logging:**
- Logs every query (user, timestamp, query text)
- Logs every retrieval (documents accessed, permission checks performed)
- Logs every response (answer generated, citations provided, model version)
- Provides tamper-evident audit trail with cryptographic integrity

**Policy Enforcement:**
- Query-time authorization (users only see permitted content)
- Metadata-based filtering (department, classification, project)
- Time-based access controls (embargo periods, retention policies)
- Redaction rules for sensitive content

## Architecture
```
User Identity → Role Mapping → Permission Check → Vector Filter Metadata
                                                        ↓
Query Result → Citation Validation → Audit Log → Response
```

## Audit Log Schema
```json
{
  "query_id": "uuid",
  "timestamp": "2026-01-10T14:23:45Z",
  "user": "arnaldo@company.com",
  "user_roles": ["engineer", "safety_officer"],
  "query_text": "What's the confined space procedure?",
  "sources_accessed": ["doc_123", "doc_456"],
  "permission_checks": [
    {"doc_id": "doc_123", "allowed": true, "reason": "user_has_role_safety_officer"},
    {"doc_id": "doc_789", "allowed": false, "reason": "requires_clearance_level_2"}
  ],
  "response_generated": true,
  "model_version": "qwen2.5-32b-instruct",
  "citations": ["doc_123:chunk_5", "doc_456:chunk_12"]
}
```

## Technology Stack

- **PostgreSQL** (permissions database, audit log storage)
- **JWT** (user authentication tokens)
- **Keycloak** (optional SSO integration)
- **SOPS + age** (secrets encryption)

## Development Status

🚧 **Active Development**
- MVP demo: February 2026
- Production-ready: Q2 2026

## License

Keystone Gov is licensed under the [Business Source License 1.1](LICENSE).

**Non-production use is free:**
- Development, testing, and evaluation environments only
- Up to 100 internal users

**Production use requires a commercial license.**

**Change Date:** 2030-01-01  
After this date, the license automatically converts to Apache License 2.0.

For commercial licensing: arnaldo@getkeystone.ai
