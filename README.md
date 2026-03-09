# Keystone Gov

Authorization and audit subsystem for Keystone AI.

Runs fully on customer infrastructure. No external API calls. Air-gap compatible.

## Current scope

`keystone-gov` contains the governance behavior behind the current KDAT-001A proof.

Today it covers:
- Authentication for demo use
- Query-time ACL filtering
- Audit logging for every query
- Hash-chained audit verification
- Admin-only audit endpoints

## Proven today in KDAT-001A

- Admin-only content is filtered out before the LLM sees it
- Unauthorized users receive fail-closed or permitted-only results
- Every query writes an audit entry
- Audit integrity can be verified through an HMAC-SHA256 hash chain
- Policy enforcement happens outside the model

## Important boundary

Tamper-evident does **not** mean production-grade immutability.

Current proof:
- Detects row modification if the HMAC key remains confidential

Not yet proven:
- Append-only DB privileges
- External verifier
- WORM storage anchoring
- Key management via Vault/HSM

## Current authorization model

KDAT-001A uses a simple demo model:
- Static JWT-based auth
- Binary ACL pattern (`public` / `admin`)
- Query-time filtering after retrieval and before generation

## Planned next

- OIDC / enterprise identity integration
- Group and attribute-based authorization
- Harder audit guarantees
- Adversarial ACL test suite
- User activity views and export controls

## Development status

🚧 Active Development

Current milestone: KDAT-001A governance proof  
Next milestone: KDAT-001B validation and adversarial testing

## License

Keystone Gov is licensed under the [Business Source License 1.1](LICENSE).

**Non-production use is free:**
- Development, testing, and evaluation environments only
- Up to 100 internal users

**Production use requires a commercial license.**

**Change Date:** 2030-01-01  
After this date, the license automatically converts to Apache License 2.0.

For commercial licensing: arnaldo@getkeystone.ai
