-- INSERT-only enforcement for agent_action_audit.
--
-- keystone_app is the runtime API role. Revoking UPDATE, DELETE, and TRUNCATE
-- ensures that audit records cannot be modified or erased through the
-- application connection, even by a compromised application process.
--
-- Mirrors 22-permission-hardening.sql (audit_log) in keystone-dev/initdb.
--
-- Idempotent: REVOKE is a no-op if the privilege was never granted.
-- GRANT is a no-op if the privilege is already held.
-- Run as DB owner (keystone) — not as keystone_app.

-- Ensure keystone_app role exists (no-op if already present).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keystone_app') THEN
        CREATE ROLE keystone_app WITH LOGIN PASSWORD 'keystone_app_pw';
    END IF;
END
$$;

-- Remove mutation privileges — audit rows must be immutable at the role level.
REVOKE UPDATE, DELETE, TRUNCATE ON agent_action_audit FROM keystone_app;

-- Ensure the runtime role has exactly what it needs: read + append.
GRANT SELECT, INSERT ON agent_action_audit TO keystone_app;

-- Proof command (run as keystone_app after applying this migration):
--
--   psql -U keystone_app -d keystone_dev \
--     -c "UPDATE agent_action_audit SET entry_hash='x' WHERE 1=0;"
--   => ERROR:  permission denied for table agent_action_audit
