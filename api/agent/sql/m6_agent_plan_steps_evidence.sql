-- M6: add per-step evidence sensor columns to agent_plan_steps.
--
-- Stores the evidence_score (P2.1), hhem_score (P2.2), citation_count,
-- and evidence_passed flag for each executed plan step.
-- Required for HITL resume to reload prior evidence readings.
--
-- Idempotent: IF NOT EXISTS guards against re-running.

ALTER TABLE agent_plan_steps
    ADD COLUMN IF NOT EXISTS evidence_score   DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS hhem_score       DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS citation_count   INTEGER,
    ADD COLUMN IF NOT EXISTS evidence_passed  BOOLEAN;
