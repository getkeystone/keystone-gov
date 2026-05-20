-- M5: add raw_steps column to agent_plans for HITL resume.
--
-- raw_steps stores the original step list so the plan execution loop
-- can resume after a HITL approval without re-prompting the LLM.
--
-- Idempotent: IF NOT EXISTS guards against re-running.

ALTER TABLE agent_plans
    ADD COLUMN IF NOT EXISTS raw_steps JSONB DEFAULT '[]'::jsonb;
