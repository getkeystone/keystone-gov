-- 23-compliance-runs.sql
-- COR Audit Readiness: stores results of compliance checklist runs.

CREATE TABLE IF NOT EXISTS compliance_runs (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  checklist_id   TEXT        NOT NULL,
  user_id        TEXT        NOT NULL,
  timestamp      TIMESTAMPTZ NOT NULL DEFAULT now(),
  overall_score  NUMERIC(5,2),
  passed         BOOLEAN,
  result         JSONB       NOT NULL
);

CREATE INDEX idx_compliance_runs_ts ON compliance_runs(timestamp DESC);

GRANT SELECT, INSERT ON compliance_runs TO keystone_app;
