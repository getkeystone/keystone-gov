"""
M3 integration tests: plan execution loop.

All tests use `db_client` (real PostgreSQL session) because plan execution
writes to agent_plans, agent_plan_steps, agent_notifications, and
document_versions. Steps are submitted directly (bypassing LLM) so tests
are deterministic.

Test coverage:
  1. operator + lookup_procedure     → positive, results returned
  2. supervisor + queue_notification → positive, notification row created
  3. custodian + draft_procedure_update → positive, version row in 'draft'
  4. operator + queue_notification   → denied by role-tool matrix (P1.2)
  5. plan depth cap                  → 6 steps submitted, 5 run, terminated
  6. invalid tool name               → rejected before execution (T12.1)
  7. invalid parameters              → rejected before execution (T12.2)
"""
import pytest
from sqlalchemy import text


# ── helpers ──────────────────────────────────────────────────────────────────

def _post_plan(client, role, steps, user_id=None, query="test query"):
    body = {
        "query": query,
        "role": role,
        "steps": steps,
    }
    if user_id:
        body["user_id"] = user_id
    return client.post("/agent/plans", json=body)


def _lookup_step(idx=0):
    return {
        "step_index": idx,
        "tool_name": "lookup_procedure",
        "params": {"topic": "confined space entry", "facility_type": "petroleum"},
    }


# ── 1. Positive: operator + lookup_procedure ─────────────────────────────────

class TestLookupProcedure:
    def test_returns_201(self, db_client):
        client, _ = db_client
        resp = _post_plan(client, "operator", [_lookup_step()])
        assert resp.status_code == 201

    def test_plan_status_completed(self, db_client):
        client, _ = db_client
        resp = _post_plan(client, "operator", [_lookup_step()])
        body = resp.json()
        assert body["status"] == "completed", f"unexpected status: {body}"

    def test_step_result_returned(self, db_client):
        client, _ = db_client
        resp = _post_plan(client, "operator", [_lookup_step()])
        body = resp.json()
        assert len(body["step_results"]) == 1
        sr = body["step_results"][0]
        assert sr["tool_name"] == "lookup_procedure"
        assert sr["auth_decision"] == "allow"
        assert sr["result"] is not None

    def test_retrieval_returns_found_or_no_corpus(self, db_client):
        client, _ = db_client
        resp = _post_plan(client, "operator", [_lookup_step()])
        result = resp.json()["step_results"][0]["result"]
        # result must have 'found' key; True if corpus populated, False if empty.
        assert "found" in result

    def test_get_plan_endpoint(self, db_client):
        client, _ = db_client
        post_resp = _post_plan(client, "operator", [_lookup_step()])
        plan_id = post_resp.json()["plan_id"]
        get_resp = client.get(f"/agent/plans/{plan_id}")
        assert get_resp.status_code == 200
        detail = get_resp.json()
        assert detail["plan_id"] == plan_id
        assert detail["role"] == "operator"
        assert len(detail["steps"]) == 1


# ── 2. Positive: supervisor + queue_notification ─────────────────────────────

class TestQueueNotification:
    _MSG = "M3 test notification — safety drill tomorrow 09:00"

    def test_plan_completed(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "supervisor",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {
                    "severity": 3,
                    "message": self._MSG,
                    "recipients": ["operator"],
                },
            }],
            user_id="test-supervisor",
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "completed"

    def test_notification_row_created(self, db_client):
        client, db = db_client
        _post_plan(
            client, "supervisor",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {
                    "severity": 3,
                    "message": self._MSG,
                    "recipients": ["operator"],
                },
            }],
        )
        row = db.execute(
            text(
                "SELECT severity, recipients FROM agent_notifications"
                " WHERE message = :msg ORDER BY created_at DESC LIMIT 1"
            ),
            {"msg": self._MSG},
        ).fetchone()
        assert row is not None, "Notification row not found in DB"
        assert row[0] == 3
        assert "operator" in row[1]

    def test_result_has_notification_id(self, db_client):
        client, _ = db_client
        # severity=3 (Medium) → ALLOW for supervisor; severity=2 (High) would route to HITL
        resp = _post_plan(
            client, "supervisor",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": 3, "message": "Medium severity test", "recipients": ["custodian"]},
            }],
        )
        sr = resp.json()["step_results"][0]
        assert sr["result"]["status"] == "queued"
        assert "notification_id" in sr["result"]


# ── 3. draft_procedure_update is Critical tier → always routes to HITL ───────
# M5 wired Critical tier to HITL for ALL roles (spec §4.5, P5.3).
# Full approve-then-execute flow is covered in test_m5_hitl.py.

class TestDraftProcedureUpdate:
    def test_plan_hitl_pending(self, db_client):
        """Critical tier always pauses for HITL regardless of role."""
        client, db = db_client
        doc = db.execute(
            text("SELECT rel_path FROM corpus_documents LIMIT 1")
        ).fetchone()
        if not doc:
            pytest.skip("No corpus documents in DB — seed the corpus first")
        resp = _post_plan(
            client, "custodian",
            [{
                "step_index": 0,
                "tool_name": "draft_procedure_update",
                "params": {
                    "procedure_id": doc[0],
                    "proposed_text": "M3 test draft: updated confined space entry procedure.",
                    "citations": ["ohs-doc-001"],
                },
            }],
            user_id="test-custodian-m3",
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "hitl_pending"

    def test_hitl_response_fields(self, db_client):
        """HITL pause response carries hitl_step_index and approval_id."""
        client, db = db_client
        doc = db.execute(
            text("SELECT rel_path FROM corpus_documents LIMIT 1")
        ).fetchone()
        if not doc:
            pytest.skip("No corpus documents in DB — seed the corpus first")
        resp = _post_plan(
            client, "custodian",
            [{
                "step_index": 0,
                "tool_name": "draft_procedure_update",
                "params": {
                    "procedure_id": doc[0],
                    "proposed_text": "HITL fields test.",
                    "citations": [],
                },
            }],
            user_id="test-custodian-m3",
        )
        body = resp.json()
        assert body["hitl_step_index"] == 0
        assert body["approval_id"] is not None

    def test_no_version_row_before_approval(self, db_client):
        """No document_versions row is created until the HITL step is approved."""
        client, db = db_client
        doc = db.execute(
            text("SELECT rel_path FROM corpus_documents LIMIT 1")
        ).fetchone()
        if not doc:
            pytest.skip("No corpus documents in DB — seed the corpus first")
        unique_uid = "test-custodian-m3-no-exec"
        _post_plan(
            client, "custodian",
            [{
                "step_index": 0,
                "tool_name": "draft_procedure_update",
                "params": {
                    "procedure_id": doc[0],
                    "proposed_text": "Should not be saved yet.",
                    "citations": [],
                },
            }],
            user_id=unique_uid,
        )
        ver = db.execute(
            text(
                "SELECT status FROM document_versions"
                " WHERE created_by = :uid"
                " ORDER BY created_at DESC LIMIT 1"
            ),
            {"uid": unique_uid},
        ).fetchone()
        assert ver is None, "No version row should exist before HITL approval"


# ── 4. Negative: operator + queue_notification → denied ──────────────────────

class TestOperatorQueueNotificationDenied:
    def test_status_failed(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": 1, "message": "Emergency!", "recipients": ["supervisor"]},
            }],
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "failed"

    def test_terminated_reason_contains_denied(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": 1, "message": "Emergency!", "recipients": ["supervisor"]},
            }],
        )
        reason = resp.json().get("terminated_reason", "")
        assert "denied" in reason, f"expected 'denied' in reason, got: {reason!r}"

    def test_step_auth_decision_is_deny(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": 1, "message": "Emergency!", "recipients": ["supervisor"]},
            }],
        )
        sr = resp.json()["step_results"][0]
        assert sr["auth_decision"] == "deny"

    def test_no_notification_row_created(self, db_client):
        client, db = db_client
        unique_msg = "operator-denied-test-no-row-should-exist"
        _post_plan(
            client, "operator",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": 1, "message": unique_msg, "recipients": ["supervisor"]},
            }],
        )
        row = db.execute(
            text("SELECT COUNT(*) FROM agent_notifications WHERE message = :msg"),
            {"msg": unique_msg},
        ).fetchone()
        assert row[0] == 0, "Notification row should NOT exist for denied call"


# ── 5. Plan depth cap: 6 steps → 5 execute, status=terminated ────────────────

class TestPlanDepthCap:
    def test_six_steps_terminates(self, db_client):
        client, _ = db_client
        steps = [_lookup_step(i) for i in range(6)]
        resp = _post_plan(client, "operator", steps)
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "terminated"

    def test_terminated_reason_plan_depth_exceeded(self, db_client):
        client, _ = db_client
        steps = [_lookup_step(i) for i in range(6)]
        resp = _post_plan(client, "operator", steps)
        assert resp.json()["terminated_reason"] == "plan_depth_exceeded"

    def test_only_five_steps_executed(self, db_client):
        client, _ = db_client
        steps = [_lookup_step(i) for i in range(6)]
        resp = _post_plan(client, "operator", steps)
        assert len(resp.json()["step_results"]) == 5

    def test_five_steps_persisted_to_db(self, db_client):
        client, db = db_client
        steps = [_lookup_step(i) for i in range(6)]
        resp = _post_plan(client, "operator", steps)
        plan_id = resp.json()["plan_id"]
        count = db.execute(
            text("SELECT COUNT(*) FROM agent_plan_steps WHERE plan_id = :pid"),
            {"pid": plan_id},
        ).fetchone()[0]
        assert count == 5


# ── 6. Invalid tool name → rejected before execution (T12.1) ─────────────────

class TestInvalidToolName:
    def test_status_failed(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{"step_index": 0, "tool_name": "bing_search", "params": {}}],
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "failed"

    def test_terminated_reason_is_validation_failed(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{"step_index": 0, "tool_name": "bing_search", "params": {}}],
        )
        assert resp.json()["terminated_reason"] == "plan_validation_failed"

    def test_validation_errors_populated(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{"step_index": 0, "tool_name": "nonexistent_tool", "params": {}}],
        )
        errors = resp.json()["validation_errors"]
        assert any("not in registry" in e for e in errors), f"errors: {errors}"

    def test_no_steps_executed(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{"step_index": 0, "tool_name": "fake_tool", "params": {}}],
        )
        assert resp.json()["step_results"] == []


# ── 7. Invalid parameters → rejected before execution (T12.2) ────────────────

class TestInvalidParameters:
    def test_missing_required_field(self, db_client):
        client, _ = db_client
        # lookup_procedure requires 'topic' and 'facility_type'
        resp = _post_plan(
            client, "operator",
            [{"step_index": 0, "tool_name": "lookup_procedure", "params": {"topic": "confined space"}}],
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "failed"

    def test_wrong_type_integer_field(self, db_client):
        client, _ = db_client
        # queue_notification.severity must be integer, not string
        resp = _post_plan(
            client, "supervisor",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": "high", "message": "test", "recipients": []},
            }],
        )
        assert resp.json()["status"] == "failed"
        assert resp.json()["terminated_reason"] == "plan_validation_failed"

    def test_integer_out_of_bounds(self, db_client):
        client, _ = db_client
        # severity must be 1-4; 99 is out of range
        resp = _post_plan(
            client, "supervisor",
            [{
                "step_index": 0,
                "tool_name": "queue_notification",
                "params": {"severity": 99, "message": "test", "recipients": []},
            }],
        )
        assert resp.json()["status"] == "failed"
        errors = resp.json()["validation_errors"]
        assert any("maximum" in e for e in errors), f"errors: {errors}"

    def test_validation_errors_populated(self, db_client):
        client, _ = db_client
        resp = _post_plan(
            client, "operator",
            [{"step_index": 0, "tool_name": "lookup_procedure", "params": {}}],
        )
        errors = resp.json()["validation_errors"]
        assert len(errors) > 0
        assert any("required" in e for e in errors), f"errors: {errors}"
