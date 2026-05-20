"""
M5 integration tests: HITL routing and approval queue.

Coverage:
  1.  Critical tier (draft_procedure_update) always routes to HITL
  2.  High tier + supervisor routes to HITL (queue_notification severity=2)
  3.  High tier + custodian proceeds without HITL
  4.  Low tier (lookup_procedure) always proceeds without HITL
  5.  hitl_step_index and approval_id present in hitl_pending response
  6.  Approve resumes plan, step executes, result persisted
  7.  Reject terminates plan with terminated_reason
  8.  Self-approval returns 403
  9.  Insufficient role (operator/supervisor) cannot approve → 403
  10. Approval writes audit entry with policy_reference="P5.1"
  11. Plan state transitions: hitl_pending → completed after approval
  12. Already-decided task returns 409
  13. GET /agent/approvals lists pending tasks
  14. GET /agent/approvals/{id} returns full context
"""
import pytest
from sqlalchemy import text


# ── helpers ───────────────────────────────────────────────────────────────────

def _post_plan(client, role, steps, user_id="test-hitl-user"):
    return client.post(
        "/agent/plans",
        json={"query": "m5 test", "role": role, "steps": steps, "user_id": user_id},
    )


def _draft_step(procedure_id, idx=0):
    return {
        "step_index": idx,
        "tool_name": "draft_procedure_update",
        "params": {
            "procedure_id": procedure_id,
            "proposed_text": f"M5 test draft at step {idx}.",
            "citations": ["ohs-doc-001"],
        },
    }


def _notify_step(severity, idx=0):
    return {
        "step_index": idx,
        "tool_name": "queue_notification",
        "params": {
            "severity": severity,
            "message": f"M5 test notification severity={severity} step={idx}",
            "recipients": ["operator"],
        },
    }


def _lookup_step(idx=0):
    return {
        "step_index": idx,
        "tool_name": "lookup_procedure",
        "params": {"topic": "confined space entry", "facility_type": "petroleum"},
    }


def _first_doc(db):
    row = db.execute(text("SELECT rel_path FROM corpus_documents LIMIT 1")).fetchone()
    return row[0] if row else None


def _approve(client, approval_id, approver_user_id="test-approver", approver_role="custodian", rationale="M5 test approval"):
    return client.post(
        f"/agent/approvals/{approval_id}/approve",
        json={"approver_user_id": approver_user_id, "approver_role": approver_role, "rationale": rationale},
    )


def _reject(client, approval_id, approver_user_id="test-approver", approver_role="custodian"):
    return client.post(
        f"/agent/approvals/{approval_id}/reject",
        json={"approver_user_id": approver_user_id, "approver_role": approver_role},
    )


# ── 1. Critical tier always routes to HITL ────────────────────────────────────

class TestCriticalTierAlwaysHITL:
    def test_custodian_draft_routes_to_hitl(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)])
        assert resp.status_code == 201
        assert resp.json()["status"] == "hitl_pending"

    def test_admin_draft_routes_to_hitl(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "admin", [_draft_step(doc)])
        assert resp.json()["status"] == "hitl_pending"

    def test_approval_task_row_created(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-approval-row-check")
        approval_id = resp.json()["approval_id"]
        row = db.execute(
            text("SELECT status, tool_name FROM agent_approval_tasks WHERE approval_id = :aid"),
            {"aid": approval_id},
        ).fetchone()
        assert row is not None, "ApprovalTask row not found"
        assert row[0] == "pending"
        assert row[1] == "draft_procedure_update"


# ── 2–3. High tier HITL depends on role ───────────────────────────────────────

class TestHighTierRouting:
    def test_supervisor_high_routes_to_hitl(self, db_client):
        """severity=2 (High) + supervisor → HITL."""
        client, _ = db_client
        resp = _post_plan(client, "supervisor", [_notify_step(severity=2)])
        assert resp.status_code == 201
        assert resp.json()["status"] == "hitl_pending"

    def test_custodian_high_proceeds(self, db_client):
        """severity=2 (High) + custodian → ALLOW (no HITL)."""
        client, _ = db_client
        resp = _post_plan(client, "custodian", [_notify_step(severity=2)])
        assert resp.json()["status"] == "completed"

    def test_admin_high_proceeds(self, db_client):
        """severity=2 (High) + admin → ALLOW (no HITL)."""
        client, _ = db_client
        resp = _post_plan(client, "admin", [_notify_step(severity=2)])
        assert resp.json()["status"] == "completed"


# ── 4. Low tier never routes to HITL ─────────────────────────────────────────

class TestLowTierNoHITL:
    def test_operator_lookup_completed(self, db_client):
        client, _ = db_client
        resp = _post_plan(client, "operator", [_lookup_step()])
        assert resp.json()["status"] == "completed"

    def test_medium_tier_completed(self, db_client):
        """severity=3 (Medium) + supervisor → ALLOW."""
        client, _ = db_client
        resp = _post_plan(client, "supervisor", [_notify_step(severity=3)])
        assert resp.json()["status"] == "completed"


# ── 5. HITL response fields ───────────────────────────────────────────────────

class TestHITLResponseFields:
    def test_hitl_step_index_and_approval_id(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)])
        body = resp.json()
        assert body["hitl_step_index"] == 0
        assert body["approval_id"] is not None
        assert body["step_results"] == []

    def test_high_tier_hitl_fields(self, db_client):
        client, _ = db_client
        resp = _post_plan(client, "supervisor", [_notify_step(severity=2)])
        body = resp.json()
        assert body["hitl_step_index"] == 0
        assert body["approval_id"] is not None


# ── 6. Approve resumes and executes ──────────────────────────────────────────

class TestApproveResumesExecution:
    def test_approve_returns_completed(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-submit-approve")
        approval_id = resp.json()["approval_id"]

        appr = _approve(client, approval_id, approver_user_id="test-approver-cu")
        assert appr.status_code == 200
        assert appr.json()["status"] == "completed"

    def test_approve_step_result_present(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-submit-result")
        approval_id = resp.json()["approval_id"]

        appr = _approve(client, approval_id, approver_user_id="test-approver-result")
        body = appr.json()
        assert len(body["step_results"]) == 1
        sr = body["step_results"][0]
        assert sr["tool_name"] == "draft_procedure_update"
        assert sr["auth_decision"] == "allow"
        assert sr["result"] is not None

    def test_approve_version_row_created(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        uid = "test-custodian-after-approve"
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id=uid)
        approval_id = resp.json()["approval_id"]

        _approve(client, approval_id, approver_user_id="test-approver-ver")
        db.expire_all()  # refresh session to see committed rows

        ver = db.execute(
            text(
                "SELECT status FROM document_versions"
                " WHERE created_by = :uid ORDER BY created_at DESC LIMIT 1"
            ),
            {"uid": uid},
        ).fetchone()
        assert ver is not None, "DocumentVersion row not created after approval"
        assert ver[0] == "draft"


# ── 7. Reject terminates plan ─────────────────────────────────────────────────

class TestRejectTerminatesPlan:
    def test_reject_returns_terminated(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-reject-submit")
        approval_id = resp.json()["approval_id"]

        rej = _reject(client, approval_id, approver_user_id="test-rejecter")
        assert rej.status_code == 200
        assert rej.json()["status"] == "terminated"

    def test_reject_terminated_reason(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-reject-reason")
        approval_id = resp.json()["approval_id"]

        rej = _reject(client, approval_id, approver_user_id="test-rejecter-2")
        reason = rej.json().get("terminated_reason", "")
        assert "rejected" in reason or "test-rejecter-2" in reason

    def test_reject_no_version_row(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        uid = "test-reject-no-version"
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id=uid)
        approval_id = resp.json()["approval_id"]

        _reject(client, approval_id, approver_user_id="test-rejecter-3")

        ver = db.execute(
            text(
                "SELECT status FROM document_versions"
                " WHERE created_by = :uid ORDER BY created_at DESC LIMIT 1"
            ),
            {"uid": uid},
        ).fetchone()
        assert ver is None, "No version row should exist after rejection"


# ── 8. Self-approval blocked ──────────────────────────────────────────────────

class TestSelfApprovalBlocked:
    def test_self_approve_returns_403(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        uid = "test-self-approver"
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id=uid)
        approval_id = resp.json()["approval_id"]

        # Approver user_id matches the user who submitted the plan
        appr = _approve(client, approval_id, approver_user_id=uid, approver_role="custodian")
        assert appr.status_code == 403
        assert "self" in appr.json()["detail"].lower()

    def test_self_reject_returns_403(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        uid = "test-self-rejecter"
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id=uid)
        approval_id = resp.json()["approval_id"]

        rej = _reject(client, approval_id, approver_user_id=uid, approver_role="custodian")
        assert rej.status_code == 403


# ── 9. Insufficient role cannot approve ──────────────────────────────────────

class TestInsufficientRoleCannotApprove:
    def test_operator_cannot_approve(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-insufficient-submit")
        approval_id = resp.json()["approval_id"]

        appr = client.post(
            f"/agent/approvals/{approval_id}/approve",
            json={"approver_user_id": "some-operator", "approver_role": "operator"},
        )
        assert appr.status_code == 403

    def test_supervisor_cannot_approve(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-supervisor-cannot-approve")
        approval_id = resp.json()["approval_id"]

        appr = client.post(
            f"/agent/approvals/{approval_id}/approve",
            json={"approver_user_id": "some-supervisor", "approver_role": "supervisor"},
        )
        assert appr.status_code == 403


# ── 10. Approval writes P5.1 audit entry ─────────────────────────────────────

class TestApprovalAuditEntry:
    def test_approve_writes_p5_1_entry(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-p51-audit")
        plan_id = resp.json()["plan_id"]
        approval_id = resp.json()["approval_id"]

        _approve(client, approval_id, approver_user_id="test-p51-approver")

        row = db.execute(
            text(
                "SELECT policy_reference, auth_decision, role"
                " FROM agent_action_audit"
                " WHERE plan_id = :pid AND policy_reference = 'P5.1'"
                " ORDER BY timestamp DESC LIMIT 1"
            ),
            {"pid": plan_id},
        ).fetchone()
        assert row is not None, "P5.1 audit entry not found"
        assert row[0] == "P5.1"
        assert row[1] == "allow"
        assert row[2] == "custodian"

    def test_reject_writes_p5_1_deny_entry(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-p51-reject")
        plan_id = resp.json()["plan_id"]
        approval_id = resp.json()["approval_id"]

        _reject(client, approval_id, approver_user_id="test-p51-rejecter")

        row = db.execute(
            text(
                "SELECT policy_reference, auth_decision"
                " FROM agent_action_audit"
                " WHERE plan_id = :pid AND policy_reference = 'P5.1'"
                " ORDER BY timestamp DESC LIMIT 1"
            ),
            {"pid": plan_id},
        ).fetchone()
        assert row is not None, "P5.1 deny audit entry not found"
        assert row[1] == "deny"


# ── 11. Plan state transitions ────────────────────────────────────────────────

class TestPlanStateTransitions:
    def test_hitl_then_completed(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-state-transition")
        plan_id = resp.json()["plan_id"]
        approval_id = resp.json()["approval_id"]
        assert resp.json()["status"] == "hitl_pending"

        appr = _approve(client, approval_id, approver_user_id="test-state-approver")
        assert appr.json()["status"] == "completed"

        # Verify via GET /agent/plans/{plan_id}
        detail = client.get(f"/agent/plans/{plan_id}").json()
        assert detail["status"] == "completed"

    def test_hitl_then_terminated(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-state-reject")
        plan_id = resp.json()["plan_id"]
        approval_id = resp.json()["approval_id"]

        _reject(client, approval_id, approver_user_id="test-state-rejecter")

        detail = client.get(f"/agent/plans/{plan_id}").json()
        assert detail["status"] == "terminated"


# ── 12. Already-decided task returns 409 ─────────────────────────────────────

class TestAlreadyDecidedConflict:
    def test_double_approve_returns_409(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-409-submit")
        approval_id = resp.json()["approval_id"]

        _approve(client, approval_id, approver_user_id="test-409-approver-1")
        second = _approve(client, approval_id, approver_user_id="test-409-approver-2")
        assert second.status_code == 409

    def test_approve_after_reject_returns_409(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-409-reject-first")
        approval_id = resp.json()["approval_id"]

        _reject(client, approval_id, approver_user_id="test-409-rejecter")
        second = _approve(client, approval_id, approver_user_id="test-409-approver")
        assert second.status_code == 409


# ── 13. GET /agent/approvals lists pending tasks ──────────────────────────────

class TestListApprovals:
    def test_list_approvals_contains_pending(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-list-approvals")
        approval_id = resp.json()["approval_id"]

        listing = client.get("/agent/approvals?status=pending").json()
        ids = [t["approval_id"] for t in listing]
        assert approval_id in ids

    def test_decided_not_in_pending_list(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-decided-not-pending")
        approval_id = resp.json()["approval_id"]

        _approve(client, approval_id, approver_user_id="test-decided-approver")

        listing = client.get("/agent/approvals?status=pending").json()
        ids = [t["approval_id"] for t in listing]
        assert approval_id not in ids


# ── 14. GET /agent/approvals/{id} returns full context ───────────────────────

class TestGetApproval:
    def test_get_pending_task(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-get-approval")
        approval_id = resp.json()["approval_id"]

        task = client.get(f"/agent/approvals/{approval_id}").json()
        assert task["approval_id"] == approval_id
        assert task["tool_name"] == "draft_procedure_update"
        assert task["severity_tier"] == "Critical"
        assert task["status"] == "pending"
        assert task["requested_by"] == "test-get-approval"

    def test_get_decided_task(self, db_client):
        client, db = db_client
        doc = _first_doc(db)
        if not doc:
            pytest.skip("No corpus documents in DB")
        resp = _post_plan(client, "custodian", [_draft_step(doc)], user_id="test-get-decided")
        approval_id = resp.json()["approval_id"]

        _approve(client, approval_id, approver_user_id="test-decided-getter")

        task = client.get(f"/agent/approvals/{approval_id}").json()
        assert task["status"] == "decided"
        assert task["decision"] == "approve"
        assert task["decided_by"] == "test-decided-getter"

    def test_get_unknown_id_returns_404(self, db_client):
        client, _ = db_client
        import uuid
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/agent/approvals/{fake_id}")
        assert resp.status_code == 404
