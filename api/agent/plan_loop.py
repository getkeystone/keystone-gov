"""
Plan generation, validation, and execution loop for KDAT-002.

Architecture: generate-then-execute per spec Section 4.6. The LLM proposes
a complete plan; the controller validates authorization for ALL steps before
any tool runs. Sequential execution with plan_depth_cap enforcement (§4.8).

Public API:
  generate_plan(query, role, registry) -> list[dict] | None
  execute_plan(plan_id, role, raw_steps, db, ...) -> dict
"""
import json
import logging
import uuid
from datetime import datetime

from sqlalchemy.orm import Session as DBSession

from .controller import authorize
from .evidence import check_evidence
from .hitl import create_approval_task
from .models import AgentPlan, AgentPlanStep
from .registry import tools as _registry_tools, permitted_tools_for

log = logging.getLogger("keystone.agent.plan_loop")

PLAN_DEPTH_CAP = 5

_PLAN_SYSTEM_PROMPT = """\
You are the Keystone governed agent planner. Your ONLY output is a JSON plan.

Available tools:
{tools_json}

Rules:
1. Produce at most {depth_cap} steps (step_index 0 through {max_idx}).
2. Each step calls exactly one tool from the list above.
3. Parameters must satisfy the tool JSON Schema (correct types, all required fields present).
4. Do NOT add extra keys. Do NOT explain or narrate.

Respond ONLY with this JSON:
{{"steps": [{{"step_index": 0, "tool_name": "...", "params": {{...}}}}, ...]}}
"""


# ---------------------------------------------------------------------------
# Plan generation (LLM path)
# ---------------------------------------------------------------------------

def _tools_prompt_json(registry: dict) -> str:
    return json.dumps(
        [
            {
                "name": name,
                "description": t.get("description", ""),
                "parameters_schema": t.get("parameters_schema", {}),
            }
            for name, t in registry.items()
        ],
        indent=2,
    )


def generate_plan(query: str, role: str, registry: dict) -> list[dict] | None:
    """
    Ask the LLM to produce a structured plan for the query.

    Only tools the role is permitted to call are exposed in the prompt —
    this is the first layer of role-based access control. The controller
    authorization check (phase 2 of execute_plan) is the enforcing layer.

    Returns a list of step dicts, or None if the LLM call fails.
    """
    try:
        import ollama_client
    except ImportError:
        log.error("generate_plan: ollama_client not importable")
        return None

    permitted = {t["name"]: t for t in permitted_tools_for(role)}
    if not permitted:
        log.warning("generate_plan: role '%s' has no permitted tools", role)
        return []

    system = _PLAN_SYSTEM_PROMPT.format(
        tools_json=_tools_prompt_json(permitted),
        depth_cap=PLAN_DEPTH_CAP,
        max_idx=PLAN_DEPTH_CAP - 1,
    )
    raw = ollama_client.generate_json(system, query)
    if raw is None:
        log.warning("generate_plan: LLM returned no valid JSON for query: %r", query[:80])
        return None

    steps = raw.get("steps")
    if not isinstance(steps, list):
        log.warning("generate_plan: LLM JSON missing 'steps' list: %s", raw)
        return None

    return steps


# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------

def _validate_params(schema: dict, params: dict) -> list[str]:
    """Minimal JSON Schema validation for tool call parameters."""
    errors: list[str] = []
    props = schema.get("properties", {})
    required = schema.get("required", [])

    for field in required:
        if field not in params:
            errors.append(f"missing required field '{field}'")

    for field, val in params.items():
        if field not in props:
            continue
        expected = props[field].get("type")
        if expected == "string" and not isinstance(val, str):
            errors.append(f"'{field}': expected string, got {type(val).__name__}")
        elif expected == "integer" and not isinstance(val, int):
            errors.append(f"'{field}': expected integer, got {type(val).__name__}")
        elif expected == "array" and not isinstance(val, list):
            errors.append(f"'{field}': expected array, got {type(val).__name__}")
        if expected == "integer" and isinstance(val, int):
            mn = props[field].get("minimum")
            mx = props[field].get("maximum")
            if mn is not None and val < mn:
                errors.append(f"'{field}': {val} < minimum {mn}")
            if mx is not None and val > mx:
                errors.append(f"'{field}': {val} > maximum {mx}")

    return errors


def _validate_step(step: dict, registry: dict) -> list[str]:
    """Return validation error strings for a single plan step."""
    errors: list[str] = []
    tool_name = step.get("tool_name")
    if not tool_name:
        errors.append("step missing 'tool_name'")
        return errors
    if tool_name not in registry:
        errors.append(f"tool '{tool_name}' not in registry (T12.1: invalid_tool)")
        return errors
    params = step.get("params", {})
    schema = registry[tool_name].get("parameters_schema", {})
    errors.extend(_validate_params(schema, params))
    return errors


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _execute_tool(
    tool_name: str,
    params: dict,
    plan_id: str,
    step_index: int,
    user_id: str,
    db: DBSession,
) -> tuple[dict | None, str | None]:
    """Dispatch a tool call. Returns (result, error_str)."""
    from .tools import lookup_procedure, queue_notification, draft_procedure_update

    try:
        if tool_name == "lookup_procedure":
            result = lookup_procedure(
                topic=params["topic"],
                facility_type=params["facility_type"],
                db=db,
            )
        elif tool_name == "queue_notification":
            result = queue_notification(
                severity=params["severity"],
                message=params["message"],
                recipients=params["recipients"],
                plan_id=plan_id,
                step_index=step_index,
                db=db,
            )
        elif tool_name == "draft_procedure_update":
            result = draft_procedure_update(
                procedure_id=params["procedure_id"],
                proposed_text=params["proposed_text"],
                citations=params["citations"],
                plan_id=plan_id,
                step_index=step_index,
                user_id=user_id,
                db=db,
            )
        else:
            return None, f"unknown tool: {tool_name!r}"
    except Exception as exc:
        log.exception("Tool %s raised during execution", tool_name)
        return None, f"tool execution error: {exc}"

    return result, None


# ---------------------------------------------------------------------------
# Plan execution loop
# ---------------------------------------------------------------------------

def _update_plan_status(
    plan_id: str, status: str, reason: str | None, db: DBSession
) -> None:
    db.query(AgentPlan).filter(
        AgentPlan.plan_id == uuid.UUID(plan_id)
    ).update(
        {"status": status, "terminated_reason": reason, "updated_at": datetime.utcnow()},
        synchronize_session=False,
    )


def execute_plan(
    plan_id: str,
    role: str,
    raw_steps: list[dict],
    db: DBSession,
    user_id: str = "agent",
    plan_depth_cap: int = PLAN_DEPTH_CAP,
    resume_from_step: int = 0,
) -> dict:
    """
    Execute a plan per spec §4.6 generate-then-execute with §4.8 HITL pause.

    Phase 1 — schema validation of ALL steps (skipped when resuming after HITL).
    Phase 2+3 — sequential: authorize each step, then execute immediately.
      - ALLOW   → execute; continue
      - HITL    → pause; create ApprovalTask; return hitl_pending
      - DENY    → fail plan; return failed

    resume_from_step > 0: skip all steps with step_index < resume_from_step,
    loading their already-persisted results from agent_plan_steps instead of
    re-executing. Used after an approval decision is recorded.

    plan_depth_cap is enforced by truncating raw_steps; if the input exceeds
    the cap the plan terminates with reason='plan_depth_exceeded' after the
    allowed steps complete (T12.7).

    Returns:
        {
          "status": str,
          "terminated_reason": str | None,
          "step_results": list[dict],
          "validation_errors": list[str],
          "hitl_step_index": int | None,
          "approval_id": str | None,
        }
    """
    registry = _registry_tools()
    depth_exceeded = len(raw_steps) > plan_depth_cap
    steps = raw_steps[:plan_depth_cap]

    # ── Phase 1: Schema validation (first-run only) ───────────────────────────
    if resume_from_step == 0:
        for step in steps:
            errors = _validate_step(step, registry)
            if errors:
                _update_plan_status(plan_id, "failed", "plan_validation_failed", db)
                db.commit()
                return {
                    "status": "failed",
                    "terminated_reason": "plan_validation_failed",
                    "step_results": [],
                    "validation_errors": errors,
                    "hitl_step_index": None,
                    "approval_id": None,
                    "citation_coverage": 0,
                    "evidence_pass_rate": None,
                }

    # ── Phase 2+3: Sequential authorize-then-execute ──────────────────────────
    step_results: list[dict] = []

    for idx, step in enumerate(steps):
        tool_name = step["tool_name"]
        params = step.get("params", {})
        step_index = step.get("step_index", idx)

        # ── Resume shortcut: load already-persisted result ───────────────────
        if step_index < resume_from_step:
            record = (
                db.query(AgentPlanStep)
                .filter(
                    AgentPlanStep.plan_id == uuid.UUID(plan_id),
                    AgentPlanStep.step_index == step_index,
                )
                .first()
            )
            if record:
                step_results.append({
                    "step_index": step_index,
                    "tool_name": record.tool_name,
                    "auth_decision": record.auth_decision,
                    "severity_tier": record.severity_tier or "Unknown",
                    "result": record.result,
                    "error": record.error,
                    "evidence_score": record.evidence_score,
                    "hhem_score": record.hhem_score,
                    "citation_count": record.citation_count or 0,
                    "evidence_passed": record.evidence_passed,
                })
            continue

        # ── Authorize ────────────────────────────────────────────────────────
        auth = authorize(
            role, tool_name, params,
            plan_id=plan_id, step_index=step_index, db=db,
        )

        # ── HITL: pause plan ─────────────────────────────────────────────────
        if auth.get("routed_to_hitl"):
            task = create_approval_task(
                plan_id=plan_id,
                step_index=step_index,
                tool_name=tool_name,
                proposed_params=params,
                severity_tier=auth["severity_tier"],
                user_id=user_id,
                db=db,
            )
            _update_plan_status(plan_id, "hitl_pending", None, db)
            db.commit()
            return {
                "status": "hitl_pending",
                "terminated_reason": None,
                "step_results": step_results,
                "validation_errors": [],
                "hitl_step_index": step_index,
                "approval_id": str(task.approval_id),
                "citation_coverage": sum(s.get("citation_count") or 0 for s in step_results),
                "evidence_pass_rate": None,
            }

        # ── Deny ─────────────────────────────────────────────────────────────
        if not auth["allowed"]:
            policy_ref = auth.get("policy_reference", "P1.2")
            _update_plan_status(plan_id, "failed", f"{policy_ref}_denied", db)
            db.commit()
            return {
                "status": "failed",
                "terminated_reason": (
                    f"step_{step_index}_{policy_ref}_denied: {auth['rationale']}"
                ),
                "step_results": [
                    {
                        "step_index": step_index,
                        "tool_name": tool_name,
                        "auth_decision": "deny",
                        "severity_tier": auth["severity_tier"],
                        "result": None,
                        "error": auth["rationale"],
                        "evidence_score": None,
                        "hhem_score": None,
                        "citation_count": 0,
                        "evidence_passed": None,
                    }
                ],
                "validation_errors": [],
                "hitl_step_index": None,
                "approval_id": None,
                "citation_coverage": 0,
                "evidence_pass_rate": None,
            }

        # ── Execute ───────────────────────────────────────────────────────────
        step_record = AgentPlanStep(
            plan_id=uuid.UUID(plan_id),
            step_index=step_index,
            tool_name=tool_name,
            proposed_params=params,
            executed_params=params,
            auth_decision="allow",
            severity_tier=auth["severity_tier"],
        )
        db.add(step_record)
        db.flush()

        result, error = _execute_tool(tool_name, params, plan_id, step_index, user_id, db)
        step_record.result = result
        step_record.error = error
        step_record.executed_at = datetime.utcnow()
        db.flush()

        # ── Evidence gating (M6 P2.1/P2.2) ───────────────────────────────────
        evidence_score: float | None = None
        hhem_score: float | None = None
        citation_count: int = 0
        evidence_passed: bool | None = None

        if result is not None and error is None:
            ev = check_evidence(
                tool_name=tool_name,
                params=params,
                result=result,
                plan_id=plan_id,
                step_index=step_index,
                role=role,
                severity_tier=auth["severity_tier"],
                db=db,
            )
            evidence_score = ev["evidence_score"]
            hhem_score = ev["hhem_score"]
            citation_count = ev["citation_count"]
            # Only set a boolean for evidence-bound tools; evidence-free tools stay None
            evidence_passed = ev["passed"] if ev["policy_reference"] != "none" else None

            step_record.evidence_score = evidence_score
            step_record.hhem_score = hhem_score
            step_record.citation_count = citation_count
            step_record.evidence_passed = evidence_passed
            db.flush()

            if not ev["passed"]:
                policy_ref = ev["policy_reference"]
                step_results.append({
                    "step_index": step_index,
                    "tool_name": tool_name,
                    "auth_decision": "allow",
                    "severity_tier": auth["severity_tier"],
                    "result": result,
                    "error": f"evidence check failed: {ev['rationale']}",
                    "evidence_score": evidence_score,
                    "hhem_score": hhem_score,
                    "citation_count": citation_count,
                    "evidence_passed": False,
                })
                _update_plan_status(
                    plan_id, "failed",
                    f"step_{step_index}_{policy_ref}_evidence_fail",
                    db,
                )
                db.commit()
                return {
                    "status": "failed",
                    "terminated_reason": (
                        f"step_{step_index}_{policy_ref}: {ev['rationale']}"
                    ),
                    "step_results": step_results,
                    "validation_errors": [],
                    "hitl_step_index": None,
                    "approval_id": None,
                    "citation_coverage": sum(
                        s.get("citation_count") or 0 for s in step_results
                    ),
                    "evidence_pass_rate": None,
                }

        step_results.append({
            "step_index": step_index,
            "tool_name": tool_name,
            "auth_decision": "allow",
            "severity_tier": auth["severity_tier"],
            "result": result,
            "error": error,
            "evidence_score": evidence_score,
            "hhem_score": hhem_score,
            "citation_count": citation_count,
            "evidence_passed": evidence_passed,
        })

    # ── Finalize plan ─────────────────────────────────────────────────────────
    if depth_exceeded:
        final_status = "terminated"
        terminated_reason = "plan_depth_exceeded"
    else:
        final_status = "completed"
        terminated_reason = None

    _update_plan_status(plan_id, final_status, terminated_reason, db)
    db.commit()

    citation_coverage = sum(s.get("citation_count") or 0 for s in step_results)
    bound_steps = [s for s in step_results if s.get("evidence_passed") is not None]
    evidence_pass_rate = (
        sum(1 for s in bound_steps if s.get("evidence_passed") is True) / len(bound_steps)
        if bound_steps else None
    )

    return {
        "status": final_status,
        "terminated_reason": terminated_reason,
        "step_results": step_results,
        "validation_errors": [],
        "hitl_step_index": None,
        "approval_id": None,
        "citation_coverage": citation_coverage,
        "evidence_pass_rate": evidence_pass_rate,
    }
