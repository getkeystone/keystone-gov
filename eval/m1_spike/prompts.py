"""
M1 reliability spike prompt pool for qwen2.5:7b-instruct.

The pool generates 50 plan-generation prompts spanning:
- 3 tools (lookup_procedure, queue_notification, draft_procedure_update)
- 4 roles (operator, supervisor, custodian, admin)
- 4 severity tiers (Critical, High, Medium, Low)
- 10 base scenarios per tool with parametric variation

The model is asked to emit a structured JSON plan object. Only parameter
shape is graded at this stage (per spike acceptance criteria).
"""

from itertools import product

BASE_SCENARIOS = {
    "lookup_procedure": [
        "Find the procedure for confined space entry on rig 14.",
        "What is the lockout-tagout procedure for the main compressor?",
        "Show me the spill response procedure for diesel.",
        "Pull the emergency shutdown procedure for the pump station.",
        "What are the hot work permit requirements?",
    ],
    "queue_notification": [
        "Notify the supervisor that the pressure relief valve is showing intermittent fault.",
        "Send a notification to maintenance about the gas detector failure.",
        "Queue an alert for the safety officer about the unsigned permit.",
        "Notify the on-call about the elevated H2S reading on sector 3.",
        "Send a notification to the day shift lead about the equipment lockout.",
    ],
    "draft_procedure_update": [
        "Draft an update to the confined space entry procedure to add the new ventilation requirement.",
        "Update the lockout-tagout procedure to include the new energy isolation device.",
        "Draft a revision to the spill response procedure to reference the new absorbent.",
        "Update the emergency shutdown sequence to add the new bypass valve.",
        "Draft an update to the hot work permit to include thermal imaging confirmation.",
    ],
}

ROLES = ["operator", "supervisor", "custodian", "admin"]
SEVERITY_TIERS = ["Critical", "High", "Medium", "Low"]


def build_prompts():
    """Yield 50 prompts as dicts: {prompt, tool, role, severity}."""
    out = []
    for tool, scenarios in BASE_SCENARIOS.items():
        for i, scenario in enumerate(scenarios):
            # Each base scenario gets 4 role variations (cycling through severity).
            for j in range(4):
                role = ROLES[(i + j) % len(ROLES)]
                severity = SEVERITY_TIERS[(i + j) % len(SEVERITY_TIERS)]
                prompt_text = (
                    f"[role={role} severity={severity}] {scenario} "
                    f"Respond with a JSON object: "
                    f'{{"tool": "...", "parameters": {{...}}}}. '
                    f"Use only one of the tools: lookup_procedure, queue_notification, draft_procedure_update."
                )
                out.append({
                    "prompt": prompt_text,
                    "expected_tool_candidates": [tool],
                    "role": role,
                    "severity": severity,
                })
                if len(out) >= 50:
                    break
            if len(out) >= 50:
                break
        if len(out) >= 50:
            break
    return out[:50]


REQUIRED_PARAMS = {
    "lookup_procedure": {"query"},
    "queue_notification": {"recipient", "message"},
    "draft_procedure_update": {"procedure_id", "proposed_change"},
}


def grade(response_obj: dict, expected_tool_candidates: list) -> dict:
    """Return {passed: bool, reasons: [str]}. Parameter shape only."""
    reasons = []
    if not isinstance(response_obj, dict):
        return {"passed": False, "reasons": ["response is not a JSON object"]}
    tool = response_obj.get("tool")
    if tool not in REQUIRED_PARAMS:
        reasons.append(f"tool '{tool}' not in registry")
    elif tool not in expected_tool_candidates:
        # Wrong-tool selections are graded as parameter-shape failures here.
        # Tool choice correctness is graded in T11/T12 properly.
        reasons.append(f"tool '{tool}' not in expected candidates {expected_tool_candidates}")
    params = response_obj.get("parameters")
    if not isinstance(params, dict):
        reasons.append("parameters is not a JSON object")
    elif tool in REQUIRED_PARAMS:
        missing = REQUIRED_PARAMS[tool] - set(params.keys())
        if missing:
            reasons.append(f"missing required parameters: {sorted(missing)}")
    return {"passed": len(reasons) == 0, "reasons": reasons}
