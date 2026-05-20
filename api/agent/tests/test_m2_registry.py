"""
M2 tests: tool registry, role-tool matrix, and registry endpoints.

Covers:
  - Registry loads exactly 3 tools
  - Each tool has required parameter schema with correct shape
  - role_can_call() is correct for all role × tool combinations
  - severity_tier_for() returns correct base tiers
  - effective_severity_tier() resolves queue_notification param-dependent tiers
  - GET /agent/tools → 200 with 3 tools
  - GET /agent/registry/role/operator → only lookup_procedure
  - GET /agent/registry/role/<unknown> → 404
"""

import pytest

# ── Registry unit tests ───────────────────────────────────────────────────────

EXPECTED_TOOLS = {"lookup_procedure", "queue_notification", "draft_procedure_update"}

ROLE_TOOL_MATRIX = {
    "operator":   {"lookup_procedure"},
    "supervisor": {"lookup_procedure", "queue_notification"},
    "custodian":  {"lookup_procedure", "queue_notification", "draft_procedure_update"},
    "admin":      {"lookup_procedure", "queue_notification", "draft_procedure_update"},
}

EXPECTED_BASE_TIERS = {
    "lookup_procedure":      "Low",
    "queue_notification":    "High",
    "draft_procedure_update": "Critical",
}

# queue_notification severity param → expected tier per spec Section 4.3
QUEUE_TIER_MAP = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}


class TestRegistryLoad:
    def test_loads_three_tools(self):
        from agent import registry
        assert set(registry.tools().keys()) == EXPECTED_TOOLS

    def test_each_tool_has_name(self):
        from agent import registry
        for name, t in registry.tools().items():
            assert t["name"] == name

    def test_each_tool_has_description(self):
        from agent import registry
        for t in registry.tools().values():
            assert isinstance(t.get("description"), str)
            assert len(t["description"]) > 0

    def test_each_tool_has_severity_tier(self):
        from agent import registry
        valid_tiers = {"Critical", "High", "Medium", "Low"}
        for t in registry.tools().values():
            assert t.get("severity_tier") in valid_tiers, \
                f"{t['name']} has invalid severity_tier: {t.get('severity_tier')}"

    def test_each_tool_has_parameters_schema(self):
        from agent import registry
        for t in registry.tools().values():
            schema = t.get("parameters_schema")
            assert isinstance(schema, dict), f"{t['name']} missing parameters_schema"
            assert schema.get("type") == "object"
            assert isinstance(schema.get("properties"), dict)
            assert len(schema["properties"]) > 0

    def test_each_tool_schema_has_required_fields(self):
        from agent import registry
        for t in registry.tools().values():
            schema = t["parameters_schema"]
            required = schema.get("required", [])
            assert len(required) > 0, f"{t['name']} has no required params"
            for field in required:
                assert field in schema["properties"], \
                    f"{t['name']} required field '{field}' not in properties"

    def test_requires_evidence_field_present(self):
        from agent import registry
        for t in registry.tools().values():
            assert "requires_evidence" in t, f"{t['name']} missing requires_evidence"
            assert isinstance(t["requires_evidence"], bool)


class TestParameterSchemas:
    def test_lookup_procedure_params(self):
        from agent import registry
        t = registry.tools()["lookup_procedure"]
        props = t["parameters_schema"]["properties"]
        assert "topic" in props
        assert "facility_type" in props
        assert props["topic"]["type"] == "string"
        assert props["facility_type"]["type"] == "string"

    def test_queue_notification_params(self):
        from agent import registry
        t = registry.tools()["queue_notification"]
        props = t["parameters_schema"]["properties"]
        assert "severity" in props
        assert "message" in props
        assert "recipients" in props
        assert props["severity"]["type"] == "integer"
        assert props["message"]["type"] == "string"
        assert props["recipients"]["type"] == "array"

    def test_queue_notification_severity_bounds(self):
        from agent import registry
        t = registry.tools()["queue_notification"]
        sev = t["parameters_schema"]["properties"]["severity"]
        assert sev.get("minimum") == 1
        assert sev.get("maximum") == 4

    def test_draft_procedure_update_params(self):
        from agent import registry
        t = registry.tools()["draft_procedure_update"]
        props = t["parameters_schema"]["properties"]
        assert "procedure_id" in props
        assert "proposed_text" in props
        assert "citations" in props
        assert props["procedure_id"]["type"] == "string"
        assert props["proposed_text"]["type"] == "string"
        assert props["citations"]["type"] == "array"


class TestRoleCanCall:
    @pytest.mark.parametrize("role,tool,expected", [
        # operator
        ("operator", "lookup_procedure",      True),
        ("operator", "queue_notification",    False),
        ("operator", "draft_procedure_update", False),
        # supervisor
        ("supervisor", "lookup_procedure",      True),
        ("supervisor", "queue_notification",    True),
        ("supervisor", "draft_procedure_update", False),
        # custodian
        ("custodian", "lookup_procedure",      True),
        ("custodian", "queue_notification",    True),
        ("custodian", "draft_procedure_update", True),
        # admin
        ("admin", "lookup_procedure",      True),
        ("admin", "queue_notification",    True),
        ("admin", "draft_procedure_update", True),
        # unknown role
        ("unknown_role", "lookup_procedure", False),
        # unknown tool
        ("operator", "nonexistent_tool", False),
    ])
    def test_role_can_call(self, role, tool, expected):
        from agent.registry import role_can_call
        assert role_can_call(role, tool) is expected

    def test_permitted_tools_for_operator(self):
        from agent.registry import permitted_tools_for
        names = {t["name"] for t in permitted_tools_for("operator")}
        assert names == {"lookup_procedure"}

    def test_permitted_tools_for_custodian(self):
        from agent.registry import permitted_tools_for
        names = {t["name"] for t in permitted_tools_for("custodian")}
        assert names == EXPECTED_TOOLS


class TestSeverityTier:
    @pytest.mark.parametrize("tool,expected_tier", list(EXPECTED_BASE_TIERS.items()))
    def test_base_severity_tier(self, tool, expected_tier):
        from agent.registry import severity_tier_for
        assert severity_tier_for(tool) == expected_tier

    def test_severity_tier_unknown_tool(self):
        from agent.registry import severity_tier_for
        assert severity_tier_for("nonexistent_tool") is None

    @pytest.mark.parametrize("sev_param,expected_tier", list(QUEUE_TIER_MAP.items()))
    def test_effective_tier_queue_notification(self, sev_param, expected_tier):
        from agent.registry import effective_severity_tier
        result = effective_severity_tier("queue_notification", {"severity": sev_param})
        assert result == expected_tier, \
            f"severity={sev_param}: expected {expected_tier}, got {result}"

    def test_effective_tier_falls_back_to_base_without_params(self):
        from agent.registry import effective_severity_tier
        # No params → base tier
        assert effective_severity_tier("queue_notification") == "High"
        assert effective_severity_tier("lookup_procedure") == "Low"

    def test_effective_tier_non_dependent_tool_ignores_params(self):
        from agent.registry import effective_severity_tier
        # draft_procedure_update is not parameter-dependent
        result = effective_severity_tier("draft_procedure_update", {"anything": "ignored"})
        assert result == "Critical"


# ── Endpoint tests ────────────────────────────────────────────────────────────

class TestToolsEndpoint:
    def test_returns_200(self, client):
        resp = client.get("/agent/tools")
        assert resp.status_code == 200

    def test_returns_three_tools(self, client):
        resp = client.get("/agent/tools")
        body = resp.json()
        assert body["count"] == 3
        assert len(body["tools"]) == 3

    def test_tool_names_match_spec(self, client):
        resp = client.get("/agent/tools")
        names = {t["name"] for t in resp.json()["tools"]}
        assert names == EXPECTED_TOOLS

    def test_each_tool_has_severity_tier(self, client):
        resp = client.get("/agent/tools")
        for t in resp.json()["tools"]:
            assert t["severity_tier"] in {"Critical", "High", "Medium", "Low"}

    def test_each_tool_has_parameters_schema(self, client):
        resp = client.get("/agent/tools")
        for t in resp.json()["tools"]:
            schema = t["parameters_schema"]
            assert schema["type"] == "object"
            assert len(schema["properties"]) > 0


class TestRoleRegistryEndpoint:
    def test_operator_returns_200(self, client):
        resp = client.get("/agent/registry/role/operator")
        assert resp.status_code == 200

    def test_operator_permitted_tools(self, client):
        resp = client.get("/agent/registry/role/operator")
        body = resp.json()
        assert body["role"] == "operator"
        assert body["count"] == 1
        names = {t["name"] for t in body["permitted_tools"]}
        assert names == {"lookup_procedure"}

    def test_supervisor_permitted_tools(self, client):
        resp = client.get("/agent/registry/role/supervisor")
        body = resp.json()
        names = {t["name"] for t in body["permitted_tools"]}
        assert names == {"lookup_procedure", "queue_notification"}

    def test_custodian_permitted_tools(self, client):
        resp = client.get("/agent/registry/role/custodian")
        body = resp.json()
        names = {t["name"] for t in body["permitted_tools"]}
        assert names == EXPECTED_TOOLS

    def test_admin_permitted_tools(self, client):
        resp = client.get("/agent/registry/role/admin")
        body = resp.json()
        names = {t["name"] for t in body["permitted_tools"]}
        assert names == EXPECTED_TOOLS

    def test_unknown_role_returns_404(self, client):
        resp = client.get("/agent/registry/role/unknown_role")
        assert resp.status_code == 404
