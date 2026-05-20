"""
M1 smoke tests. Verify scaffold is importable and the module exposes the
expected surface.
"""


def test_module_imports():
    import agent  # noqa: F401
    from agent import audit, controller, hitl, models, registry, router, schemas, tools  # noqa: F401


def test_module_version(agent_module_version):
    assert agent_module_version.startswith("0.0.")


def test_audit_canonical_params_hash():
    from agent.audit import canonical_params_hash
    a = canonical_params_hash({"x": 1, "y": 2})
    b = canonical_params_hash({"y": 2, "x": 1})
    assert a == b, "canonical hash must be order-independent"


def test_registry_empty_stub():
    from agent import registry
    registry.load_registry()
    assert registry.tools() == {}


def test_hitl_severity_routing():
    from agent.hitl import requires_hitl
    assert requires_hitl("Critical") is True
    assert requires_hitl("High") is True
    assert requires_hitl("Medium") is False
    assert requires_hitl("Low") is False
