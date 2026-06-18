"""
Keystone agent extension package (keystone-core/agent, formerly KDAT-002).

Implements the single-agent governed extension per keystone-core/agent-spec v1.2 (formerly KDAT-002-SPEC v1.2)
(keystone-kdat main, commit 4b12094). Adds three tools, four roles,
four severity tiers, HITL routing, controller-as-reflection, and an
action audit chain that operates alongside the existing query audit chain.

Surface area:

- agent.router: FastAPI router mounted by api/main.py
- agent.controller: the only execution path for tool calls
- agent.audit: HMAC-SHA256 action audit chain
- agent.hitl: approval queue + endpoints
- agent.registry: tool registry and role-tool authorization matrix
- agent.tools: tool implementations
- agent.models: SQLAlchemy models (4 new tables, zero ALTERs on existing)
- agent.schemas: Pydantic request/response schemas
"""

__version__ = "0.0.1-scaffold"
