"""
Deployment configuration loader.

Reads deployment.yaml to configure branding, roles, modes,
and suggested queries per deployment. Falls back to defaults
if no config file is found.
"""
import os
import yaml
import logging
from pathlib import Path

log = logging.getLogger("keystone.config")

_CONFIG_PATH = Path(os.environ.get(
    "DEPLOYMENT_CONFIG_PATH",
    "/etc/keystone/deployment.yaml"
))

_DEFAULT_CONFIG = {
    "deployment": {
        "id": "default",
        "name": "Safety Procedure Assistant",
        "subtitle": "Ask a question, get a cited answer",
    },
    "roles": [
        {"id": "member", "label": "Member", "level": 0},
        {"id": "officer", "label": "Officer", "level": 1},
        {"id": "custodian", "label": "Custodian", "level": 0},
        {"id": "authority", "label": "Authority", "level": 2},
    ],
    "modes": [
        {"id": "operational", "label": "Operational",
         "description": "Only approved, current procedures",
         "default": True},
        {"id": "training", "label": "Training",
         "description": "Includes draft and superseded documents"},
    ],
    "suggested_queries": [],
}

def _load() -> dict:
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH) as f:
                cfg = yaml.safe_load(f)
            log.info("Loaded deployment config from %s", _CONFIG_PATH)
            return cfg
        except Exception as e:
            log.warning("Failed to load %s: %s — using defaults", _CONFIG_PATH, e)
    else:
        log.info("No deployment config at %s — using defaults", _CONFIG_PATH)
    return _DEFAULT_CONFIG

CONFIG = _load()
