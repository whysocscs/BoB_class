"""
Lightweight config loader for conf.json with env overrides.

Usage:
    from config import conf
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _load_conf() -> dict:
    # Default to conf.json in CWD
    conf_path = Path(__file__).parent / "conf.json"
    data: dict = {}
    if conf_path.exists():
        try:
            data = json.loads(conf_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    # Environment overrides (optional)
    overrides = {
        "dbpassword": os.getenv("DB_PASSWORD"),
        "log": os.getenv("LOG_LEVEL"),
        # Optional keys for integrations
        "slack_bot_token": os.getenv("SLACK_BOT_TOKEN"),
        "slack_app_token": os.getenv("SLACK_APP_TOKEN"),
        "virustotal_api_key": os.getenv("VT_API_KEY"),
        "otx_api_key": os.getenv("OTX_API_KEY"),
    }
    for k, v in overrides.items():
        if v:
            data[k] = v
    return data


conf = _load_conf()

