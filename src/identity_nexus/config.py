"""Configuration loading for Identity Nexus."""

from __future__ import annotations

import os
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import ToolDefinition

DEFAULT_CONFIG = """
[service]
data_dir = "~/.identity-nexus"
max_output_chars = 20000
derive_usernames_from_email = true

[safeguards]
require_authorization_attestation = true

[tools.blackbird]
name = "Blackbird"
enabled = true
accepts = ["username"]
risk = "passive"
command = ["blackbird", "--username", "{username}"]
timeout_seconds = 180
description = "Username discovery across social platforms."
install_hint = "Install Blackbird and ensure the blackbird executable is on PATH."

[tools.holehe]
name = "Holehe"
enabled = true
accepts = ["email"]
risk = "passive"
command = ["holehe", "--no-color", "{email}"]
timeout_seconds = 180
description = "Email registration checks across public websites."
install_hint = "Install Holehe and ensure the holehe executable is on PATH."

[tools.ghunt]
name = "GHunt"
enabled = true
accepts = ["email"]
risk = "session"
command = ["ghunt", "email", "{email}"]
timeout_seconds = 180
requires_session = true
description = "Google account OSINT for authorized email investigations."
install_hint = "Install and authenticate GHunt before enabling this module."

[tools.maigret]
name = "Maigret"
enabled = true
accepts = ["username"]
risk = "passive"
command = ["maigret", "{username}", "--timeout", "30", "--no-color"]
timeout_seconds = 240
description = "Username checks across many sites."
install_hint = "Install Maigret and ensure the maigret executable is on PATH."

[tools.sherlock]
name = "Sherlock"
enabled = true
accepts = ["username"]
risk = "passive"
command = ["sherlock", "{username}", "--print-found", "--timeout", "30", "--no-color"]
timeout_seconds = 240
description = "Username checks across social networks."
install_hint = "Install Sherlock and ensure the sherlock executable is on PATH."

[tools.whatsmyname]
name = "WhatsMyName"
enabled = true
accepts = ["username"]
risk = "passive"
command = ["whatsmyname", "{username}"]
timeout_seconds = 240
description = "Username checks using WhatsMyName data."
install_hint = "Install a WhatsMyName-compatible CLI and adjust this command if needed."

[tools.socialscan]
name = "socialscan"
enabled = true
accepts = ["email", "username"]
risk = "passive"
command = ["socialscan", "{target}"]
timeout_seconds = 180
description = "Registration checks for email or username targets."
install_hint = "Install socialscan and ensure the socialscan executable is on PATH."

[tools.phoneinfoga]
name = "PhoneInfoga"
enabled = true
accepts = ["phone"]
risk = "passive"
command = ["phoneinfoga", "scan", "-n", "{phone}"]
timeout_seconds = 180
description = "Phone number OSINT scan."
install_hint = "Install PhoneInfoga and ensure the phoneinfoga executable is on PATH."

[tools.ignorant]
name = "Ignorant"
enabled = true
accepts = ["phone"]
risk = "passive"
command = ["ignorant", "{phone}"]
timeout_seconds = 180
description = "Phone number registration checks."
install_hint = "Install Ignorant and ensure the ignorant executable is on PATH."

[tools.h8mail]
name = "h8mail"
enabled = true
accepts = ["email"]
risk = "passive"
command = ["h8mail", "-t", "{email}"]
timeout_seconds = 180
description = "Email breach and paste lookup orchestration."
install_hint = "Install h8mail and configure any provider keys required by your use case."

[tools.spiderfoot]
name = "SpiderFoot"
enabled = false
accepts = ["email", "phone", "username"]
risk = "deep"
command = ["spiderfoot", "-s", "{target}", "-q"]
timeout_seconds = 900
description = "Deep OSINT automation. Disabled by default; tune modules before use."
install_hint = "Install SpiderFoot, then adjust this command for your preferred CLI/API mode."

[tools.recon_ng]
name = "Recon-ng"
enabled = false
accepts = ["email", "phone", "username"]
risk = "deep"
command = []
timeout_seconds = 900
description = "Recon-ng workflow hook. Configure a non-interactive resource script or wrapper."
install_hint = "Create a recon-ng wrapper command or resource-script workflow, then set command here."
"""


def default_config_path() -> Path:
    return Path(os.environ.get("IDENTITY_NEXUS_CONFIG", "~/.identity-nexus/config.toml")).expanduser()


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config = tomllib.loads(DEFAULT_CONFIG)
    config_path = Path(path).expanduser() if path else default_config_path()
    if config_path.exists():
        with config_path.open("rb") as handle:
            user_config = tomllib.load(handle)
        config = deep_merge(config, user_config)
    return config


def save_default_config(path: str | Path | None = None, overwrite: bool = False) -> Path:
    config_path = Path(path).expanduser() if path else default_config_path()
    if config_path.exists() and not overwrite:
        raise FileExistsError(f"Config already exists: {config_path}")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(DEFAULT_CONFIG.strip() + "\n", encoding="utf-8")
    return config_path


def build_tool_definitions(config: dict[str, Any]) -> dict[str, ToolDefinition]:
    return {
        tool_id: ToolDefinition.from_mapping(tool_id, raw)
        for tool_id, raw in config.get("tools", {}).items()
    }


def data_dir_from_config(config: dict[str, Any]) -> Path:
    value = os.environ.get("IDENTITY_NEXUS_DATA_DIR") or config.get("service", {}).get("data_dir")
    return Path(str(value or "~/.identity-nexus")).expanduser()


def max_output_chars(config: dict[str, Any]) -> int:
    return int(config.get("service", {}).get("max_output_chars", 20000))


def derive_usernames_from_email(config: dict[str, Any]) -> bool:
    return bool(config.get("service", {}).get("derive_usernames_from_email", True))


def require_authorization_attestation(config: dict[str, Any]) -> bool:
    return bool(config.get("safeguards", {}).get("require_authorization_attestation", True))


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
