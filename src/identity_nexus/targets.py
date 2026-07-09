"""Target detection and normalization helpers."""

from __future__ import annotations

import re

from .models import EMAIL, PHONE, USERNAME

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_CHARS_RE = re.compile(r"^\+?[\d\s()./-]{7,32}$")
USERNAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class TargetError(ValueError):
    """Raised when a lookup target cannot be normalized."""


def detect_target_kind(value: str) -> str:
    target = value.strip()
    if EMAIL_RE.match(target):
        return EMAIL

    digits = re.sub(r"\D", "", target)
    if PHONE_CHARS_RE.match(target) and 7 <= len(digits) <= 15:
        return PHONE

    if target:
        return USERNAME

    raise TargetError("Target cannot be empty.")


def normalize_target(value: str, target_kind: str | None = None) -> tuple[str, str]:
    target = value.strip()
    if not target:
        raise TargetError("Target cannot be empty.")

    kind = target_kind or detect_target_kind(target)
    if kind == EMAIL:
        normalized = target.lower()
        if not EMAIL_RE.match(normalized):
            raise TargetError("Email target is not valid.")
        return normalized, EMAIL

    if kind == PHONE:
        normalized = normalize_phone(target)
        if not normalized:
            raise TargetError("Phone target is not valid.")
        return normalized, PHONE

    if kind == USERNAME:
        return target, USERNAME

    raise TargetError(f"Unsupported target kind: {target_kind}")


def normalize_phone(value: str) -> str:
    stripped = value.strip()
    prefix = "+" if stripped.startswith("+") else ""
    digits = re.sub(r"\D", "", stripped)
    if not 7 <= len(digits) <= 15:
        return ""
    return f"{prefix}{digits}"


def derive_username_from_email(email: str) -> str:
    local_part = email.split("@", 1)[0].split("+", 1)[0]
    local_part = USERNAME_SAFE_RE.sub("", local_part)
    return local_part.strip("._-")
