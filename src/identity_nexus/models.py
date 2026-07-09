"""Core data models shared by the CLI, API, and runner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


EMAIL = "email"
PHONE = "phone"
USERNAME = "username"

SCAN_QUEUED = "queued"
SCAN_RUNNING = "running"
SCAN_COMPLETE = "complete"
SCAN_FAILED = "failed"

RESULT_OK = "ok"
RESULT_DRY_RUN = "dry_run"
RESULT_SKIPPED = "skipped"
RESULT_NOT_APPLICABLE = "not_applicable"
RESULT_NOT_INSTALLED = "not_installed"
RESULT_CONFIG_REQUIRED = "configuration_required"
RESULT_TIMEOUT = "timeout"
RESULT_ERROR = "error"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    name: str
    accepts: tuple[str, ...]
    command: tuple[str, ...] = ()
    enabled: bool = True
    risk: str = "passive"
    timeout_seconds: int = 120
    parser: str = "text"
    install_hint: str = ""
    requires_session: bool = False
    description: str = ""

    @classmethod
    def from_mapping(cls, tool_id: str, raw: dict[str, Any]) -> "ToolDefinition":
        return cls(
            id=tool_id,
            name=str(raw.get("name") or tool_id),
            accepts=tuple(str(item) for item in raw.get("accepts", [])),
            command=tuple(str(item) for item in raw.get("command", [])),
            enabled=bool(raw.get("enabled", True)),
            risk=str(raw.get("risk", "passive")),
            timeout_seconds=int(raw.get("timeout_seconds", 120)),
            parser=str(raw.get("parser", "text")),
            install_hint=str(raw.get("install_hint", "")),
            requires_session=bool(raw.get("requires_session", False)),
            description=str(raw.get("description", "")),
        )


@dataclass
class ScanRequest:
    target: str
    target_kind: str | None = None
    modules: list[str] | None = None
    include_deep: bool = False
    authorized: bool = False
    dry_run: bool = False
    notes: str | None = None

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "ScanRequest":
        modules = raw.get("modules")
        if modules is not None:
            modules = [str(item) for item in modules]
        return cls(
            target=str(raw["target"]),
            target_kind=raw.get("target_kind"),
            modules=modules,
            include_deep=bool(raw.get("include_deep", False)),
            authorized=bool(raw.get("authorized", False)),
            dry_run=bool(raw.get("dry_run", False)),
            notes=raw.get("notes"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    tool_id: str
    tool_name: str
    status: str
    command: list[str] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float = 0.0
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResolvedTool:
    definition: ToolDefinition
    applicable: bool
    reason: str = ""


@dataclass
class ScanRecord:
    scan_id: str
    request: ScanRequest
    target_kind: str
    status: str = SCAN_QUEUED
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    completed_at: str | None = None
    results: list[ToolResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "request": self.request.to_dict(),
            "target_kind": self.target_kind,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "results": [result.to_dict() for result in self.results],
            "errors": self.errors,
        }

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "ScanRecord":
        return cls(
            scan_id=str(raw["scan_id"]),
            request=ScanRequest.from_mapping(raw["request"]),
            target_kind=str(raw["target_kind"]),
            status=str(raw.get("status", SCAN_QUEUED)),
            created_at=str(raw.get("created_at", utc_now())),
            started_at=raw.get("started_at"),
            completed_at=raw.get("completed_at"),
            results=[
                ToolResult(
                    tool_id=str(item["tool_id"]),
                    tool_name=str(item.get("tool_name", item["tool_id"])),
                    status=str(item["status"]),
                    command=list(item.get("command", [])),
                    started_at=item.get("started_at"),
                    completed_at=item.get("completed_at"),
                    duration_seconds=float(item.get("duration_seconds", 0.0)),
                    return_code=item.get("return_code"),
                    stdout=str(item.get("stdout", "")),
                    stderr=str(item.get("stderr", "")),
                    parsed=dict(item.get("parsed", {})),
                    artifacts=list(item.get("artifacts", [])),
                    message=str(item.get("message", "")),
                )
                for item in raw.get("results", [])
            ],
            errors=[str(item) for item in raw.get("errors", [])],
        )
