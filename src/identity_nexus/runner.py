"""Tool orchestration for Identity Nexus scans."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from .config import (
    build_tool_definitions,
    data_dir_from_config,
    derive_usernames_from_email,
    load_config,
    max_output_chars,
    require_authorization_attestation,
)
from .models import (
    EMAIL,
    PHONE,
    RESULT_CONFIG_REQUIRED,
    RESULT_DRY_RUN,
    RESULT_ERROR,
    RESULT_NOT_APPLICABLE,
    RESULT_NOT_INSTALLED,
    RESULT_OK,
    RESULT_SKIPPED,
    RESULT_TIMEOUT,
    SCAN_COMPLETE,
    SCAN_FAILED,
    SCAN_RUNNING,
    USERNAME,
    ResolvedTool,
    ScanRecord,
    ScanRequest,
    ToolDefinition,
    ToolResult,
    utc_now,
)
from .targets import TargetError, derive_username_from_email, normalize_target


class AuthorizationRequired(PermissionError):
    """Raised when a scan is attempted without an authorization attestation."""


class ToolNotFound(KeyError):
    """Raised when a requested module is not in the registry."""


class NexusRunner:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or load_config()
        self.tools = build_tool_definitions(self.config)
        self.output_limit = max_output_chars(self.config)
        self.artifact_root = data_dir_from_config(self.config) / "artifacts"

    def create_pending_record(self, request: ScanRequest, scan_id: str | None = None) -> ScanRecord:
        normalized_target, kind = normalize_target(request.target, request.target_kind)
        normalized_request = ScanRequest(
            target=normalized_target,
            target_kind=kind,
            modules=request.modules,
            include_deep=request.include_deep,
            authorized=request.authorized,
            dry_run=request.dry_run,
            notes=request.notes,
        )
        return ScanRecord(
            scan_id=scan_id or str(uuid.uuid4()),
            request=normalized_request,
            target_kind=kind,
        )

    def run(self, request: ScanRequest, scan_id: str | None = None) -> ScanRecord:
        if require_authorization_attestation(self.config) and not request.authorized:
            raise AuthorizationRequired(
                "Set authorized=true only for identifiers you own, administer, or have explicit permission to investigate."
            )

        record = self.create_pending_record(request, scan_id=scan_id)
        record.status = SCAN_RUNNING
        record.started_at = utc_now()

        try:
            selected_tools = self.select_tools(record.request, record.target_kind)
            context = self.build_context(record.request.target, record.target_kind)
            work_dir = self.scan_artifact_dir(record.scan_id)
            for selected in selected_tools:
                if not selected.definition.enabled:
                    record.results.append(
                        self.skipped_result(
                            selected.definition,
                            f"{selected.definition.name} is disabled in config.",
                        )
                    )
                    continue
                if not selected.applicable:
                    record.results.append(
                        self.not_applicable_result(selected.definition, selected.reason)
                    )
                    continue
                record.results.append(
                    self.run_tool(selected.definition, context, work_dir, dry_run=record.request.dry_run)
                )
            record.status = SCAN_COMPLETE
        except Exception as exc:  # pragma: no cover - defensive catch for API persistence
            record.status = SCAN_FAILED
            record.errors.append(str(exc))
        finally:
            record.completed_at = utc_now()

        return record

    def select_tools(self, request: ScanRequest, target_kind: str) -> list[ResolvedTool]:
        requested = set(request.modules or [])
        if requested:
            unknown = requested.difference(self.tools)
            if unknown:
                raise ToolNotFound(f"Unknown module(s): {', '.join(sorted(unknown))}")
            candidates = [self.tools[tool_id] for tool_id in request.modules or []]
        else:
            candidates = [
                tool
                for tool in self.tools.values()
                if tool.enabled and (request.include_deep or tool.risk != "deep")
            ]

        selected: list[ResolvedTool] = []
        for tool in candidates:
            applicable = self.tool_accepts_target(tool, target_kind)
            if applicable:
                selected.append(ResolvedTool(tool, True))
            elif requested:
                accepted = ", ".join(tool.accepts) or "no target kinds"
                selected.append(
                    ResolvedTool(
                        tool,
                        False,
                        f"{tool.name} accepts {accepted}, not {target_kind}.",
                    )
                )
        return selected

    def tool_accepts_target(self, tool: ToolDefinition, target_kind: str) -> bool:
        if target_kind in tool.accepts:
            return True
        return (
            target_kind == EMAIL
            and USERNAME in tool.accepts
            and derive_usernames_from_email(self.config)
        )

    def build_context(self, target: str, target_kind: str) -> dict[str, str]:
        context = {
            "target": target,
            "target_kind": target_kind,
            "email": "",
            "phone": "",
            "username": "",
        }
        if target_kind == EMAIL:
            context["email"] = target
            context["username"] = derive_username_from_email(target)
        elif target_kind == PHONE:
            context["phone"] = target
        elif target_kind == USERNAME:
            context["username"] = target
        return context

    def scan_artifact_dir(self, scan_id: str) -> Path:
        safe_id = scan_id.replace("/", "_")
        path = self.artifact_root / safe_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def run_tool(
        self,
        tool: ToolDefinition,
        context: dict[str, str],
        work_dir: Path,
        dry_run: bool = False,
    ) -> ToolResult:
        started_at = utc_now()
        started = time.monotonic()
        if not tool.command:
            return ToolResult(
                tool_id=tool.id,
                tool_name=tool.name,
                status=RESULT_CONFIG_REQUIRED,
                started_at=started_at,
                completed_at=utc_now(),
                message=tool.install_hint or "No command is configured for this module.",
            )

        command, artifacts = self.expand_command(tool, context, work_dir)
        if dry_run:
            return ToolResult(
                tool_id=tool.id,
                tool_name=tool.name,
                status=RESULT_DRY_RUN,
                command=command,
                started_at=started_at,
                completed_at=utc_now(),
                artifacts=[str(path) for path in artifacts],
                message="Dry run only; command was not executed.",
            )

        if not self.is_command_available(command):
            return ToolResult(
                tool_id=tool.id,
                tool_name=tool.name,
                status=RESULT_NOT_INSTALLED,
                command=command,
                started_at=started_at,
                completed_at=utc_now(),
                message=tool.install_hint or f"Executable not found: {command[0]}",
            )

        try:
            completed = subprocess.run(
                command,
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=tool.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool_id=tool.id,
                tool_name=tool.name,
                status=RESULT_TIMEOUT,
                command=command,
                started_at=started_at,
                completed_at=utc_now(),
                duration_seconds=round(time.monotonic() - started, 3),
                stdout=self.truncate(exc.stdout or ""),
                stderr=self.truncate(exc.stderr or ""),
                artifacts=[str(path) for path in artifacts if path.exists()],
                message=f"Timed out after {tool.timeout_seconds} seconds.",
            )
        except OSError as exc:
            return ToolResult(
                tool_id=tool.id,
                tool_name=tool.name,
                status=RESULT_ERROR,
                command=command,
                started_at=started_at,
                completed_at=utc_now(),
                duration_seconds=round(time.monotonic() - started, 3),
                message=str(exc),
            )

        stdout = self.truncate(completed.stdout)
        stderr = self.truncate(completed.stderr)
        parsed = self.parse_outputs(stdout, artifacts)
        status = RESULT_OK if completed.returncode == 0 else RESULT_ERROR
        return ToolResult(
            tool_id=tool.id,
            tool_name=tool.name,
            status=status,
            command=command,
            started_at=started_at,
            completed_at=utc_now(),
            duration_seconds=round(time.monotonic() - started, 3),
            return_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            parsed=parsed,
            artifacts=[str(path) for path in artifacts if path.exists()],
        )

    def expand_command(
        self,
        tool: ToolDefinition,
        context: dict[str, str],
        work_dir: Path,
    ) -> tuple[list[str], list[Path]]:
        artifacts = {
            "output_json": work_dir / f"{tool.id}.json",
            "output_txt": work_dir / f"{tool.id}.txt",
            "output_dir": work_dir / tool.id,
        }
        artifacts["output_dir"].mkdir(exist_ok=True)

        substitutions = {**context, **{key: str(value) for key, value in artifacts.items()}}
        command = [self.replace_placeholders(part, substitutions) for part in tool.command]
        return command, list(artifacts.values())

    def replace_placeholders(self, value: str, substitutions: dict[str, str]) -> str:
        expanded = value
        for key, replacement in substitutions.items():
            expanded = expanded.replace("{" + key + "}", replacement)
        return expanded

    def skipped_result(self, tool: ToolDefinition, message: str) -> ToolResult:
        return ToolResult(
            tool_id=tool.id,
            tool_name=tool.name,
            status=RESULT_SKIPPED,
            completed_at=utc_now(),
            message=message,
        )

    def not_applicable_result(self, tool: ToolDefinition, message: str) -> ToolResult:
        return ToolResult(
            tool_id=tool.id,
            tool_name=tool.name,
            status=RESULT_NOT_APPLICABLE,
            completed_at=utc_now(),
            message=message,
        )

    def is_command_available(self, command: list[str]) -> bool:
        if not command:
            return False
        executable = command[0]
        if "/" in executable:
            return Path(executable).expanduser().exists()
        return shutil.which(executable) is not None

    def parse_outputs(self, stdout: str, artifact_paths: list[Path]) -> dict[str, Any]:
        parsed: dict[str, Any] = {
            "stdout_line_count": len(stdout.splitlines()) if stdout else 0,
        }
        stripped = stdout.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed["stdout_json"] = json.loads(stripped)
            except json.JSONDecodeError:
                pass

        json_artifacts: dict[str, Any] = {}
        for path in artifact_paths:
            if path.suffix.lower() != ".json" or not path.exists():
                continue
            try:
                json_artifacts[path.name] = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
        if json_artifacts:
            parsed["json_artifacts"] = json_artifacts
        return parsed

    def truncate(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if len(value) <= self.output_limit:
            return value
        return value[: self.output_limit] + "\n[identity-nexus: output truncated]\n"


def run_scan_from_mapping(raw: dict[str, Any], config: dict[str, Any] | None = None) -> ScanRecord:
    request = ScanRequest.from_mapping(raw)
    return NexusRunner(config=config).run(request)


def describe_tool_status(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    runner = NexusRunner(config=config)
    statuses = []
    for tool in runner.tools.values():
        command = list(tool.command)
        statuses.append(
            {
                "id": tool.id,
                "name": tool.name,
                "enabled": tool.enabled,
                "accepts": list(tool.accepts),
                "risk": tool.risk,
                "requires_session": tool.requires_session,
                "available": bool(command) and runner.is_command_available(command),
                "command": command,
                "install_hint": tool.install_hint,
            }
        )
    return statuses


def friendly_error(exc: Exception) -> str:
    if isinstance(exc, AuthorizationRequired):
        return str(exc)
    if isinstance(exc, TargetError):
        return str(exc)
    if isinstance(exc, ToolNotFound):
        return str(exc)
    return f"{exc.__class__.__name__}: {exc}"
