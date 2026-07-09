"""Command line interface for Identity Nexus."""

from __future__ import annotations

import argparse
import json
import sys

from .config import load_config, save_default_config
from .models import ScanRequest
from .runner import NexusRunner, describe_tool_status, friendly_error
from .storage import ScanStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="identity-nexus")
    parser.add_argument("--config", help="Path to an Identity Nexus TOML config.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Write a default config file.")
    init_parser.add_argument("--path", help="Config path to create.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing config.")

    tools_parser = subparsers.add_parser("tools", help="List configured tool availability.")
    tools_parser.add_argument("--json", action="store_true", help="Print JSON.")

    scan_parser = subparsers.add_parser("scan", help="Run a lookup scan.")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--kind", choices=["email", "phone", "username"], help="Target kind. Defaults to auto.")
    scan_parser.add_argument("--module", action="append", dest="modules", help="Run only a specific module id.")
    scan_parser.add_argument("--include-deep", action="store_true", help="Include deep modules such as SpiderFoot.")
    scan_parser.add_argument("--dry-run", action="store_true", help="Show selected commands without executing them.")
    scan_parser.add_argument("--authorized", action="store_true", help="Confirm you are allowed to investigate the target.")
    scan_parser.add_argument("--notes", help="Audit notes for this scan.")
    scan_parser.add_argument("--json", action="store_true", help="Print full JSON result.")
    scan_parser.add_argument("--save", action="store_true", help="Save the scan record in the data directory.")

    serve_parser = subparsers.add_parser("serve", help="Run the local API and browser UI.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--reload", action="store_true")

    history_parser = subparsers.add_parser("history", help="List saved scan records.")
    history_parser.add_argument("--limit", type=int, default=10)
    history_parser.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config) if getattr(args, "config", None) else load_config()

    try:
        if args.command == "init":
            path = save_default_config(args.path, overwrite=args.force)
            print(f"Wrote config: {path}")
            return 0

        if args.command == "tools":
            statuses = describe_tool_status(config)
            if args.json:
                print(json.dumps(statuses, indent=2, sort_keys=True))
            else:
                print_tools(statuses)
            return 0

        if args.command == "scan":
            request = ScanRequest(
                target=args.target,
                target_kind=args.kind,
                modules=args.modules,
                include_deep=args.include_deep,
                authorized=args.authorized,
                dry_run=args.dry_run,
                notes=args.notes,
            )
            record = NexusRunner(config=config).run(request)
            if args.save:
                path = ScanStore.from_config(config).save(record)
                print(f"Saved scan: {path}", file=sys.stderr)
            if args.json:
                print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
            else:
                print_scan(record.to_dict())
            return 0 if not record.errors else 1

        if args.command == "serve":
            from .api import create_app

            import uvicorn

            app_path = "identity_nexus.api:create_app"
            if args.reload:
                uvicorn.run(app_path, host=args.host, port=args.port, reload=True, factory=True)
            else:
                uvicorn.run(create_app(config), host=args.host, port=args.port)
            return 0

        if args.command == "history":
            records = [record.to_dict() for record in ScanStore.from_config(config).list(limit=args.limit)]
            if args.json:
                print(json.dumps(records, indent=2, sort_keys=True))
            else:
                for record in records:
                    print(f"{record['scan_id']}  {record['status']}  {record['request']['target']}")
            return 0

    except Exception as exc:
        print(friendly_error(exc), file=sys.stderr)
        return 2

    parser.error(f"Unknown command: {args.command}")
    return 2


def print_tools(statuses: list[dict]) -> None:
    for status in statuses:
        availability = "available" if status["available"] else "missing"
        enabled = "enabled" if status["enabled"] else "disabled"
        accepts = ",".join(status["accepts"])
        command = " ".join(status["command"]) if status["command"] else "(configure command)"
        print(f"{status['id']:<14} {availability:<9} {enabled:<8} {status['risk']:<7} {accepts:<20} {command}")


def print_scan(record: dict) -> None:
    print(f"Scan {record['scan_id']} [{record['status']}] target={record['request']['target']}")
    for error in record.get("errors", []):
        print(f"error: {error}")
    for result in record.get("results", []):
        command = " ".join(result.get("command") or [])
        print(f"{result['tool_id']:<14} {result['status']:<22} {command}")
        message = result.get("message")
        if message:
            print(f"  {message}")
        stdout = (result.get("stdout") or "").strip()
        stderr = (result.get("stderr") or "").strip()
        if stdout:
            print(indent_block(stdout))
        if stderr:
            print(indent_block(stderr))


def indent_block(value: str) -> str:
    return "\n".join(f"  {line}" for line in value.splitlines())


if __name__ == "__main__":
    raise SystemExit(main())
