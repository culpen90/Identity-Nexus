"""JSON persistence for scan audit records."""

from __future__ import annotations

import json
from pathlib import Path

from .config import data_dir_from_config, load_config
from .models import ScanRecord


class ScanStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.scan_dir = data_dir / "scans"
        self.scan_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_config(cls, config: dict | None = None) -> "ScanStore":
        loaded = config or load_config()
        return cls(data_dir_from_config(loaded))

    def save(self, record: ScanRecord) -> Path:
        path = self.path_for(record.scan_id)
        path.write_text(
            json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def get(self, scan_id: str) -> ScanRecord:
        path = self.path_for(scan_id)
        if not path.exists():
            raise FileNotFoundError(f"Scan not found: {scan_id}")
        return ScanRecord.from_mapping(json.loads(path.read_text(encoding="utf-8")))

    def list(self, limit: int = 25) -> list[ScanRecord]:
        paths = sorted(self.scan_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        return [
            ScanRecord.from_mapping(json.loads(path.read_text(encoding="utf-8")))
            for path in paths[:limit]
        ]

    def path_for(self, scan_id: str) -> Path:
        safe_id = scan_id.replace("/", "_")
        return self.scan_dir / f"{safe_id}.json"
