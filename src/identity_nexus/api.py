"""FastAPI application for Identity Nexus."""

from __future__ import annotations

import os
from threading import Lock
from typing import Any

from .config import load_config
from .models import SCAN_FAILED, SCAN_RUNNING, ScanRequest, utc_now
from .runner import AuthorizationRequired, NexusRunner, describe_tool_status, friendly_error
from .storage import ScanStore

try:
    from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - import guard for CLI-only installs
    raise RuntimeError("Install the service dependencies with `pip install -e .` to use the API.") from exc


class ScanCreate(BaseModel):
    target: str = Field(min_length=1)
    target_kind: str | None = None
    modules: list[str] | None = None
    include_deep: bool = False
    authorized: bool = False
    dry_run: bool = False
    notes: str | None = None


class ScanManager:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or load_config()
        self.runner = NexusRunner(config=self.config)
        self.store = ScanStore.from_config(self.config)
        self.lock = Lock()

    def create(self, payload: ScanCreate) -> dict[str, Any]:
        data = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
        request = ScanRequest.from_mapping(data)
        record = self.runner.create_pending_record(request)
        self.store.save(record)
        return record.to_dict()

    def run_pending(self, scan_id: str) -> None:
        with self.lock:
            pending = self.store.get(scan_id)
            pending.status = SCAN_RUNNING
            pending.started_at = utc_now()
            self.store.save(pending)

        try:
            record = self.runner.run(pending.request, scan_id=scan_id)
        except Exception as exc:
            pending.status = SCAN_FAILED
            pending.completed_at = utc_now()
            pending.errors.append(friendly_error(exc))
            self.store.save(pending)
            return

        self.store.save(record)


def create_app(config: dict[str, Any] | None = None) -> FastAPI:
    manager = ScanManager(config=config)
    app = FastAPI(title="Identity Nexus", version="0.1.0")

    def require_api_token(request: Request) -> None:
        expected = os.environ.get("IDENTITY_NEXUS_API_TOKEN")
        if not expected:
            return
        bearer = request.headers.get("authorization", "")
        api_key = request.headers.get("x-api-key", "")
        token = bearer.removeprefix("Bearer ").strip() if bearer.startswith("Bearer ") else api_key
        if token != expected:
            raise HTTPException(status_code=401, detail="Missing or invalid API token.")

    @app.get("/", response_class=HTMLResponse)
    def index(_: None = Depends(require_api_token)) -> str:
        return INDEX_HTML

    @app.get("/api/tools", dependencies=[Depends(require_api_token)])
    def tools() -> list[dict[str, Any]]:
        return describe_tool_status(manager.config)

    @app.post("/api/scans", dependencies=[Depends(require_api_token)])
    def create_scan(payload: ScanCreate, background: BackgroundTasks) -> dict[str, Any]:
        if not payload.authorized:
            raise HTTPException(
                status_code=403,
                detail="Authorization attestation is required before running a lookup.",
            )
        try:
            record = manager.create(payload)
        except AuthorizationRequired as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=friendly_error(exc)) from exc
        background.add_task(manager.run_pending, record["scan_id"])
        return record

    @app.get("/api/scans", dependencies=[Depends(require_api_token)])
    def list_scans(limit: int = 25) -> list[dict[str, Any]]:
        return [record.to_dict() for record in manager.store.list(limit=limit)]

    @app.get("/api/scans/{scan_id}", dependencies=[Depends(require_api_token)])
    def get_scan(scan_id: str) -> dict[str, Any]:
        try:
            return manager.store.get(scan_id).to_dict()
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app


INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Nexus</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f7f7f2;
      --ink: #141512;
      --muted: #62645d;
      --panel: #ffffff;
      --line: #d7d8cf;
      --accent: #0f766e;
      --accent-ink: #ffffff;
      --warn: #a16207;
      --bad: #b91c1c;
      --good: #166534;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #10110f;
        --ink: #f2f2eb;
        --muted: #a9aaa2;
        --panel: #1a1c18;
        --line: #383a33;
        --accent: #2dd4bf;
        --accent-ink: #06201d;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
    }
    h1, h2 { margin: 0; font-size: 18px; letter-spacing: 0; }
    main {
      display: grid;
      grid-template-columns: minmax(280px, 420px) 1fr;
      min-height: calc(100vh - 66px);
    }
    aside {
      border-right: 1px solid var(--line);
      padding: 20px;
    }
    section {
      padding: 20px;
      overflow: auto;
    }
    label {
      display: grid;
      gap: 6px;
      margin: 0 0 14px;
      color: var(--muted);
      font-size: 13px;
    }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--ink);
      padding: 10px 11px;
      font: inherit;
    }
    textarea { min-height: 76px; resize: vertical; }
    .row { display: flex; gap: 10px; align-items: center; }
    .row > * { flex: 1; }
    .check {
      display: grid;
      grid-template-columns: 18px 1fr;
      gap: 10px;
      align-items: start;
      color: var(--ink);
      margin: 16px 0;
    }
    .check input { width: 18px; margin-top: 2px; }
    button {
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: var(--accent-ink);
      padding: 10px 13px;
      font-weight: 700;
      cursor: pointer;
    }
    button.secondary {
      background: transparent;
      color: var(--ink);
      border: 1px solid var(--line);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 14px;
      background: var(--panel);
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      word-break: break-word;
    }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    code, pre {
      font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    pre {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      max-height: 220px;
      overflow: auto;
      background: color-mix(in srgb, var(--panel) 84%, var(--bg));
    }
    .status-ok { color: var(--good); }
    .status-error, .status-timeout { color: var(--bad); }
    .status-not_installed, .status-configuration_required { color: var(--warn); }
    .muted { color: var(--muted); }
    @media (max-width: 760px) {
      main { grid-template-columns: 1fr; }
      aside { border-right: 0; border-bottom: 1px solid var(--line); }
    }
  </style>
</head>
<body>
  <header>
    <h1>Identity Nexus</h1>
    <button class="secondary" id="refresh" type="button">Refresh</button>
  </header>
  <main>
    <aside>
      <form id="scan-form">
        <label>Target
          <input name="target" autocomplete="off" placeholder="email, phone, or username" required>
        </label>
        <div class="row">
          <label>Kind
            <select name="target_kind">
              <option value="">Auto</option>
              <option value="email">Email</option>
              <option value="phone">Phone</option>
              <option value="username">Username</option>
            </select>
          </label>
          <label>Mode
            <select name="mode">
              <option value="standard">Standard</option>
              <option value="deep">Deep</option>
              <option value="dry">Dry run</option>
            </select>
          </label>
        </div>
        <label>Modules
          <input name="modules" placeholder="optional comma-separated ids">
        </label>
        <label>Notes
          <textarea name="notes"></textarea>
        </label>
        <label class="check">
          <input name="authorized" type="checkbox" required>
          <span>I am authorized to investigate this identifier.</span>
        </label>
        <button type="submit">Start Scan</button>
      </form>
      <p class="muted" id="form-status"></p>
    </aside>
    <section>
      <h2>Scans</h2>
      <div id="scans"></div>
    </section>
  </main>
  <script>
    const scansEl = document.querySelector("#scans");
    const statusEl = document.querySelector("#form-status");
    const form = document.querySelector("#scan-form");
    const refreshButton = document.querySelector("#refresh");

    async function api(path, options = {}) {
      const headers = {"Content-Type": "application/json", ...(options.headers || {})};
      const response = await fetch(path, {...options, headers});
      if (!response.ok) throw new Error(await response.text());
      return response.json();
    }

    function statusClass(value) {
      return `status-${String(value || "").replaceAll(" ", "_")}`;
    }

    function renderResult(result) {
      const output = result.stdout || result.stderr || result.message || "";
      return `<tr>
        <td>${result.tool_name}</td>
        <td class="${statusClass(result.status)}">${result.status}</td>
        <td><code>${(result.command || []).join(" ")}</code></td>
        <td>${result.duration_seconds || ""}</td>
        <td>${output ? `<pre>${escapeHtml(output)}</pre>` : ""}</td>
      </tr>`;
    }

    function renderScan(scan) {
      const rows = (scan.results || []).map(renderResult).join("");
      return `<article>
        <p><strong>${scan.request.target}</strong> <span class="muted">${scan.status} · ${scan.scan_id}</span></p>
        ${scan.errors?.length ? `<pre>${escapeHtml(scan.errors.join("\\n"))}</pre>` : ""}
        <table>
          <thead><tr><th>Tool</th><th>Status</th><th>Command</th><th>Seconds</th><th>Output</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="5" class="muted">Pending</td></tr>`}</tbody>
        </table>
      </article>`;
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
      }[ch]));
    }

    async function refresh() {
      const scans = await api("/api/scans");
      scansEl.innerHTML = scans.map(renderScan).join("") || "<p class='muted'>No scans yet.</p>";
      if (scans.some(scan => scan.status === "queued" || scan.status === "running")) {
        window.setTimeout(refresh, 1500);
      }
    }

    form.addEventListener("submit", async event => {
      event.preventDefault();
      const data = new FormData(form);
      const mode = data.get("mode");
      const modules = String(data.get("modules") || "")
        .split(",")
        .map(item => item.trim())
        .filter(Boolean);
      const payload = {
        target: data.get("target"),
        target_kind: data.get("target_kind") || null,
        modules: modules.length ? modules : null,
        include_deep: mode === "deep",
        dry_run: mode === "dry",
        authorized: data.get("authorized") === "on",
        notes: data.get("notes") || null
      };
      statusEl.textContent = "Starting...";
      try {
        const scan = await api("/api/scans", {method: "POST", body: JSON.stringify(payload)});
        statusEl.textContent = `Started ${scan.scan_id}`;
        form.reset();
        await refresh();
      } catch (error) {
        statusEl.textContent = error.message;
      }
    });

    refreshButton.addEventListener("click", refresh);
    refresh();
  </script>
</body>
</html>
"""
