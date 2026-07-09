# Identity Nexus

Identity Nexus is a local-first, authorization-gated OSINT lookup service for
email addresses, phone numbers, and usernames. It orchestrates external tools
through configurable adapters and writes each lookup to an audit record.

The built-in registry includes adapters for:

- Blackbird
- Holehe
- GHunt
- Maigret
- Sherlock
- WhatsMyName
- socialscan
- PhoneInfoga
- Ignorant
- h8mail
- SpiderFoot
- Recon-ng

Use this only for identifiers you own, administer, or have explicit permission
to investigate. The API and CLI require an authorization attestation before a
scan runs.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Install whichever OSINT tools you want to run, then make sure their executables
are on `PATH`. Identity Nexus will report missing tools instead of failing the
whole scan.

## Configure

```bash
identity-nexus init
identity-nexus tools
```

The default config is written to `~/.identity-nexus/config.toml`. Edit the
`command` arrays there if a tool is installed under a different command or
needs a wrapper script.

SpiderFoot and Recon-ng are registered as deep modules and disabled by default.
Enable and tune them in the config when you have a non-interactive workflow you
trust.

See [docs/adapters.md](docs/adapters.md) and
[configs/identity-nexus.example.toml](configs/identity-nexus.example.toml) for
the full adapter map.

## Run The CLI

```bash
identity-nexus scan person@example.com --authorized
identity-nexus scan "+12125550100" --authorized
identity-nexus scan example_user --authorized --dry-run
```

Useful options:

- `--module holehe --module ghunt` runs only selected adapters.
- `--include-deep` includes enabled deep modules.
- `--save` stores the scan JSON in the configured data directory.
- `--json` prints the full normalized scan record.

Artifacts are written under `~/.identity-nexus/artifacts/<scan-id>/` by default.

## Run The Service

```bash
identity-nexus serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`.

Set `IDENTITY_NEXUS_API_TOKEN` to require a bearer token or `X-API-Key` header
for the API and browser UI.

API endpoints:

- `GET /api/tools`
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`

Example request:

```bash
curl -X POST http://127.0.0.1:8765/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"person@example.com","authorized":true}'
```

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
