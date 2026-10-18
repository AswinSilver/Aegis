# Aegis

Aegis is a local-first cybersecurity investigation workspace built with React, TypeScript, and Vite. It is designed as a polished demonstration environment for threat hunting workflows: indicator investigation, attack-path exploration, vulnerability review, event triage, detection-rule testing, forensic text analysis, asset inventory, case management, and report export.

## Current scope

- Responsive Aegis command-center interface with an explicit `DEMO MODE · REAL API DATA ONLY` label
- Backend-backed indicator investigations for IP, URL, domain, and file hashes
- Local file hashing with an explicit browser action (the selected file is not sent until submitted)
- Local IOC extraction and JSON/CSV log analysis
- Persisted event timeline with JSON/CSV imports and filters
- Backend NVD search with honest loading, empty, and unavailable states
- Detection-rule CRUD and test results against persisted events
- Asset and case CRUD, JSON/CSV asset imports, and case report export
- Persisted attack graph and backend health status

The frontend does not seed synthetic records or claim that an external provider is available. Intelligence and vulnerability provider configuration remains a backend concern, with source attribution returned by the API.

## Run locally

Install frontend dependencies and start the Vite UI:

```bash
npm install
npm run dev
```

In a second terminal, install and start the local FastAPI service:

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --reload
```

The API creates the existing `data/blacksite.db` compatibility database automatically. The frontend uses
`http://127.0.0.1:8000` by default.

Open the URL printed by Vite. For a production build:

```bash
npm run build
npm run preview
```

Backend checks:

```bash
python -m pytest backend/tests -q
python -m compileall -q backend
```

## Environment variables

The frontend uses the local backend by default. Set `VITE_API_URL` in a local `.env` file when the API is hosted elsewhere:

```bash
VITE_API_URL=http://127.0.0.1:8000
```

Provider credentials such as `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`, and `ABUSEIPDB_API_KEY` belong on the backend and are never read by the frontend.

NVD's public API is enabled by default because it does not require a paid key.
Set `NVD_ENABLED=false` in `backend/.env` for offline-only mode. Configure
`CORS_ORIGINS` for the actual UI origin when deploying beyond localhost.

See [`AUDIT.md`](./AUDIT.md) for a feature-by-feature implementation checklist
and the deliberately incomplete optional capabilities.
