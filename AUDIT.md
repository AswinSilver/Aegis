# BLACKSITE implementation audit

This audit records the state of the repository after wiring the existing UI to the local backend. It is intentionally explicit about what is real, what is optional, and what remains outside the current scope.

| Area | Initial state | Current state | Evidence |
| --- | --- | --- | --- |
| Frontend | React/Vite UI with local hardcoded collections and simulated result strings | React UI uses a typed API client, loading/error/empty states, and backend-backed records | `src/App.tsx`, `src/api.ts` |
| Backend | No backend or persistence | FastAPI service with SQLite/SQLAlchemy, startup schema creation, additive local upgrades, CORS, request limits, rate limiting, and audit rows | `backend/app/main.py`, `backend/app/db/` |
| Hashing | No real file analysis | Explicit file action calculates MD5/SHA-1/SHA-256, size, extension, and conservative magic-byte type; no execution or external upload | `backend/app/services/hashing.py` |
| IOC extraction | No real extraction | Local URL/IP/domain/hash/CVE/email extraction with deduplication and source explanation | `backend/app/services/ioc.py` |
| Log analysis | Static/demo event rows | JSON/JSONL/CSV parsing, timestamp normalization, failed-login grouping, repeated-event and explicit frequency observations, persisted imports | `backend/app/services/logs.py` |
| Indicator intelligence | Hardcoded match message | Validated IP/URL/domain/hash endpoints with private-destination blocking, optional VirusTotal/AbuseIPDB/URLhaus, timeouts, attribution, cache, and honest no-result/unavailable states | `backend/app/services/intelligence.py` |
| Vulnerability research | Hardcoded vulnerability list | NVD API adapter with pagination, CVE/keyword, severity and publication-date query parameters; upstream failures are visible | `backend/app/services/vulnerabilities.py` |
| Detection rules | Button returned a simulated match | Persisted data-only rule trees with AND/OR, comparison/string operators, time-window operator, match explanations, CRUD, and event testing | `backend/app/services/rules.py` |
| Cases | Local-only case list | SQLite CRUD, linked assets/events, related indicators/CVEs, analyst notes, case activity, JSON/CSV/PDF reports | `backend/app/db/models.py`, `backend/app/services/reports.py` |
| Assets | Local-only inventory list | SQLite CRUD/import/search/filter, OS/owner/software/notes fields, and explicit single-target TCP/HTTP metadata assessment endpoint | `backend/app/main.py` |
| Graph | Hardcoded nodes and relationships | Nodes/edges derive from persisted cases, assets, events, analysis records, extracted indicators and case annotations; UI supports search, filtering, selection, path highlighting, export | `backend/app/services/graph.py`, `src/App.tsx` |
| Reports | One local demo JSON export | Backend-generated case JSON/CSV/PDF downloads contain only persisted evidence and source/limitation text | `backend/app/services/reports.py` |
| External secrets | None | Backend-only optional provider variables; frontend never reads provider keys | `backend/.env.example`, `src/api.ts` |

## Remaining deliberate gaps

- Authentication, multi-user RBAC, and organization policy enforcement are not implemented.
- The optional AI integration is not implemented; deterministic local workflows do not depend on AI.
- The optional Three.js spatial scene is not implemented; the core evidence graph is available without it.
- Vulnerability records are queried from NVD but are not yet persisted as a separate local catalog/bookmark table.
- Active assessments are intentionally limited to one explicitly authorized asset target and one TCP port or HTTP metadata request; there is no network-range scanner, exploit, brute force, or unrestricted URL proxy.

All remaining gaps are exposed as missing capabilities rather than represented by fake findings or synthetic live telemetry.
