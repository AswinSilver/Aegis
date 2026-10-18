# BLACKSITE backend

The backend is a local-first FastAPI service. It uses SQLite at the project-relative
`data/blacksite.db` path by default and creates the schema on startup. It does not
seed synthetic records.

From the project root:

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --reload
```

Optional provider variables are documented in `.env.example`. NVD's public endpoint
is enabled by default; set `NVD_ENABLED=false` for offline-only operation. An unset
malware/abuse provider is reported as `no_result` or `unavailable`; the service never
turns a missing lookup into a clean verdict. Private, loopback, link-local, reserved,
and obvious internal destinations are not sent to external intelligence providers.
There is no generic URL fetch or proxy endpoint.

Run the backend checks from the project root:

```bash
python -m pytest backend/tests -q
python -c "import sys; sys.path.insert(0, 'backend'); from app.main import app; print(app.title)"
```
