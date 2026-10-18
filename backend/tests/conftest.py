from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


_db_dir = Path(tempfile.mkdtemp(prefix="blacksite-tests-"))
_project_root = Path(__file__).resolve().parents[2]
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
os.environ["DATABASE_URL"] = f"sqlite:///{(_db_dir / 'test.db').as_posix()}"
os.environ["RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ.pop("ABUSEIPDB_API_KEY", None)
os.environ.pop("VIRUSTOTAL_API_KEY", None)
os.environ.pop("URLHAUS_API_URL", None)
os.environ.pop("URLHAUS_ENABLED", None)
os.environ.pop("NVD_API_KEY", None)
os.environ.pop("NVD_API_URL", None)
os.environ["NVD_ENABLED"] = "0"

from backend.app.db.models import Base  # noqa: E402
from backend.app.db.setup import engine  # noqa: E402
from backend.app.main import app  # noqa: E402


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client
