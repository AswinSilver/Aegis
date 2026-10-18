from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, sessionmaker

from .models import Base


def _database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./data/blacksite.db")


def _ensure_sqlite_parent(url: str) -> None:
    if not url.startswith("sqlite:///") or ":memory:" in url:
        return
    raw_path = url.removeprefix("sqlite:///")
    # sqlite:////absolute/path has one extra slash after the scheme.
    path = Path("/" + raw_path) if raw_path.startswith("/") else Path(raw_path)
    path.parent.mkdir(parents=True, exist_ok=True)


DATABASE_URL = _database_url()
_ensure_sqlite_parent(DATABASE_URL)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
pool_args = {"poolclass": StaticPool} if DATABASE_URL in {"sqlite://", "sqlite:///:memory:"} else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True, **pool_args)


if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # The project intentionally keeps the local setup dependency-free from a
    # migration runner.  Additive columns are upgraded in place so a local
    # BLACKSITE database survives backend updates without losing records.
    if DATABASE_URL.startswith("sqlite"):
        additions = {
            "cases": {
                "indicators_json": "JSON NOT NULL DEFAULT '[]'",
                "vulnerability_ids_json": "JSON NOT NULL DEFAULT '[]'",
                "analyst_notes": "TEXT",
            },
            "assets": {
                "operating_system": "VARCHAR(160)",
                "owner": "VARCHAR(160)",
                "software_json": "JSON",
                "last_assessment_date": "VARCHAR(80)",
                "notes": "TEXT",
            },
        }
        inspector = inspect(engine)
        with engine.begin() as connection:
            for table_name, columns in additions.items():
                existing = {column["name"] for column in inspector.get_columns(table_name)}
                for column_name, declaration in columns.items():
                    if column_name not in existing:
                        connection.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN "{column_name}" {declaration}'))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
