"""SQLite storage for GarudaX. It needs no separate database server."""
import os
import sqlite3
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("GARUDAX_DB_PATH", BACKEND_DIR / "garudax_data.db"))


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH), timeout=30, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def _add_missing_columns(db, table, columns):
    existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    for column, definition in columns.items():
        if column not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            phone TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('citizen','authority','worker')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            citizen_id INTEGER NOT NULL REFERENCES users(id),
            description TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            address TEXT DEFAULT '',
            photo_filename TEXT NOT NULL,
            damage_type TEXT DEFAULT '',
            confidence REAL,
            ai_available INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Pending',
            assigned_worker_id INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_complaints_citizen ON complaints(citizen_id);
        CREATE INDEX IF NOT EXISTS idx_complaints_worker ON complaints(assigned_worker_id);
        CREATE TABLE IF NOT EXISTS repair_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER NOT NULL REFERENCES complaints(id),
            actor_id INTEGER NOT NULL REFERENCES users(id),
            status TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS complaint_supporters (
            complaint_id INTEGER NOT NULL REFERENCES complaints(id),
            citizen_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (complaint_id, citizen_id)
        );
        CREATE TABLE IF NOT EXISTS email_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            to_address TEXT NOT NULL,
            subject TEXT NOT NULL,
            status TEXT NOT NULL,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        # safe upgrades for databases created by older versions of GarudaX
        _add_missing_columns(db, "users", {
            "failed_logins": "INTEGER NOT NULL DEFAULT 0",
            "locked_until": "TEXT",
        })
        _add_missing_columns(db, "complaints", {
            "high_emergency": "INTEGER NOT NULL DEFAULT 0",
            "emergency_escalated_at": "TEXT",
            "citizen_urgent": "INTEGER NOT NULL DEFAULT 0",
            "support_count": "INTEGER NOT NULL DEFAULT 0",
            "photo_sha256": "TEXT",
            "photo_dhash": "TEXT",
            "before_photo_filename": "TEXT",
            "before_photo_sha256": "TEXT",
            "before_photo_dhash": "TEXT",
            "after_photo_filename": "TEXT",
            "after_photo_sha256": "TEXT",
            "after_photo_dhash": "TEXT",
            "verification_note": "TEXT DEFAULT ''",
            "completed_at": "TEXT",
            "ai_review": "INTEGER NOT NULL DEFAULT 0",
        })
        db.execute("CREATE INDEX IF NOT EXISTS idx_complaints_sha ON complaints(photo_sha256)")
