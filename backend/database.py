"""
NetWatcher - SQLite database layer.
Handles schema creation and gives every module a single place to get a connection.
"""
import sqlite3
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "netwatch.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor():
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'guest',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT UNIQUE NOT NULL,
                device_type TEXT DEFAULT 'generic',
                vendor TEXT DEFAULT '',
                ssh_port INTEGER DEFAULT 22,
                tags TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS ping_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                alive INTEGER NOT NULL,
                latency_ms REAL,
                checked_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ping_ip_time ON ping_history(ip, checked_at)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS config_backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                config_text TEXT NOT NULL,
                config_hash TEXT NOT NULL,
                taken_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            )
        """)

        # --- SNMP: per-device settings (migrated in so existing databases keep working)
        cur.execute("PRAGMA table_info(devices)")
        existing = {row["name"] for row in cur.fetchall()}
        for column, ddl in {
            "snmp_enabled": "INTEGER NOT NULL DEFAULT 0",
            "snmp_community": "TEXT NOT NULL DEFAULT ''",
            "snmp_version": "TEXT NOT NULL DEFAULT '2c'",
            "snmp_port": "INTEGER NOT NULL DEFAULT 161",
        }.items():
            if column not in existing:
                cur.execute(f"ALTER TABLE devices ADD COLUMN {column} {ddl}")

        # Latest SNMP poll result per device (one row each, overwritten every poll)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS snmp_snapshots (
                device_id INTEGER PRIMARY KEY,
                collected_at TEXT NOT NULL,
                ok INTEGER NOT NULL,
                error TEXT DEFAULT '',
                data TEXT DEFAULT '',
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT NOT NULL,
                detail TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
