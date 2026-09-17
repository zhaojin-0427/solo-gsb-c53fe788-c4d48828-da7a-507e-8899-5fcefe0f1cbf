"""SQLite 数据访问层。WAL 模式 + 线程局部连接，审计写入使用 BEGIN IMMEDIATE 串行化。"""
from __future__ import annotations

import os
import sqlite3
import threading

DB_PATH = os.environ.get("DB_PATH", "app.db")

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    kid         TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    status      TEXT NOT NULL,              -- active | retired
    created_at  TEXT NOT NULL,
    retired_at  TEXT
);

CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    version     INTEGER NOT NULL,
    schema_json TEXT NOT NULL,
    schema_hash TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',   -- active | deprecated
    created_at  TEXT NOT NULL,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    template_name   TEXT NOT NULL,
    template_version INTEGER NOT NULL,
    subject         TEXT NOT NULL,
    fields_json     TEXT NOT NULL,
    salts_json      TEXT NOT NULL,
    header_json     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

-- 撤销列表按 (模板, 版本) 生效；credential_id = '*' 表示撤销该版本全部凭证
CREATE TABLE IF NOT EXISTS revocations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name    TEXT NOT NULL,
    template_version INTEGER NOT NULL,
    credential_id    TEXT NOT NULL,
    reason           TEXT,
    revoked_at       TEXT NOT NULL,
    UNIQUE(template_name, template_version, credential_id)
);

CREATE TABLE IF NOT EXISTS audits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT NOT NULL UNIQUE,
    credential_id   TEXT,
    template_name   TEXT,
    template_version INTEGER,
    result          TEXT NOT NULL,          -- valid | invalid
    checks_json     TEXT NOT NULL,
    disclosed_json  TEXT NOT NULL,
    failures_json   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def init_db() -> None:
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
