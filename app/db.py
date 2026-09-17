"""SQLite 持久层 + schema 初始化 + 演示种子数据。"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .crypto import canonical_json, generate_ed25519_keypair

DB_PATH = os.environ.get("SDV_DB_PATH", "/data/verifier.db")
SEED_ON_START = os.environ.get("SDV_SEED", "1") == "1"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utciso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def now_iso() -> str:
    return utciso(utcnow())


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    conn = get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = get_conn()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
                kid          TEXT PRIMARY KEY,
                public_pem   TEXT NOT NULL,
                private_pem  TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                active       INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS templates (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                current_version INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS template_versions (
                template_id  TEXT NOT NULL REFERENCES templates(id),
                version      INTEGER NOT NULL,
                schema_json  TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                PRIMARY KEY (template_id, version)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id           TEXT PRIMARY KEY,
                template_id  TEXT NOT NULL,
                version      INTEGER NOT NULL,
                kid          TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                revoked      INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL
            );

            -- 撤销列表按模板版本生效：同一张凭证可针对多个版本被撤销
            CREATE TABLE IF NOT EXISTS revocations (
                template_id  TEXT NOT NULL,
                version      INTEGER NOT NULL,
                credential_id TEXT NOT NULL,
                reason       TEXT NOT NULL DEFAULT '',
                created_at   TEXT NOT NULL,
                PRIMARY KEY (template_id, version, credential_id)
            );

            CREATE TABLE IF NOT EXISTS verifications (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                idem_key      TEXT NOT NULL UNIQUE,
                request_hash  TEXT NOT NULL,
                result_json   TEXT,
                checks_json   TEXT,
                chain_hash    TEXT,
                prev_hash     TEXT,
                duplicate     INTEGER NOT NULL DEFAULT 0,
                status        TEXT NOT NULL DEFAULT 'pending',
                created_at    TEXT NOT NULL,
                completed_at  TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_creds_tpl ON credentials(template_id, version);
            CREATE INDEX IF NOT EXISTS idx_rev_lookup ON revocations(template_id, version, credential_id);
            """
        )
    finally:
        conn.close()
    if SEED_ON_START:
        _seed()


def _seed() -> None:
    """写入演示用密钥与模板（仅首次）。"""
    with tx() as conn:
        key_count = conn.execute("SELECT COUNT(*) c FROM key_versions").fetchone()["c"]
        if key_count == 0:
            priv_pem, pub_pem = generate_ed25519_keypair()
            conn.execute(
                "INSERT INTO key_versions(kid, public_pem, private_pem, created_at, active) "
                "VALUES (?,?,?,?,1)",
                ("k1", pub_pem, priv_pem, now_iso()),
            )
        tpl_count = conn.execute("SELECT COUNT(*) c FROM templates").fetchone()["c"]
        if tpl_count == 0:
            ts = now_iso()
            schema = [
                {"name": "full_name", "type": "string", "required": True},
                {"name": "age", "type": "integer", "required": True},
                {"name": "email", "type": "string", "required": False},
                {"name": "is_vip", "type": "boolean", "required": False},
                {"name": "member_since", "type": "date", "required": False},
            ]
            conn.execute(
                "INSERT INTO templates(id, name, current_version, created_at) VALUES (?,?,?,?)",
                ("tpl_demo", "演示会员凭证", 1, ts),
            )
            conn.execute(
                "INSERT INTO template_versions(template_id, version, schema_json, created_at) "
                "VALUES (?,?,?,?)",
                ("tpl_demo", 1, canonical_json(schema).decode("utf-8"), ts),
            )


# ---------- 查询辅助 ----------

def fetch_keys() -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT kid, public_pem, created_at, active FROM key_versions ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def fetch_key_map() -> dict[str, dict[str, str]]:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT kid, public_pem, private_pem FROM key_versions").fetchall()
        return {r["kid"]: dict(r) for r in rows}
    finally:
        conn.close()


def active_kid() -> str | None:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT kid FROM key_versions WHERE active=1 ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return row["kid"] if row else None
    finally:
        conn.close()


def fetch_templates() -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT t.id, t.name, t.current_version, t.created_at, "
            "(SELECT schema_json FROM template_versions v WHERE v.template_id=t.id "
            " AND v.version=t.current_version) AS schema_json "
            "FROM templates t ORDER BY t.created_at"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["schema"] = json.loads(d.pop("schema_json"))
            out.append(d)
        return out
    finally:
        conn.close()


def fetch_template_version(template_id: str, version: int) -> dict[str, Any] | None:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT tv.template_id, tv.version, tv.schema_json, tv.created_at, t.name "
            "FROM template_versions tv JOIN templates t ON t.id = tv.template_id "
            "WHERE tv.template_id=? AND tv.version=?",
            (template_id, version),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["schema"] = json.loads(d.pop("schema_json"))
        return d
    finally:
        conn.close()


def is_revoked(template_id: str, version: int, credential_id: str) -> bool:
    """撤销列表按凭证声明的模板版本生效。"""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT 1 FROM revocations WHERE template_id=? AND version=? AND credential_id=?",
            (template_id, version, credential_id),
        ).fetchone()
        return row is not None
    finally:
        conn.close()
