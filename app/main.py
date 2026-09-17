"""选择性披露凭证验证台 — FastAPI 后端。"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import credential as cred_mod
from . import crypto, db
from .typeschema import SchemaError, validate_claims, validate_schema_definition

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="选择性披露凭证验证台", version="1.0.0")


@app.on_event("startup")
def _startup_init_db():
    db.init_db()


# ---------- Pydantic 模型 ----------

class TemplateIn(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    schema_: list[dict[str, Any]] = Field(alias="schema")

    model_config = {"populate_by_name": True}


class TemplateVersionIn(BaseModel):
    schema_: list[dict[str, Any]] = Field(alias="schema")

    model_config = {"populate_by_name": True}


class IssueIn(BaseModel):
    template_id: str
    claims: dict[str, Any]
    valid_days: int = Field(default=365, ge=1, le=3650)
    disclose: list[str] | None = None  # 可选：签发后直接返回一个演示 presentation


class RevokeIn(BaseModel):
    credential_id: str
    reason: str = ""
    version: int | None = None  # 默认按凭证自身版本生效


# ---------- 工具 ----------

async def _read_body(request: Request) -> bytes:
    """读取原始 body，幂等哈希基于精确字节。"""
    return await request.body()


def _audit_entry_hash(prev_hash: str, idem_key: str, request_hash: str, result: dict[str, Any]) -> str:
    """哈希链一环：sha256(prev_hash || canonical_json(本条关键内容))。"""
    payload = {
        "idem_key": idem_key,
        "request_hash": request_hash,
        "valid": result["valid"],
        "credential_id": result.get("summary", {}).get("credential_id"),
        "checks": [(c["name"], c["ok"]) for c in result.get("checks", [])],
    }
    return crypto.sha256(prev_hash.encode("ascii") + crypto.canonical_json(payload)).hex()


# ---------- 健康检查 / 首页 ----------

@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ---------- 管理员：密钥轮换 / 模板 ----------

@app.get("/api/keys")
def list_keys():
    rows = db.fetch_keys()
    for r in rows:
        r.pop("public_pem")  # 列表不返回完整 PEM，详情接口给
        r["active"] = bool(r["active"])
    return {"keys": rows, "active_kid": db.active_kid()}


@app.get("/api/keys/{kid}")
def get_key(kid: str):
    kmap = db.fetch_key_map()
    if kid not in kmap:
        raise HTTPException(404, "密钥版本不存在")
    return {"kid": kid, "public_pem": kmap[kid]["public_pem"]}


@app.post("/api/keys/rotate")
def rotate_key():
    """生成新 Ed25519 密钥并停用旧密钥；历史凭证用头部 kid 对应的旧公钥验证。"""
    kid = "k" + uuid4().hex[:10]
    priv_pem, pub_pem = crypto.generate_ed25519_keypair()
    with db.tx() as conn:
        conn.execute("UPDATE key_versions SET active=0")
        conn.execute(
            "INSERT INTO key_versions(kid, public_pem, private_pem, created_at, active) "
            "VALUES (?,?,?,?,1)",
            (kid, pub_pem, priv_pem, db.now_iso()),
        )
    return {"kid": kid, "public_pem": pub_pem, "active": True}


@app.get("/api/templates")
def list_templates():
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT template_id, version, created_at FROM template_versions ORDER BY template_id, version"
        ).fetchall()
    finally:
        conn.close()
    versions: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        versions.setdefault(r["template_id"], []).append(
            {"version": r["version"], "created_at": r["created_at"]}
        )
    out = db.fetch_templates()
    for t in out:
        t["versions"] = versions.get(t["id"], [])
    return {"templates": out}


@app.get("/api/templates/{template_id}/versions/{version}")
def get_template_version(template_id: str, version: int):
    tv = db.fetch_template_version(template_id, version)
    if not tv:
        raise HTTPException(404, "模板版本不存在")
    return tv


@app.post("/api/templates")
def create_template(body: TemplateIn):
    try:
        fields = validate_schema_definition(body.schema_)
    except SchemaError as e:
        raise HTTPException(422, str(e))
    ts = db.now_iso()
    try:
        with db.tx() as conn:
            conn.execute(
                "INSERT INTO templates(id, name, current_version, created_at) VALUES (?,?,1,?)",
                (body.id, body.name, ts),
            )
            conn.execute(
                "INSERT INTO template_versions(template_id, version, schema_json, created_at) "
                "VALUES (?,?,?,?)",
                (body.id, 1, crypto.canonical_json(fields).decode("utf-8"), ts),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, f"模板 {body.id} 已存在")
    return {"template_id": body.id, "version": 1, "schema": fields}


@app.post("/api/templates/{template_id}/versions")
def new_template_version(template_id: str, body: TemplateVersionIn):
    """模板升级：新版本带新的类型/必填约束；已签发凭证锁定其签发时版本。"""
    try:
        fields = validate_schema_definition(body.schema_)
    except SchemaError as e:
        raise HTTPException(422, str(e))
    with db.tx() as conn:
        row = conn.execute(
            "SELECT current_version FROM templates WHERE id=?", (template_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "模板不存在")
        nxt = row["current_version"] + 1
        conn.execute(
            "INSERT INTO template_versions(template_id, version, schema_json, created_at) "
            "VALUES (?,?,?,?)",
            (template_id, nxt, crypto.canonical_json(fields).decode("utf-8"), db.now_iso()),
        )
        conn.execute(
            "UPDATE templates SET current_version=? WHERE id=?", (nxt, template_id)
        )
    return {"template_id": template_id, "version": nxt, "schema": fields}


# ---------- 签发端 ----------

@app.post("/api/issue")
def issue(body: IssueIn):
    kid = db.active_kid()
    if not kid:
        raise HTTPException(409, "系统中没有可用签名密钥，请先轮换密钥")
    tv = None
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT t.current_version FROM templates t WHERE t.id=?", (body.template_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, f"模板 {body.template_id} 不存在")
    version = row["current_version"]
    tv = db.fetch_template_version(body.template_id, version)
    err = validate_claims(tv["schema"], body.claims)
    if err:
        raise HTTPException(422, err)

    keys = db.fetch_key_map()
    now = db.utcnow()
    envelope = cred_mod.issue_credential(
        template_id=body.template_id,
        version=version,
        schema_fields=tv["schema"],
        claims=body.claims,
        valid_from=db.utciso(now),
        valid_until=db.utciso(now + timedelta(days=body.valid_days)),
        kid=kid,
        private_pem=keys[kid]["private_pem"],
    )
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO credentials(id, template_id, version, kid, envelope_json, revoked, created_at) "
            "VALUES (?,?,?,?,?,0,?)",
            (
                envelope["header"]["credential_id"],
                body.template_id,
                version,
                kid,
                crypto.canonical_json(envelope).decode("utf-8"),
                db.now_iso(),
            ),
        )
    resp: dict[str, Any] = {"credential": envelope}
    if body.disclose is not None:
        unknown = set(body.disclose) - {lf["field"] for lf in envelope["leaves"]}
        if unknown:
            raise HTTPException(422, f"披露字段不存在: {sorted(unknown)}")
        resp["presentation"] = cred_mod.build_presentation(envelope, body.disclose)
    return resp


@app.get("/api/credentials")
def list_credentials():
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT id, template_id, version, kid, revoked, created_at FROM credentials "
            "ORDER BY created_at DESC"
        ).fetchall()
        out = [dict(r) for r in rows]
        for r in out:
            r["revoked"] = bool(r["revoked"])
        return {"credentials": out}
    finally:
        conn.close()


@app.get("/api/credentials/{credential_id}")
def get_credential(credential_id: str):
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT envelope_json FROM credentials WHERE id=?", (credential_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "凭证不存在")
    return JSONResponse(json.loads(row["envelope_json"]))


@app.post("/api/presentations")
async def build_presentation_api(request: Request):
    """服务端辅助：从已签发凭证构造选择性披露 presentation（持有者也可在浏览器本地构造）。"""
    body = await request.json()
    credential_id = body.get("credential_id")
    disclose = body.get("disclose", [])
    if not isinstance(disclose, list):
        raise HTTPException(422, "disclose 必须是字段名数组")
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT envelope_json FROM credentials WHERE id=?", (credential_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "凭证不存在")
    envelope = json.loads(row["envelope_json"])
    known = {lf["field"] for lf in envelope["leaves"]}
    unknown = set(disclose) - known
    if unknown:
        raise HTTPException(422, f"披露字段不存在: {sorted(unknown)}")
    return cred_mod.build_presentation(envelope, disclose)


# ---------- 撤销（按模板版本生效） ----------

@app.post("/api/revoke")
def revoke(body: RevokeIn):
    with db.tx() as conn:
        row = conn.execute(
            "SELECT template_id, version FROM credentials WHERE id=?", (body.credential_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "凭证不存在")
        version = body.version if body.version is not None else row["version"]
        exists = conn.execute(
            "SELECT 1 FROM template_versions WHERE template_id=? AND version=?",
            (row["template_id"], version),
        ).fetchone()
        if not exists:
            raise HTTPException(422, f"模板 {row['template_id']} 不存在版本 {version}")
        try:
            conn.execute(
                "INSERT INTO revocations(template_id, version, credential_id, reason, created_at) "
                "VALUES (?,?,?,?,?)",
                (row["template_id"], version, body.credential_id, body.reason, db.now_iso()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "该凭证在此版本撤销列表中已存在")
        # 若撤销的就是凭证自身版本，标记凭证为已撤销
        if version == row["version"]:
            conn.execute("UPDATE credentials SET revoked=1 WHERE id=?", (body.credential_id,))
    return {
        "template_id": row["template_id"],
        "version": version,
        "credential_id": body.credential_id,
        "revoked": True,
    }


@app.get("/api/revocations")
def list_revocations():
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT template_id, version, credential_id, reason, created_at "
            "FROM revocations ORDER BY created_at DESC"
        ).fetchall()
        return {"revocations": [dict(r) for r in rows]}
    finally:
        conn.close()


# ---------- 验证端（幂等 + 审计哈希链） ----------

def _record_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["duplicate"] = bool(d["duplicate"])
    d["result"] = json.loads(d["result_json"]) if d["result_json"] else None
    d["checks"] = json.loads(d["checks_json"]) if d["checks_json"] else None
    d.pop("result_json", None)
    d.pop("checks_json", None)
    d.pop("request_hash", None)
    return d


def _wait_for_record(conn: sqlite3.Connection, verif_id: int) -> sqlite3.Row:
    """并发情况下等待胜出者完成验证并发布结果。"""
    for _ in range(150):  # 最多 ~15s
        row = conn.execute(
            "SELECT * FROM verifications WHERE id=?", (verif_id,)
        ).fetchone()
        if row and row["status"] == "done":
            return row
        import time
        time.sleep(0.1)
    raise HTTPException(409, "并发验证处理超时，请稍后重试")


@app.post("/api/verify")
async def verify(
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    body = await _read_body(request)
    if not idempotency_key:
        raise HTTPException(400, "缺少 Idempotency-Key 请求头")
    try:
        presentation = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(422, "请求体不是合法 JSON")

    request_hash = crypto.sha256(body).hex()

    # 幂等快路径：同键已处理完直接返回同一条审计
    conn = db.get_conn()
    try:
        existing = conn.execute(
            "SELECT * FROM verifications WHERE idem_key=?", (idempotency_key,)
        ).fetchone()
    finally:
        conn.close()
    if existing:
        if existing["status"] != "done":
            conn = db.get_conn()
            try:
                existing = _wait_for_record(conn, existing["id"])
            finally:
                conn.close()
        with db.tx() as conn:
            conn.execute("UPDATE verifications SET duplicate=1 WHERE id=?", (existing["id"],))
        d = _record_to_dict(existing)
        d["duplicate"] = True
        return d

    # 慢路径：唯一约束保证重复/并发提交只写一条审计
    try:
        with db.tx() as conn:
            cur = conn.execute(
                "INSERT INTO verifications(idem_key, request_hash, status, created_at) "
                "VALUES (?,?, 'pending', ?)",
                (idempotency_key, request_hash, db.now_iso()),
            )
            verif_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn = db.get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM verifications WHERE idem_key=?", (idempotency_key,)
            ).fetchone()
            if row["status"] != "done":
                row = _wait_for_record(conn, row["id"])
        finally:
            conn.close()
        with db.tx() as conn:
            conn.execute("UPDATE verifications SET duplicate=1 WHERE id=?", (row["id"],))
        d = _record_to_dict(row)
        d["duplicate"] = True
        return d

    # 胜出者执行验证（数据库只此一条审计行）
    try:
        keys = {kid: v["public_pem"] for kid, v in db.fetch_key_map().items()}

        expect_version = None
        conn = db.get_conn()
        try:
            hdr = presentation.get("header") or {}
            trow = conn.execute(
                "SELECT current_version FROM templates WHERE id=?",
                (hdr.get("template_id"),),
            ).fetchone()
        finally:
            conn.close()
        if trow:
            expect_version = trow["current_version"]

        valid, checks, summary = cred_mod.verify_presentation(
            presentation,
            public_keys=keys,
            is_revoked_fn=db.is_revoked,
            expect_template_version=expect_version,
        )
        result = {"valid": valid, "checks": checks, "summary": summary}
    except cred_mod.VerifiableError as e:
        result = {"valid": False, "checks": e.checks, "summary": {}}
    except Exception as e:  # 任何异常也要落审计，避免 pending 悬挂
        result = {
            "valid": False,
            "checks": [{"name": "system", "ok": False, "detail": f"验证服务异常: {e}"}],
            "summary": {},
        }

    # 追加到哈希链尾
    with db.tx() as conn:
        last = conn.execute(
            "SELECT chain_hash FROM verifications WHERE status='done' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["chain_hash"] if last else "GENESIS"
        chain_hash = _audit_entry_hash(prev_hash, idempotency_key, request_hash, result)
        conn.execute(
            "UPDATE verifications SET result_json=?, checks_json=?, chain_hash=?, prev_hash=?, "
            "status='done', completed_at=? WHERE id=?",
            (
                crypto.canonical_json(result).decode("utf-8"),
                crypto.canonical_json(checks if "checks" in result else []).decode("utf-8"),
                chain_hash,
                prev_hash,
                db.now_iso(),
                verif_id,
            ),
        )
        row = conn.execute("SELECT * FROM verifications WHERE id=?", (verif_id,)).fetchone()
    return _record_to_dict(row)


@app.get("/api/audits")
def list_audits(limit: int = 50):
    limit = max(1, min(limit, 500))
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM verifications WHERE status='done' ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        out = [_record_to_dict(r) for r in rows]
        return {"audits": out}
    finally:
        conn.close()


@app.get("/api/audits/chain")
def audit_chain():
    """重放哈希链并逐条校验，供前端展示可校验的审计链。"""
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM verifications WHERE status='done' ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    prev = "GENESIS"
    entries = []
    chain_ok = True
    for r in rows:
        result = json.loads(r["result_json"])
        expected = _audit_entry_hash(prev, r["idem_key"], r["request_hash"], result)
        link_ok = expected == r["chain_hash"] and r["prev_hash"] == prev
        chain_ok = chain_ok and link_ok
        entries.append(
            {
                "id": r["id"],
                "idem_key": r["idem_key"],
                "prev_hash": r["prev_hash"],
                "chain_hash": r["chain_hash"],
                "link_ok": link_ok,
                "valid": result.get("valid"),
                "credential_id": result.get("summary", {}).get("credential_id"),
                "duplicate": bool(r["duplicate"]),
                "created_at": r["created_at"],
                "completed_at": r["completed_at"],
            }
        )
        prev = r["chain_hash"]
    return {"chain_ok": chain_ok, "length": len(entries), "entries": entries}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
