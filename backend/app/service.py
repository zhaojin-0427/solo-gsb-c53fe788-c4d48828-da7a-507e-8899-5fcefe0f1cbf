"""业务逻辑：模板管理、密钥轮换、凭证签发、选择性披露、验证与审计链。"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from . import crypto_utils as cu
from .db import get_db

FIELD_TYPES = ("string", "integer", "number", "boolean", "date", "enum")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ================================================================ 密钥

def ensure_active_key() -> sqlite3.Row:
    """启动时保证存在一把 active 签名密钥。"""
    db = get_db()
    row = db.execute("SELECT * FROM keys WHERE status='active' ORDER BY created_at DESC LIMIT 1").fetchone()
    if row is None:
        row = _create_key(db)
    return row


def _create_key(db: sqlite3.Connection) -> sqlite3.Row:
    priv, pub = cu.generate_keypair()
    kid = "key-" + uuid.uuid4().hex[:12]
    db.execute(
        "INSERT INTO keys(kid, public_key, private_key, status, created_at) VALUES(?,?,?,?,?)",
        (kid, pub, priv, "active", now_iso()),
    )
    db.commit()
    return db.execute("SELECT * FROM keys WHERE kid=?", (kid,)).fetchone()


def rotate_key() -> dict:
    """轮换密钥：退役当前 active 密钥并生成新密钥。旧密钥保留用于验证历史凭证。"""
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        current = db.execute("SELECT * FROM keys WHERE status='active'").fetchone()
        if current is not None:
            db.execute(
                "UPDATE keys SET status='retired', retired_at=? WHERE kid=?",
                (now_iso(), current["kid"]),
            )
        priv, pub = cu.generate_keypair()
        kid = "key-" + uuid.uuid4().hex[:12]
        db.execute(
            "INSERT INTO keys(kid, public_key, private_key, status, created_at) VALUES(?,?,?,?,?)",
            (kid, pub, priv, "active", now_iso()),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return get_key(kid)


def get_key(kid: str) -> dict | None:
    row = get_db().execute("SELECT * FROM keys WHERE kid=?", (kid,)).fetchone()
    return _key_dict(row) if row else None


def list_keys() -> list[dict]:
    rows = get_db().execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    return [_key_dict(r) for r in rows]


def _key_dict(row: sqlite3.Row) -> dict:
    return {
        "kid": row["kid"],
        "public_key": row["public_key"],
        "status": row["status"],
        "created_at": row["created_at"],
        "retired_at": row["retired_at"],
    }


# ================================================================ 模板

def validate_schema_fields(fields: list[dict]) -> list[str]:
    errors = []
    seen = set()
    for i, f in enumerate(fields):
        name = (f.get("name") or "").strip()
        if not name:
            errors.append(f"字段 #{i+1} 缺少名称")
        elif name in seen:
            errors.append(f"字段名重复: {name}")
        seen.add(name)
        ftype = f.get("type")
        if ftype not in FIELD_TYPES:
            errors.append(f"字段 {name or i+1} 类型非法: {ftype!r}，允许 {FIELD_TYPES}")
        if ftype == "enum":
            values = f.get("values") or []
            if not isinstance(values, list) or not values:
                errors.append(f"枚举字段 {name} 必须提供非空 values 列表")
    return errors


def create_template(name: str, fields: list[dict]) -> dict:
    """创建模板新版本；同名模板版本号自动递增。"""
    db = get_db()
    errors = validate_schema_fields(fields)
    if errors:
        raise ValueError("; ".join(errors))

    schema = {"fields": [
        {
            "name": f["name"].strip(),
            "type": f["type"],
            "required": bool(f.get("required")),
            **({"values": list(f["values"])} if f["type"] == "enum" else {}),
        }
        for f in fields
    ]}
    schema_json = json.dumps(schema, ensure_ascii=False, sort_keys=True)
    schema_hash = cu.sha256_hex(cu.canonical_json(schema))

    row = db.execute("SELECT MAX(version) AS v FROM templates WHERE name=?", (name,)).fetchone()
    version = (row["v"] or 0) + 1
    db.execute(
        "INSERT INTO templates(name, version, schema_json, schema_hash, status, created_at)"
        " VALUES(?,?,?,?, 'active', ?)",
        (name, version, schema_json, schema_hash, now_iso()),
    )
    db.commit()
    return get_template(name, version)


def get_template(name: str, version: int) -> dict | None:
    row = get_db().execute(
        "SELECT * FROM templates WHERE name=? AND version=?", (name, version)
    ).fetchone()
    return _template_dict(row) if row else None


def list_templates() -> list[dict]:
    rows = get_db().execute(
        "SELECT * FROM templates ORDER BY name, version DESC"
    ).fetchall()
    return [_template_dict(r) for r in rows]


def set_template_status(name: str, version: int, status: str) -> dict | None:
    if status not in ("active", "deprecated"):
        raise ValueError("status 必须是 active 或 deprecated")
    db = get_db()
    db.execute("UPDATE templates SET status=? WHERE name=? AND version=?", (status, name, version))
    db.commit()
    return get_template(name, version)


def _template_dict(row: sqlite3.Row) -> dict:
    return {
        "name": row["name"],
        "version": row["version"],
        "schema": json.loads(row["schema_json"]),
        "schema_hash": row["schema_hash"],
        "status": row["status"],
        "created_at": row["created_at"],
    }


# ================================================================ 签发

def _validate_value(field: dict, value: Any) -> str | None:
    """按模板类型校验单个字段值，返回错误信息或 None。"""
    name, ftype = field["name"], field["type"]
    if ftype == "string":
        if not isinstance(value, str):
            return f"字段 {name} 应为 string"
    elif ftype == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"字段 {name} 应为 integer"
    elif ftype == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return f"字段 {name} 应为 number"
    elif ftype == "boolean":
        if not isinstance(value, bool):
            return f"字段 {name} 应为 boolean"
    elif ftype == "date":
        if not isinstance(value, str):
            return f"字段 {name} 应为 YYYY-MM-DD 日期字符串"
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            return f"字段 {name} 不是合法日期(YYYY-MM-DD): {value!r}"
    elif ftype == "enum":
        if value not in (field.get("values") or []):
            return f"字段 {name} 取值 {value!r} 不在枚举 {field.get('values')} 内"
    return None


def issue_credential(template_name: str, template_version: int, subject: str,
                     values: dict[str, Any], valid_days: int) -> dict:
    """签发凭证：逐字段加盐生成 Merkle 叶子，树头与凭证头一起签名。"""
    db = get_db()
    tpl = get_template(template_name, template_version)
    if tpl is None:
        raise ValueError(f"模板不存在: {template_name} v{template_version}")
    if tpl["status"] != "active":
        raise ValueError(f"模板 {template_name} v{template_version} 已停用，不能签发新凭证")

    fields = tpl["schema"]["fields"]
    errors: list[str] = []
    for f in fields:
        if f["name"] not in values:
            if f["required"]:
                errors.append(f"缺少必填字段: {f['name']}")
            continue
        err = _validate_value(f, values[f["name"]])
        if err:
            errors.append(err)
    unknown = set(values) - {f["name"] for f in fields}
    if unknown:
        errors.append(f"模板未定义的字段: {sorted(unknown)}")
    if errors:
        raise ValueError("; ".join(errors))

    key = ensure_active_key()
    key_row = db.execute("SELECT * FROM keys WHERE kid=?", (key["kid"],)).fetchone()

    # 按模板声明顺序为每个字段建立承诺
    salts: dict[str, str] = {}
    leaf_hashes: list[str] = []
    ordered_names: list[str] = []
    for f in fields:
        name = f["name"]
        if name not in values:
            continue
        salt = cu.new_salt()
        salts[name] = salt
        leaf_hashes.append(cu.leaf_hash(name, salt, values[name]))
        ordered_names.append(name)
    merkle_root, _proofs = cu.build_merkle_tree(leaf_hashes)

    issued_at = now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=valid_days)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    header = {
        "credential_id": "cred-" + uuid.uuid4().hex,
        "template_name": template_name,
        "template_version": template_version,
        "template_hash": tpl["schema_hash"],
        "subject": subject,
        "merkle_root": merkle_root,
        "kid": key_row["kid"],
        "issued_at": issued_at,
        "not_before": issued_at,
        "expires_at": expires_at,
    }
    signature = cu.sign(key_row["private_key"], cu.canonical_json(header))

    db.execute(
        "INSERT INTO credentials(id, template_name, template_version, subject, fields_json,"
        " salts_json, header_json, signature, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (header["credential_id"], template_name, template_version, subject,
         json.dumps(values, ensure_ascii=False), json.dumps(salts),
         json.dumps(header, ensure_ascii=False), signature, issued_at),
    )
    db.commit()
    return get_credential(header["credential_id"])


def get_credential(credential_id: str) -> dict | None:
    row = get_db().execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return _credential_dict(row) if row else None


def list_credentials() -> list[dict]:
    rows = get_db().execute("SELECT * FROM credentials ORDER BY created_at DESC").fetchall()
    return [_credential_dict(r) for r in rows]


def _credential_dict(row: sqlite3.Row) -> dict:
    return {
        "credential_id": row["id"],
        "template_name": row["template_name"],
        "template_version": row["template_version"],
        "subject": row["subject"],
        "fields": json.loads(row["fields_json"]),
        "salts": json.loads(row["salts_json"]),
        "header": json.loads(row["header_json"]),
        "signature": row["signature"],
        "created_at": row["created_at"],
    }


# ================================================================ 撤销（按模板版本生效）

def revoke(template_name: str, template_version: int, credential_id: str, reason: str = "") -> dict:
    db = get_db()
    if get_template(template_name, template_version) is None:
        raise ValueError(f"模板不存在: {template_name} v{template_version}")
    if credential_id != "*" and get_credential(credential_id) is None:
        raise ValueError(f"凭证不存在: {credential_id}")
    try:
        db.execute(
            "INSERT INTO revocations(template_name, template_version, credential_id, reason, revoked_at)"
            " VALUES(?,?,?,?,?)",
            (template_name, template_version, credential_id, reason, now_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise ValueError("该撤销记录已存在")
    return list_revocations(template_name, template_version)[-1]


def list_revocations(template_name: str | None = None,
                     template_version: int | None = None) -> list[dict]:
    sql = "SELECT * FROM revocations"
    args: list[Any] = []
    if template_name is not None and template_version is not None:
        sql += " WHERE template_name=? AND template_version=?"
        args = [template_name, template_version]
    sql += " ORDER BY id"
    rows = get_db().execute(sql, args).fetchall()
    return [dict(r) for r in rows]


def is_revoked(template_name: str, template_version: int, credential_id: str) -> bool:
    row = get_db().execute(
        "SELECT 1 FROM revocations WHERE template_name=? AND template_version=?"
        " AND (credential_id=? OR credential_id='*') LIMIT 1",
        (template_name, template_version, credential_id),
    ).fetchone()
    return row is not None


# ================================================================ 选择性披露

def build_presentation(credential_id: str, disclose_fields: list[str]) -> dict:
    """持有者生成选择性披露 presentation：只含指定字段的明文、盐与 Merkle 路径。"""
    cred = get_credential(credential_id)
    if cred is None:
        raise ValueError(f"凭证不存在: {credential_id}")

    tpl = get_template(cred["template_name"], cred["template_version"])
    schema_fields = [f["name"] for f in tpl["schema"]["fields"]] if tpl else list(cred["fields"])

    unknown = set(disclose_fields) - set(cred["fields"])
    if unknown:
        raise ValueError(f"凭证中不存在字段: {sorted(unknown)}")

    # 按签发时的字段顺序重建整棵树，提取被披露字段的证明路径
    ordered = [n for n in schema_fields if n in cred["fields"]]
    leaves = [cu.leaf_hash(n, cred["salts"][n], cred["fields"][n]) for n in ordered]
    _root, proofs = cu.build_merkle_tree(leaves)

    disclosed = []
    for idx, name in enumerate(ordered):
        if name not in disclose_fields:
            continue
        disclosed.append({
            "name": name,
            "value": cred["fields"][name],
            "salt": cred["salts"][name],
            "proof": [[pos, sib] for pos, sib in proofs[idx]],
        })

    key = get_key(cred["header"]["kid"])
    return {
        "header": cred["header"],
        "signature": cred["signature"],
        "issuer_public_key": key["public_key"] if key else None,
        "disclosed_fields": disclosed,
    }


# ================================================================ 验证

def verify_presentation(presentation: dict) -> dict:
    """逐项校验：密钥登记、签名、模板版本、有效期、撤销列表、Merkle 证明。"""
    checks = {
        "key_registered": False,
        "signature": False,
        "template_version": False,
        "validity_period": False,
        "not_revoked": False,
        "merkle_proofs": False,
    }
    failures: list[str] = []
    disclosed: dict[str, Any] = {}
    header = presentation.get("header") or {}

    cred_id = header.get("credential_id")
    tpl_name = header.get("template_name")
    tpl_ver = header.get("template_version")

    # 1. 密钥已登记（轮换后旧密钥仍在册，历史凭证可验证）
    key = get_key(header.get("kid") or "")
    if key is None:
        failures.append(f"签名密钥未登记: {header.get('kid')}")
    else:
        if presentation.get("issuer_public_key") and \
                presentation["issuer_public_key"] != key["public_key"]:
            failures.append("presentation 携带的公钥与登记公钥不一致")
        else:
            checks["key_registered"] = True

    # 2. 签名
    if key is not None:
        if cu.verify_signature(key["public_key"], cu.canonical_json(header),
                               presentation.get("signature") or ""):
            checks["signature"] = True
        else:
            failures.append("签名验证失败")

    # 3. 模板版本与模板哈希
    tpl = get_template(tpl_name, tpl_ver) if tpl_name and tpl_ver else None
    if tpl is None:
        failures.append(f"模板版本不存在: {tpl_name} v{tpl_ver}")
    elif tpl["schema_hash"] != header.get("template_hash"):
        failures.append("模板哈希不匹配：模板内容已被修改")
    else:
        checks["template_version"] = True

    # 4. 有效期
    try:
        now = datetime.now(timezone.utc)
        nb = _parse_iso(header["not_before"])
        exp = _parse_iso(header["expires_at"])
        if nb <= now <= exp:
            checks["validity_period"] = True
        else:
            failures.append(f"凭证不在有效期内 (now={now_iso()}, "
                            f"not_before={header['not_before']}, expires_at={header['expires_at']})")
    except (KeyError, ValueError):
        failures.append("凭证头缺少合法的有效期字段")

    # 5. 按版本生效的撤销列表
    if tpl_name and tpl_ver and cred_id:
        if is_revoked(tpl_name, tpl_ver, cred_id):
            failures.append(f"凭证已被撤销 (模板 {tpl_name} v{tpl_ver} 的撤销列表)")
        else:
            checks["not_revoked"] = True
    else:
        failures.append("凭证头缺少模板或凭证标识，无法检查撤销列表")

    # 6. Merkle 证明：每个披露字段重算叶子并沿路径验证到根
    schema_names = {f["name"] for f in tpl["schema"]["fields"]} if tpl else None
    merkle_ok = True
    for item in presentation.get("disclosed_fields") or []:
        name = item.get("name")
        if schema_names is not None and name not in schema_names:
            failures.append(f"披露字段不在模板中: {name}")
            merkle_ok = False
            continue
        try:
            leaf = cu.leaf_hash(name, item["salt"], item["value"])
            proof = [(p, s) for p, s in item["proof"]]
        except (KeyError, TypeError):
            failures.append(f"披露字段 {name} 的证明数据不完整")
            merkle_ok = False
            continue
        if cu.verify_merkle_proof(leaf, proof, header.get("merkle_root") or ""):
            disclosed[name] = item["value"]
        else:
            failures.append(f"字段 {name} 的 Merkle 证明无效")
            merkle_ok = False
    if merkle_ok:
        checks["merkle_proofs"] = True

    return {
        "result": "valid" if all(checks.values()) else "invalid",
        "checks": checks,
        "failures": failures,
        "disclosed_fields": disclosed,
        "credential_id": cred_id,
        "template_name": tpl_name,
        "template_version": tpl_ver,
    }


# ================================================================ 审计链（幂等写入）

GENESIS_HASH = "0" * 64


def _audit_hash(payload: dict) -> str:
    return cu.sha256_hex(b"audit:" + cu.canonical_json(payload))


def record_audit(idempotency_key: str, verification: dict) -> tuple[dict, bool]:
    """以幂等键写入审计。重复/并发提交返回既有记录，created=False。

    审计记录构成哈希链：hash = SHA256("audit:" || canonical(含 prev_hash 的内容))。
    """
    db = get_db()
    existing = db.execute(
        "SELECT * FROM audits WHERE idempotency_key=?", (idempotency_key,)
    ).fetchone()
    if existing is not None:
        return _audit_dict(existing), False

    created_at = now_iso()
    db.execute("BEGIN IMMEDIATE")
    try:
        # 在写事务内重查，保证并发下只有一个写入者
        existing = db.execute(
            "SELECT * FROM audits WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing is not None:
            db.commit()
            return _audit_dict(existing), False

        last = db.execute("SELECT hash FROM audits ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["hash"] if last else GENESIS_HASH
        payload = {
            "prev_hash": prev_hash,
            "idempotency_key": idempotency_key,
            "credential_id": verification.get("credential_id"),
            "template_name": verification.get("template_name"),
            "template_version": verification.get("template_version"),
            "result": verification["result"],
            "checks": verification["checks"],
            "disclosed_fields": verification["disclosed_fields"],
            "failures": verification["failures"],
            "created_at": created_at,
        }
        h = _audit_hash(payload)
        try:
            db.execute(
                "INSERT INTO audits(idempotency_key, credential_id, template_name,"
                " template_version, result, checks_json, disclosed_json, failures_json,"
                " created_at, prev_hash, hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (idempotency_key, verification.get("credential_id"),
                 verification.get("template_name"), verification.get("template_version"),
                 verification["result"], json.dumps(verification["checks"]),
                 json.dumps(verification["disclosed_fields"], ensure_ascii=False),
                 json.dumps(verification["failures"], ensure_ascii=False),
                 created_at, prev_hash, h),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # 并发竞争者已写入同一幂等键
            db.rollback()
            row = db.execute(
                "SELECT * FROM audits WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            return _audit_dict(row), False
    except Exception:
        db.rollback()
        raise

    row = db.execute("SELECT * FROM audits WHERE idempotency_key=?", (idempotency_key,)).fetchone()
    return _audit_dict(row), True


def list_audits() -> list[dict]:
    rows = get_db().execute("SELECT * FROM audits ORDER BY id").fetchall()
    return [_audit_dict(r) for r in rows]


def verify_audit_chain() -> dict:
    """重放整条审计哈希链，返回首个断链位置（若有）。"""
    rows = get_db().execute("SELECT * FROM audits ORDER BY id").fetchall()
    prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != prev:
            return {"valid": False, "broken_at": row["id"],
                    "detail": f"审计 #{row['id']} 的 prev_hash 与上一条不匹配"}
        payload = {
            "prev_hash": row["prev_hash"],
            "idempotency_key": row["idempotency_key"],
            "credential_id": row["credential_id"],
            "template_name": row["template_name"],
            "template_version": row["template_version"],
            "result": row["result"],
            "checks": json.loads(row["checks_json"]),
            "disclosed_fields": json.loads(row["disclosed_json"]),
            "failures": json.loads(row["failures_json"]),
            "created_at": row["created_at"],
        }
        if _audit_hash(payload) != row["hash"]:
            return {"valid": False, "broken_at": row["id"],
                    "detail": f"审计 #{row['id']} 的内容哈希被篡改"}
        prev = row["hash"]
    return {"valid": True, "length": len(rows),
            "head": rows[-1]["hash"] if rows else None}


def _audit_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "idempotency_key": row["idempotency_key"],
        "credential_id": row["credential_id"],
        "template_name": row["template_name"],
        "template_version": row["template_version"],
        "result": row["result"],
        "checks": json.loads(row["checks_json"]),
        "disclosed_fields": json.loads(row["disclosed_json"]),
        "failures": json.loads(row["failures_json"]),
        "created_at": row["created_at"],
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
    }
