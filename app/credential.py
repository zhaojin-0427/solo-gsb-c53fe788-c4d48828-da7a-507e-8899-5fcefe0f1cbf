"""凭证签发 / 选择性披露展示 / 验证 的核心逻辑（纯函数，便于离线脚本复用）。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from . import crypto
from .typeschema import validate_value


class VerifiableError(Exception):
    """验证失败，携带检查项明细。"""

    def __init__(self, message: str, checks: list[dict[str, Any]]):
        super().__init__(message)
        self.checks = checks


def _parse_iso8601(value: str) -> datetime:
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def issue_credential(
    *,
    template_id: str,
    version: int,
    schema_fields: list[dict[str, Any]],
    claims: dict[str, Any],
    valid_from: str,
    valid_until: str,
    kid: str,
    private_pem: str,
) -> dict[str, Any]:
    """
    为每个字段建立 (salt, Merkle 叶子) 承诺，用 Ed25519 对承诺头部签名。
    返回可整体导出、离线保存的凭证信封。
    """
    leaves: list[tuple[str, bytes, str]] = []  # (field, leaf_hash, salt)
    for field in sorted(claims):
        ftype = next(f["type"] for f in schema_fields if f["name"] == field)
        salt = crypto.new_salt()
        leaf = crypto.leaf_commitment(field, claims[field], ftype, salt)
        leaves.append((field, leaf, salt))

    ordered = sorted(leaves, key=lambda x: x[0])
    root, levels = crypto.build_tree([h for _, h, _ in ordered])
    leaf_index = {name: i for i, (name, _, _) in enumerate(ordered)}

    credential_id = "cred_" + uuid4().hex
    header = {
        "credential_id": credential_id,
        "template_id": template_id,
        "template_version": version,
        "issuer_key_id": kid,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "merkle_root": root.hex(),
        "leaf_count": len(ordered),
    }
    signing_bytes = crypto.canonical_json(header)
    signature = crypto.sign(private_pem, signing_bytes)

    envelope: dict[str, Any] = {
        "header": header,
        "signature": signature.hex(),
        "schema_version": {
            "template_id": template_id,
            "version": version,
            "schema": schema_fields,
        },
        "leaves": [
            {
                "field": name,
                "salt": salt,
                "value": claims[name],
                "type": next(f["type"] for f in schema_fields if f["name"] == name),
                "index": leaf_index[name],
            }
            for (name, _h, salt) in ordered
        ],
    }
    return envelope


def build_presentation(envelope: dict[str, Any], disclose: list[str]) -> dict[str, Any]:
    """
    持有者构造选择性披露 presentation：
    被披露字段携带明文值+盐+路径；其余字段只存在于已签名的 merkle_root 中。
    """
    disclose_set = set(disclose)
    leaves = envelope["leaves"]
    ordered_hashes = [
        crypto.leaf_commitment(lf["field"], lf["value"], lf["type"], lf["salt"])
        for lf in leaves
    ]
    _root, levels = crypto.build_tree(ordered_hashes)

    disclosed = []
    for lf in leaves:
        if lf["field"] not in disclose_set:
            continue
        idx = lf["index"]
        disclosed.append(
            {
                "field": lf["field"],
                "value": lf["value"],
                "salt": lf["salt"],
                "type": lf["type"],
                "proof": crypto.build_proof(levels, idx),
            }
        )
    return {
        "header": envelope["header"],
        "signature": envelope["signature"],
        "schema_version": envelope["schema_version"],
        "disclosed": disclosed,
    }


def verify_presentation(
    presentation: dict[str, Any],
    *,
    public_keys: dict[str, str],
    now: datetime | None = None,
    is_revoked_fn=None,
    expect_template_version: int | None = None,
) -> tuple[bool, list[dict[str, Any]], dict[str, Any]]:
    """
    纯验证函数（不依赖数据库，可离线复用）。
    返回 (valid, checks, summary)。public_keys: {kid: public_pem}。
    is_revoked_fn(template_id, version, credential_id) -> bool；离线场景传 None。
    """
    now = now or datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, advisory: bool = False) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "advisory": advisory})

    # 1) 结构完整
    header = presentation.get("header")
    signature_hex = presentation.get("signature")
    disclosed = presentation.get("disclosed")
    schema_version = presentation.get("schema_version")
    structure_ok = all(
        [
            isinstance(header, dict),
            isinstance(signature_hex, str),
            isinstance(disclosed, list),
            isinstance(schema_version, dict) and isinstance(schema_version.get("schema"), list),
        ]
    )
    add("structure", structure_ok, "presentation 结构完整" if structure_ok else "presentation 缺少必要字段")
    if not structure_ok:
        return False, checks, {}

    required_header = [
        "credential_id",
        "template_id",
        "template_version",
        "issuer_key_id",
        "valid_from",
        "valid_until",
        "merkle_root",
        "leaf_count",
    ]
    missing = [k for k in required_header if k not in header]
    add("header_fields", not missing, "签名头部字段齐全" if not missing else f"头部缺失: {missing}")

    # 2) 签名（密钥轮换后用头部记录的 kid 找历史公钥）
    kid = header.get("issuer_key_id")
    pub_pem = public_keys.get(kid or "")
    sig_ok = False
    if not missing and pub_pem and signature_hex:
        try:
            sig_ok = crypto.verify_signature(
                pub_pem, bytes.fromhex(signature_hex), crypto.canonical_json(header)
            )
        except ValueError:
            sig_ok = False
    add(
        "signature",
        sig_ok,
        f"Ed25519 签名验证通过（密钥 {kid}）" if sig_ok else f"签名无效或密钥 {kid} 不存在",
    )

    # 3) 模板版本
    tpl_id = header.get("template_id")
    tpl_ver = header.get("template_version")
    embedded_id = schema_version.get("template_id")
    embedded_ver = schema_version.get("version")
    ver_match = embedded_id == tpl_id and embedded_ver == tpl_ver
    add(
        "template_version",
        ver_match,
        f"凭证基于模板 {tpl_id} v{tpl_ver}" if ver_match else "凭证头部与内嵌模板版本不一致",
    )
    if expect_template_version is not None:
        cur_ok = tpl_ver == expect_template_version
        add(
            "template_current",
            cur_ok,
            f"模板版本 {tpl_ver} 为当前要求版本" if cur_ok else f"模板已更新（凭证 v{tpl_ver}，当前 v{expect_template_version}）；历史凭证仍按 v{tpl_ver} 规则校验，不影响有效性",
            advisory=True,
        )

    # 4) 有效期
    time_ok = False
    time_detail = ""
    if not missing:
        try:
            vf = _parse_iso8601(header["valid_from"])
            vu = _parse_iso8601(header["valid_until"])
            if vf > vu:
                time_detail = "有效期区间非法（valid_from 晚于 valid_until）"
            elif now < vf:
                time_detail = f"凭证尚未生效（{header['valid_from']}）"
            elif now > vu:
                time_detail = f"凭证已过期（{header['valid_until']}）"
            else:
                time_ok = True
                time_detail = f"在有效期内（{header['valid_from']} ~ {header['valid_until']}）"
        except (ValueError, TypeError):
            time_detail = "有效期字段不是合法 ISO-8601 时间"
    add("validity_period", time_ok, time_detail)

    # 5) 撤销（按凭证声明的版本生效的撤销列表）
    cred_id = header.get("credential_id")
    if is_revoked_fn is not None:
        revoked = is_revoked_fn(tpl_id, tpl_ver, cred_id)
        add(
            "revocation",
            not revoked,
            f"撤销列表(template {tpl_id} v{tpl_ver}) 中无此凭证"
            if not revoked
            else f"凭证已在模板 v{tpl_ver} 的撤销列表中",
        )

    # 6) 每个披露字段：叶子承诺 + Merkle 路径 + 类型
    schema_by_name = {f["name"]: f for f in schema_version.get("schema", [])}
    proof_results = []
    seen_fields: set[str] = set()
    dup = False
    all_proof_ok = True
    for d in disclosed:
        field = d.get("field")
        if field in seen_fields:
            dup = True
        seen_fields.add(field)
        leaf = crypto.leaf_commitment(field, d.get("value"), d.get("type"), d.get("salt"))
        computed_root = crypto.fold_proof(leaf, d.get("proof", []))
        root_ok = computed_root.hex() == header.get("merkle_root")
        all_proof_ok = all_proof_ok and root_ok

        type_err = None
        sf = schema_by_name.get(field)
        if sf is None:
            type_err = f"字段 {field} 不在模板 v{tpl_ver} 中"
        elif sf["type"] != d.get("type"):
            type_err = f"字段 {field} 类型与模板不符（{d.get('type')} != {sf['type']}）"
        else:
            type_err = validate_value(field, sf["type"], d.get("value"))
        type_ok = type_err is None
        all_proof_ok = all_proof_ok and type_ok and not dup

        proof_results.append(
            {
                "field": field,
                "root_match": root_ok,
                "type_ok": type_ok,
                "type_detail": "类型正确" if type_ok else type_err,
            }
        )
    add(
        "disclosure_fields",
        not dup,
        "披露字段无重复" if not dup else "披露字段存在重复，拒绝验证",
    )
    add(
        "merkle_proofs",
        all_proof_ok,
        f"{len(disclosed)} 个披露字段的承诺与 Merkle 路径全部成立"
        if all_proof_ok
        else "存在披露字段的承诺/路径/类型校验失败",
    )

    # advisory（建议性）检查项不影响凭证有效性
    valid = all(c["ok"] for c in checks if not c.get("advisory"))

    hidden_count = header.get("leaf_count", 0) - len(disclosed)
    summary = {
        "credential_id": cred_id,
        "template_id": tpl_id,
        "template_version": tpl_ver,
        "issuer_key_id": kid,
        "disclosed_fields": sorted(seen_fields),
        "disclosed_values": {d.get("field"): d.get("value") for d in disclosed},
        "hidden_field_count": max(hidden_count, 0),
        "proof_results": proof_results,
        "verified_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return valid, checks, summary
