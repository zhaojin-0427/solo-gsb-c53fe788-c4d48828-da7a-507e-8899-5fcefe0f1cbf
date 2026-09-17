"""模板字段类型与必填约束校验。"""
from __future__ import annotations

from typing import Any

ALLOWED_TYPES = {"string", "integer", "number", "boolean", "date"}

TYPE_NAMES_ZH = {
    "string": "字符串",
    "integer": "整数",
    "number": "数字",
    "boolean": "布尔",
    "date": "日期(YYYY-MM-DD)",
}


class SchemaError(ValueError):
    pass


def validate_schema_definition(schema: Any) -> list[dict[str, Any]]:
    """
    校验模板定义本身，返回规范化的字段列表：
    [{"name": str, "type": str, "required": bool}, ...]
    """
    if not isinstance(schema, list) or not schema:
        raise SchemaError("schema 必须是非空字段数组")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, field in enumerate(schema):
        if not isinstance(field, dict):
            raise SchemaError(f"第 {i + 1} 个字段必须是对象")
        name = field.get("name")
        ftype = field.get("type")
        if not isinstance(name, str) or not name.strip():
            raise SchemaError(f"第 {i + 1} 个字段缺少有效 name")
        name = name.strip()
        if name in seen:
            raise SchemaError(f"字段名重复: {name}")
        seen.add(name)
        if ftype not in ALLOWED_TYPES:
            raise SchemaError(f"字段 {name} 的 type 必须是 {sorted(ALLOWED_TYPES)}")
        normalized.append(
            {"name": name, "type": ftype, "required": bool(field.get("required", False))}
        )
    return normalized


def _is_date(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 10:
        return False
    if value[4] != "-" or value[7] != "-":
        return False
    from datetime import date

    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def validate_value(name: str, ftype: str, value: Any) -> str | None:
    """校验单个值的类型；返回错误信息（None 表示通过）。"""
    if value is None:
        return f"字段 {name} 的值为 null"
    if ftype == "string":
        if not isinstance(value, str):
            return f"字段 {name} 应为字符串"
    elif ftype == "integer":
        # bool 是 int 的子类，需显式排除
        if isinstance(value, bool) or not isinstance(value, int):
            return f"字段 {name} 应为整数"
    elif ftype == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"字段 {name} 应为数字"
    elif ftype == "boolean":
        if not isinstance(value, bool):
            return f"字段 {name} 应为布尔值"
    elif ftype == "date":
        if not _is_date(value):
            return f"字段 {name} 应为 YYYY-MM-DD 日期"
    return None


def validate_claims(schema_fields: list[dict[str, Any]], claims: dict[str, Any]) -> str | None:
    """签发时校验：必填字段必须存在且类型正确；非必填字段可缺省但类型须正确。"""
    by_name = {f["name"]: f for f in schema_fields}

    extra = set(claims) - set(by_name)
    if extra:
        return f"存在模板之外的字段: {sorted(extra)}"

    for field in schema_fields:
        name, ftype = field["name"], field["type"]
        if name not in claims:
            if field["required"]:
                return f"必填字段缺失: {name}"
            continue
        err = validate_value(name, ftype, claims[name])
        if err:
            return err
    return None
