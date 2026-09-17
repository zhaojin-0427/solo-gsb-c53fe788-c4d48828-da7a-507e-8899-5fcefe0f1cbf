"""管理端：凭证模板、密钥轮换、按版本生效的撤销列表。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import service

router = APIRouter(prefix="/api/admin", tags=["admin"])


class TemplateIn(BaseModel):
    name: str = Field(min_length=1)
    fields: list[dict]


@router.post("/templates")
def create_template(body: TemplateIn):
    try:
        return service.create_template(body.name.strip(), body.fields)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/templates")
def list_templates():
    return service.list_templates()


@router.get("/templates/{name}/{version}")
def get_template(name: str, version: int):
    tpl = service.get_template(name, version)
    if tpl is None:
        raise HTTPException(404, "模板不存在")
    return tpl


class TemplateStatusIn(BaseModel):
    status: str


@router.post("/templates/{name}/{version}/status")
def set_template_status(name: str, version: int, body: TemplateStatusIn):
    try:
        tpl = service.set_template_status(name, version, body.status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if tpl is None:
        raise HTTPException(404, "模板不存在")
    return tpl


@router.post("/keys/rotate")
def rotate_key():
    return service.rotate_key()


@router.get("/keys")
def list_keys():
    return service.list_keys()


class RevocationIn(BaseModel):
    template_name: str
    template_version: int
    credential_id: str = Field(description="凭证 ID，或 '*' 撤销该版本全部凭证")
    reason: str = ""


@router.post("/revocations")
def revoke(body: RevocationIn):
    try:
        return service.revoke(body.template_name, body.template_version,
                              body.credential_id.strip(), body.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/revocations")
def list_revocations(template_name: str | None = None, template_version: int | None = None):
    return service.list_revocations(template_name, template_version)
