"""签发端：按模板签发带 Merkle 承诺的可离线验证凭证。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import service

router = APIRouter(prefix="/api/issuer", tags=["issuer"])


class IssueIn(BaseModel):
    template_name: str
    template_version: int
    subject: str = Field(min_length=1)
    values: dict[str, Any]
    valid_days: int = Field(default=365, gt=0, le=3650)


@router.post("/credentials")
def issue(body: IssueIn):
    try:
        return service.issue_credential(
            body.template_name, body.template_version,
            body.subject, body.values, body.valid_days,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/credentials")
def list_credentials():
    return service.list_credentials()


@router.get("/credentials/{credential_id}")
def get_credential(credential_id: str):
    cred = service.get_credential(credential_id)
    if cred is None:
        raise HTTPException(404, "凭证不存在")
    return cred
