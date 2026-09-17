"""持有者：从凭证生成选择性披露 presentation。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import service

router = APIRouter(prefix="/api/holder", tags=["holder"])


class PresentationIn(BaseModel):
    credential_id: str
    disclose_fields: list[str] = Field(min_length=1)


@router.post("/presentations")
def build_presentation(body: PresentationIn):
    try:
        return service.build_presentation(body.credential_id, body.disclose_fields)
    except ValueError as e:
        raise HTTPException(400, str(e))
