"""验证端：校验 presentation 并以幂等键写入审计链。"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from .. import service

router = APIRouter(prefix="/api", tags=["verifier"])


class VerifyIn(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=128)
    presentation: dict


@router.post("/verify")
def verify(body: VerifyIn):
    """验证 presentation。同一幂等键的重复/并发提交只产生一条审计记录。"""
    verification = service.verify_presentation(body.presentation)
    audit, created = service.record_audit(body.idempotency_key, verification)
    return {
        "deduplicated": not created,
        "audit": audit,
        "result": audit["result"],
        "checks": audit["checks"],
        "failures": audit["failures"],
        "disclosed_fields": audit["disclosed_fields"],
    }


@router.get("/audits")
def list_audits():
    return service.list_audits()


@router.get("/audits/verify-chain")
def verify_chain():
    return service.verify_audit_chain()
