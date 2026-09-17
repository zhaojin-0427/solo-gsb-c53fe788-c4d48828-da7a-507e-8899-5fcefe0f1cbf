"""选择性披露凭证验证台 — FastAPI 入口。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import init_db
from .routers import admin, holder, issuer, verifier
from .service import ensure_active_key

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_active_key()  # 无任何密钥时生成首把签名密钥
    yield


app = FastAPI(title="选择性披露凭证验证台", version="1.0.0", lifespan=lifespan)


app.include_router(admin.router)
app.include_router(issuer.router)
app.include_router(holder.router)
app.include_router(verifier.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
