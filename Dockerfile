FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SDV_DB_PATH=/data/verifier.db

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY offline_verify.py ./

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# 容器启动时自动建表并写入演示种子（SDV_SEED=1），然后启动 API + 静态页面
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
