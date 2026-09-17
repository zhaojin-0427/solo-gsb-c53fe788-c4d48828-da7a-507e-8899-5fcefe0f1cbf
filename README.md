# 选择性披露凭证验证台

基于 **FastAPI + SQLite + 原生 JavaScript** 的最小可用凭证平台：管理员定义带类型/必填约束的
凭证模板并轮换 Ed25519 密钥；签发端为每个字段建立 Merkle 承诺并签发可离线验证的凭证；
持有者只披露指定字段及证明路径；验证端校验签名、模板版本、有效期与按版本生效的撤销列表，
并以幂等键写入可校验的审计链。

## 快速启动（Docker Compose）

```bash
docker compose up --build
```

启动后访问：

| 入口 | 地址 |
|---|---|
| Web 控制台 | http://localhost:8000 |
| API 文档（Swagger） | http://localhost:8000/docs |
| 健康检查 | http://localhost:8000/api/health |

SQLite 数据（密钥、模板、凭证、审计链）持久化在名为 `sdc-data` 的卷中，删除卷即重置全部状态。

### 本地开发（不用 Docker）

```bash
cd backend
pip install -r requirements.txt
DB_PATH=app.db uvicorn app.main:app --reload --port 8000
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `DB_PATH` | 容器内 `/data/app.db`，本地 `app.db` | SQLite 数据库文件路径 |

首次启动自动初始化表结构，并在没有任何签名密钥时生成首把 Ed25519 密钥。

## 使用流程（对应页面四个页签）

1. **管理台**：创建凭证模板（字段名 / 类型 `string·integer·number·boolean·date·enum` /
   必填约束，同名模板版本自动递增）；轮换 Ed25519 密钥（旧密钥转 `retired`，仅用于验证）；
   维护按 `(模板, 版本)` 生效的撤销列表（凭证 ID 或 `*` 表示整版撤销）。
2. **签发端**：选择模板版本，按 schema 渲染表单，类型与必填校验通过后签发。
   每个字段独立加盐生成叶子 `SHA256("leaf:"‖name‖salt‖value)`，Merkle 根与凭证头
   （模板哈希、有效期、kid 等）一起由当前密钥签名。
3. **持有者**：加载凭证，勾选要披露的字段，生成 presentation —— 仅含这些字段的
   明文、盐与 Merkle 证明路径，外加签名头与签发方公钥，可下载 JSON 离线验证。
4. **验证台**：粘贴 presentation，携带幂等键提交。页面展示六项检查结果、已披露字段；
   「并发提交 ×5」可演示同一幂等键并发请求只落一条审计；审计链表格可一键重放校验。

## 验证端检查项

| 检查 | 内容 |
|---|---|
| `key_registered` | 签名密钥已登记；轮换后旧密钥仍在册，历史凭证可验证 |
| `signature` | Ed25519 签名对凭证头（规范 JSON）有效 |
| `template_version` | 模板版本存在且 schema 哈希与签发时一致 |
| `validity_period` | 当前时间处于 `not_before ~ expires_at` |
| `not_revoked` | 不在该模板版本的撤销列表中（支持整版 `*` 撤销） |
| `merkle_proofs` | 每个披露字段的叶子与路径可汇聚到签名头中的 Merkle 根 |

## 幂等与审计链

- `POST /api/verify` 请求体携带 `idempotency_key`；审计表对该键有唯一约束，
  重复或并发提交命中既有记录并返回 `deduplicated: true`，不会重复写入。
- 每条审计记录包含 `prev_hash` 与
  `hash = SHA256("audit:"‖canonical(含 prev_hash 的全部内容))`，构成哈希链；
  `GET /api/audits/verify-chain` 重放全链并报告首个断点。

## 离线验证

presentation 自包含密码学证据（签名头、签名、签发方公钥、披露字段的盐与 Merkle 路径）：

```bash
python3 scripts/verify_offline.py presentation.json
```

离线可校验签名、Merkle 证明与有效期；撤销列表与密钥登记状态属于服务端动态状态，
需在线调用 `POST /api/verify` 完成完整校验。

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/admin/templates` | 创建模板新版本 |
| GET | `/api/admin/templates` | 模板列表 |
| POST | `/api/admin/templates/{name}/{version}/status` | 停用/启用模板版本 |
| POST | `/api/admin/keys/rotate` | 轮换签名密钥 |
| GET | `/api/admin/keys` | 密钥列表（含已退役） |
| POST | `/api/admin/revocations` | 添加撤销记录（按版本生效） |
| GET | `/api/admin/revocations` | 撤销列表 |
| POST | `/api/issuer/credentials` | 签发凭证 |
| GET | `/api/issuer/credentials[/{id}]` | 凭证列表/详情 |
| POST | `/api/holder/presentations` | 生成选择性披露 presentation |
| POST | `/api/verify` | 验证（幂等键去重，写审计链） |
| GET | `/api/audits` | 审计列表 |
| GET | `/api/audits/verify-chain` | 校验审计链完整性 |

## 项目结构

```
├── docker-compose.yml        # 单服务编排，卷持久化 SQLite
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py           # FastAPI 入口，托管静态页面
│       ├── db.py             # SQLite（WAL）连接与建表
│       ├── crypto_utils.py   # Ed25519、Merkle 树、规范 JSON
│       ├── service.py        # 模板/密钥/签发/披露/验证/审计链
│       ├── routers/          # admin / issuer / holder / verifier
│       └── static/           # 原生 JS 单页控制台
└── scripts/verify_offline.py # 离线验证脚本
```
