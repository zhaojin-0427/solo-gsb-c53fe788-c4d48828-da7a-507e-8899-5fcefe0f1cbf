# 🔏 选择性披露凭证验证台（Selective Disclosure Credential Verifier）

一个完整的可验证凭证（VC）演示系统：管理员定义**带类型与必填约束**的凭证模板并轮换
**Ed25519** 签名密钥；签发端为**每个字段建立 Merkle 承诺**并生成可离线保存的凭证；持有者只披露
指定字段及 Merkle 证明路径；验证端校验 **签名、模板版本、有效期、按版本生效的撤销列表**，
密钥轮换后仍可验证历史凭证。验证请求带**幂等键**，重复或并发提交只写一条审计，所有验证形成
**可逐条重放校验的哈希链**。

- **后端**：Python 3.12 · FastAPI · SQLite（WAL 模式）
- **前端**：原生 HTML/CSS/JavaScript（无框架、无构建步骤）
- **密码学**：Ed25519（RFC 8032）+ SHA-256 字段级 Merkle 树
- **部署**：Docker Compose，单卷持久化

---

## 一、快速开始（Docker Compose）

```bash
docker compose up --build
```

启动后访问：

| 入口 | 地址 |
| --- | --- |
| 演示页面 | http://localhost:8000/ |
| API 文档（Swagger） | http://localhost:8000/docs |
| 健康检查 | http://localhost:8000/api/health |

数据保存在 Docker 卷 `sdv-data`（容器内 `/data/verifier.db`）。首次启动自动写入演示数据：

- 签名密钥 `k1`（Ed25519，标记为生效）
- 模板 `tpl_demo`（演示会员凭证 v1）：
  `full_name:string*`、`age:integer*`、`email:string`、`is_vip:boolean`、`member_since:date`（`*` 必填）

重置数据：

```bash
docker compose down -v   # 删除数据卷
docker compose up --build
```

### 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SDV_DB_PATH` | `/data/verifier.db` | SQLite 文件路径 |
| `SDV_SEED` | `1` | 首次启动是否写入演示密钥与模板 |

---

## 二、功能操作流程

页面分六个标签页，对应四个角色 + 审计 + 离线说明：

1. **① 管理员**
   - 「轮换生成新密钥」：生成新 Ed25519 密钥并停用旧密钥（旧密钥保留在库中，历史凭证照常验证）。
   - 新建模板：逐字段指定 `name` / `type`（`string | integer | number | boolean | date`）/ 是否必填。
   - 「发布新版本」：在已有模板上修改约束并升版本；已签发凭证锁定其签发时的模板版本。
   - 撤销：输入凭证 ID，将其加入**该模板当前（或指定）版本生效的撤销列表**。
2. **② 签发端**：选择模板、填写字段（必填缺失或类型错误会被拒绝）、设置有效期后签发。
   系统为每字段生成随机盐与叶子承诺 `SHA256(0x00‖canonical_json({field,value,type,salt}))`，
   对包含 Merkle 根的头部进行 Ed25519 签名。可直接「发送到持有者钱包」或下载凭证信封 JSON。
3. **③ 持有者钱包**：从下拉列表载入服务端凭证，或**导入离线凭证信封 JSON**；勾选要披露的字段，
   浏览器本地（Web Crypto）重算 Merkle 根自检并生成 presentation（未勾选字段不出现任何明文/盐）。
4. **④ 验证端**：粘贴 presentation，带自动生成的 `Idempotency-Key` 提交。
   - 「用同键重放」：第二次请求返回同一审计行并标记重复；
   - 「并发 5 次同键压测」：5 个并发请求只产生一条审计；
   - 结果页展示逐项检查、已披露字段明文与承诺/类型校验、隐藏字段数量、审计链 hash。
5. **⑤ 审计链**：服务端按写入顺序重放 `chain_hash = SHA256(prev_hash ‖ 本条内容)`，
   逐环显示链接是否成立；任何对历史审计的篡改都会导致校验失败。
6. **⑥ 离线验证**：命令行离线使用说明（见下节）。

### 验证端检查项

| 检查 | 说明 |
| --- | --- |
| `structure` / `header_fields` | presentation 与签名头部结构完整 |
| `signature` | 用头部 `issuer_key_id` 找对应版本公钥验 Ed25519（轮换后的旧公钥仍保留） |
| `template_version` | 头部版本与内嵌模式版本一致；另提示是否为当前最新模板版本 |
| `validity_period` | 当前 UTC 时间在 `valid_from ~ valid_until` 区间内 |
| `revocation` | 凭证 ID **不在按其模板版本生效的撤销列表**中 |
| `merkle_proofs` / `disclosure_fields` | 每个披露字段重算叶子承诺并用证明路径折叠到签名根；类型与模板一致；无重复披露 |

---

## 三、离线验证

凭证信封自包含（签名头部、字段值与盐、模板版本定义），可导出离线保存。
`offline_verify.py` 只依赖 `cryptography`，可在无服务端环境运行：

```bash
pip install -r requirements.txt

# 用完整凭证信封生成只披露 full_name、age 的 presentation
python offline_verify.py disclose credential.json --fields full_name,age -o presentation.json

# 取签发公钥（密钥轮换后用凭证头部的 issuer_key_id 取历史公钥）
curl -s http://localhost:8000/api/keys/k1 | python -c "import sys,json;open('key.pem','w').write(json.load(sys.stdin)['public_pem'])"

# 离线验证（输出与在线验证一致的检查项）
python offline_verify.py verify presentation.json --public-key key.pem
```

> 离线模式下跳过在线撤销列表检查（终端会明确提示）；签名、模板版本、有效期、Merkle 路径全部本地完成。

---

## 四、HTTP API 摘要

所有接口前缀 `/api`，JSON 请求/响应：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/keys/rotate` | 轮换 Ed25519 密钥 |
| GET | `/keys` · `/keys/{kid}` | 密钥列表 · 指定版本公钥 PEM |
| POST | `/templates` | 创建模板（v1） |
| POST | `/templates/{id}/versions` | 发布模板新版本 |
| GET | `/templates` · `/templates/{id}/versions/{v}` | 模板列表 · 指定版本定义 |
| POST | `/issue` | 签发凭证（body: `template_id, claims, valid_days, disclose?`） |
| GET | `/credentials` · `/credentials/{id}` | 凭证列表 · 完整信封 |
| POST | `/presentations` | 服务端辅助生成 presentation |
| POST | `/revoke` | 加入按版本生效的撤销列表（body: `credential_id, reason?, version?`） |
| GET | `/revocations` | 撤销列表 |
| **POST** | **`/verify`** | **验证 presentation，必须带请求头 `Idempotency-Key: <随机串>`** |
| GET | `/audits` · `/audits/chain` | 审计列表 · 哈希链重放校验 |

`curl` 示例：

```bash
# 签发
curl -s -X POST localhost:8000/api/issue -H 'Content-Type: application/json' -d '{
  "template_id":"tpl_demo",
  "claims":{"full_name":"张三","age":28,"email":"zs@example.com","is_vip":true,"member_since":"2024-03-01"},
  "disclose":["full_name","age"]
}'

# 幂等验证：同一 Idempotency-Key 重复/并发提交只产生一条审计
curl -s -X POST localhost:8000/api/verify \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: demo-key-001' \
  --data-binary @presentation.json
```

---

## 五、设计说明

### 凭证信封（`credential`，签发端/持有者保存）

```jsonc
{
  "header": {
    "credential_id": "cred_…",
    "template_id": "tpl_demo",
    "template_version": 1,          // 锁定签发时版本
    "issuer_key_id": "k1",          // 轮换后据此找历史公钥
    "valid_from": "…Z", "valid_until": "…Z",
    "merkle_root": "<hex>",         // 全部字段承诺的根
    "leaf_count": 5
  },
  "signature": "<Ed25519 over canonical_json(header)>",
  "schema_version": { "template_id": "…", "version": 1, "schema": [ … 类型/必填定义 … ] },
  "leaves": [ { "field","value","salt","type","index" }, … ]
}
```

### Presentation（持有者 → 验证端）

```jsonc
{
  "header": { … 同上，连同签名原样出示 … },
  "signature": "<hex>",
  "schema_version": { … },
  "disclosed": [
    { "field":"full_name", "value":"张三", "salt":"<hex>", "type":"string",
      "proof": [ {"side":"left|right","hash":"<hex>"}, … ] }
  ]
}
```

- 叶子：`SHA256(0x00 ‖ canonical_json({field, salt, type, value}))`，每字段独立随机盐，防字典猜测；
  未披露字段的字段名与值均不离开持有者。
- 内部节点：`SHA256(0x01 ‖ left ‖ right)`；奇数节点直接提升（不复制哈希）。
- 浏览器 `app.js` 与 Python 端使用**逐字节一致**的 canonical JSON（键排序、紧凑分隔、`ensure_ascii=False`），
  因此 presentation 可完全离线在浏览器端构造。
- 审计链：`chain_hash_n = SHA256(prev_hash ‖ canonical_json({idem_key, request_hash, valid, credential_id, checks}))`，
  创世前驱为字符串 `GENESIS`。幂等通过 `verifications.idem_key` 唯一约束 + `BEGIN IMMEDIATE` 事务实现：
  并发请求中唯一插入胜出者执行验证，其余请求等待并复用同一结果。

### 目录结构

```
.
├── docker-compose.yml          # 一键启动（端口 8000，卷 sdv-data）
├── Dockerfile
├── requirements.txt
├── offline_verify.py           # 离线 disclose / verify CLI
├── README.md
└── app/
    ├── main.py                 # FastAPI 路由：管理/签发/撤销/幂等验证/审计链
    ├── credential.py           # 签发、presentation 构造、纯函数验证逻辑
    ├── crypto.py               # Ed25519、canonical JSON、Merkle 树/证明
    ├── typeschema.py           # 字段类型与必填约束
    ├── db.py                   # SQLite schema、种子数据、事务辅助
    └── static/                 # 原生 JS 单页前端
        ├── index.html
        ├── app.js
        └── style.css
```
