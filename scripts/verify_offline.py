#!/usr/bin/env python3
"""离线验证脚本：不依赖服务端，仅校验 presentation 的密码学证据。

校验内容（纯本地）：
  1. Ed25519 签名（使用 presentation 内携带的 issuer_public_key）
  2. 每个披露字段的 Merkle 证明路径是否汇聚到签名头中的 merkle_root
  3. 有效期窗口

注意：撤销列表与密钥登记状态属于服务端动态状态，离线无法校验，
     完整验证请使用 POST /api/verify。

用法: python3 scripts/verify_offline.py presentation.json
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app import crypto_utils as cu  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        p = json.load(f)

    header = p["header"]
    ok = True

    sig_ok = cu.verify_signature(
        p["issuer_public_key"], cu.canonical_json(header), p["signature"])
    print(f"[{'✓' if sig_ok else '✗'}] Ed25519 签名 (kid={header.get('kid')})")
    ok &= sig_ok

    for item in p.get("disclosed_fields", []):
        leaf = cu.leaf_hash(item["name"], item["salt"], item["value"])
        proof = [(pos, sib) for pos, sib in item["proof"]]
        proof_ok = cu.verify_merkle_proof(leaf, proof, header["merkle_root"])
        print(f"[{'✓' if proof_ok else '✗'}] Merkle 证明: {item['name']} = {json.dumps(item['value'], ensure_ascii=False)}")
        ok &= proof_ok

    now = datetime.now(timezone.utc)
    nb = datetime.fromisoformat(header["not_before"].replace("Z", "+00:00"))
    exp = datetime.fromisoformat(header["expires_at"].replace("Z", "+00:00"))
    time_ok = nb <= now <= exp
    print(f"[{'✓' if time_ok else '✗'}] 有效期 {header['not_before']} ~ {header['expires_at']}")
    ok &= time_ok

    print("\n结果:", "密码学证据有效（撤销状态需在线核验）" if ok else "验证失败")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
