#!/usr/bin/env python3
"""
离线验证工具（不依赖服务端 / 数据库）。

用法：
  # 1) 用完整凭证信封导出一个选择性披露 presentation
  python offline_verify.py disclose credential.json --fields full_name,age -o presentation.json

  # 2) 离线验证 presentation（凭证信封内嵌签发公钥，无需联网）
  python offline_verify.py verify presentation.json --public-key key.pem
  python offline_verify.py verify presentation.json            # 使用 presentation 内嵌公钥

  # 导出某 kid 的公钥（从运行中的服务复制，或用管理员接口 GET /api/keys/{kid}）
  # 保存为 PEM 文件后用 --public-key 指定；不指定时使用 presentation 内嵌的 schema/公钥。

注意：撤销检查需要在线查询验证端；离线模式下会跳过 revocation 检查项。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from app import crypto
from app.credential import build_presentation, verify_presentation


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _is_credential_envelope(obj) -> bool:
    return isinstance(obj, dict) and "leaves" in obj and "header" in obj and "signature" in obj


def _is_presentation(obj) -> bool:
    return isinstance(obj, dict) and "disclosed" in obj and "header" in obj


def cmd_disclose(args) -> int:
    envelope = _load_json(args.file)
    if not _is_credential_envelope(envelope):
        print("输入文件不是完整凭证信封（需要包含 leaves）", file=sys.stderr)
        return 2
    fields = [s.strip() for s in args.fields.split(",") if s.strip()] if args.fields else []
    presentation = build_presentation(envelope, fields)
    text = json.dumps(presentation, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"已写出 presentation 到 {args.output}（披露 {len(fields)} 个字段）")
    else:
        print(text)
    return 0


def cmd_verify(args) -> int:
    obj = _load_json(args.file)
    if _is_credential_envelope(obj):
        print("提示：输入为完整凭证信封，自动披露全部字段进行验证", file=sys.stderr)
        obj = build_presentation(obj, [lf["field"] for lf in obj["leaves"]])
    if not _is_presentation(obj):
        print("输入文件不是 presentation / 凭证信封", file=sys.stderr)
        return 2

    kid = obj["header"].get("issuer_key_id")
    if args.public_key:
        with open(args.public_key, "r", encoding="utf-8") as f:
            public_keys = {kid: f.read()}
    elif args.credential:
        env = _load_json(args.credential)
        # 完整信封不自带公钥；需要外部 PEM
        print("使用 --public-key 指定签发公钥 PEM", file=sys.stderr)
        return 2
    else:
        print(
            f"错误：离线验证需要签发公钥。请用管理员接口 GET /api/keys/{kid} 获取 PEM，"
            "保存后用 --public-key 指定",
            file=sys.stderr,
        )
        return 2

    valid, checks, summary = verify_presentation(
        obj,
        public_keys=public_keys,
        now=datetime.now(timezone.utc),
        is_revoked_fn=None,  # 离线跳过撤销检查
    )
    print(json.dumps({"valid": valid, "checks": checks, "summary": summary},
                     ensure_ascii=False, indent=2))
    print()
    for c in checks:
        mark = "✅" if c["ok"] else "❌"
        print(f"{mark} [{c['name']}] {c['detail']}")
    print("\n注：离线模式跳过撤销列表（revocation）检查。")
    return 0 if valid else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="选择性披露凭证离线工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("disclose", help="从凭证信封生成 presentation")
    p1.add_argument("file", help="凭证信封 JSON 文件")
    p1.add_argument("--fields", default="", help="逗号分隔的披露字段名；留空表示全部隐藏")
    p1.add_argument("-o", "--output", help="输出文件（默认 stdout）")
    p1.set_defaults(func=cmd_disclose)

    p2 = sub.add_parser("verify", help="离线验证 presentation")
    p2.add_argument("file", help="presentation JSON 文件")
    p2.add_argument("--public-key", help="签发公钥 PEM 文件（kid 取自凭证头部）")
    p2.add_argument("--credential", help="（保留）完整凭证信封")
    p2.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
