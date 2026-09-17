"""
加密原语：Ed25519 签名 + 字段级 Merkle 承诺。

- Merkle 叶子 = SHA256(0x00 || canonical_json({field,value,type,salt}))
- Merkle 内部节点 = SHA256(0x01 || left_hash || right_hash)
- 奇数节点：提升最后一个节点到上一层（不复制哈希）
- canonical_json 使用紧凑 JSON，键按字典序排序，无空白；
  浏览器端 app.js 中的实现必须与此处保持逐字节一致。
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def canonical_json(obj: Any) -> bytes:
    """确定性 JSON 序列化：键排序、紧凑分隔符、ensure_ascii=False。"""
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def new_salt() -> str:
    """每字段一个 16 字节随机盐（hex 表示），防止字典猜测。"""
    return secrets.token_hex(16)


def generate_ed25519_keypair() -> tuple[str, str]:
    """返回 (private_pem, public_pem)，均为 PEM 文本（不含密码保护）。"""
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    assert isinstance(key, Ed25519PublicKey)
    return key


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def sign(private_pem: str, data: bytes) -> bytes:
    return load_private_key(private_pem).sign(data)


def verify_signature(public_pem: str, signature: bytes, data: bytes) -> bool:
    try:
        load_public_key(public_pem).verify(signature, data)
        return True
    except Exception:
        return False


def leaf_commitment(field: str, value: Any, field_type: str, salt: str) -> bytes:
    preimage = canonical_json(
        {"field": field, "salt": salt, "type": field_type, "value": value}
    )
    return sha256(LEAF_PREFIX + preimage)


def hash_node(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


def build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """
    输入按字段名排序后的叶子哈希列表；
    返回 (root, levels)，levels[0] 为叶子层，供生成证明路径。
    空列表的根为 32 字节 0x00。
    """
    if not leaves:
        return b"\x00" * 32, []
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        layer = levels[-1]
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(hash_node(layer[i], layer[i + 1]))
            else:
                nxt.append(layer[i])  # 奇数节点直接提升
        levels.append(nxt)
    return levels[-1][0], levels


def build_proof(levels: list[list[bytes]], index: int) -> list[dict[str, str]]:
    """
    生成某叶子的 Merkle 路径。
    每步 {"side": "left"|"right", "hash": hex}：
      side="left"  表示兄弟在左，当前值在右：parent = H(sibling || current)
      side="right" 表示兄弟在右，当前值在左：parent = H(current || sibling)
    """
    proof: list[dict[str, str]] = []
    idx = index
    for layer in levels[:-1]:
        if idx % 2 == 0:
            sib = idx + 1
            if sib < len(layer):
                proof.append({"side": "right", "hash": layer[sib].hex()})
        else:
            proof.append({"side": "left", "hash": layer[idx - 1].hex()})
        idx //= 2
    return proof


def fold_proof(leaf: bytes, proof: list[dict[str, str]]) -> bytes:
    """用证明路径把叶子哈希折叠成根。"""
    current = leaf
    for step in proof:
        sib = bytes.fromhex(step["hash"])
        if step["side"] == "left":
            current = hash_node(sib, current)
        else:
            current = hash_node(current, sib)
    return current
