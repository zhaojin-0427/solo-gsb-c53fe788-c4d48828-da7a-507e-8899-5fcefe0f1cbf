"""密码学原语：Ed25519 签名、字段级 Merkle 承诺、规范 JSON 编码。

凭证的每个字段独立加盐生成叶子哈希：
    leaf = SHA256("leaf:" || field_name || 0x00 || salt || 0x00 || canonical_json(value))
内部节点：
    node = SHA256("node:" || left || right)
签名对象为凭证头（含 Merkle 根、模板哈希、有效期等）的规范 JSON。
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json(obj: Any) -> bytes:
    """确定性 JSON 编码：键排序、无空白、UTF-8。签名与哈希的统一输入。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_salt() -> str:
    return os.urandom(16).hex()


# ---------------------------------------------------------------- Ed25519

def generate_keypair() -> tuple[str, str]:
    """返回 (private_key_hex, public_key_hex)。"""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv, pub


def sign(private_key_hex: str, message: bytes) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return sk.sign(message).hex()


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- Merkle

def leaf_hash(field_name: str, salt: str, value: Any) -> str:
    payload = (
        b"leaf:"
        + field_name.encode("utf-8")
        + b"\x00"
        + salt.encode("utf-8")
        + b"\x00"
        + canonical_json(value)
    )
    return sha256_hex(payload)


def node_hash(left_hex: str, right_hex: str) -> str:
    return sha256_hex(b"node:" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def build_merkle_tree(leaf_hashes: list[str]) -> tuple[str, dict[int, list[tuple[str, str]]]]:
    """按给定顺序构建 Merkle 树。

    返回 (root_hex, proofs)；proofs[i] 为第 i 个叶子的证明路径，
    元素为 (position, sibling_hash)，position "L"/"R" 表示兄弟节点在左/右。
    奇数节点通过复制自身补齐，路径中同样记录。
    """
    if not leaf_hashes:
        return sha256_hex(b"empty"), {}

    level = list(leaf_hashes)
    proofs: dict[int, list[tuple[str, str]]] = {i: [] for i in range(len(level))}
    # groups[j] = 当前层第 j 个节点覆盖的所有原始叶子下标；
    # 节点合并时其下全部叶子都要追加高层路径，不能只跟踪代表下标
    groups = [[i] for i in range(len(level))]

    while len(level) > 1:
        next_level: list[str] = []
        next_groups: list[list[int]] = []
        for i in range(0, len(level), 2):
            left = level[i]
            if i + 1 < len(level):
                right = level[i + 1]
                for li in groups[i]:
                    proofs[li].append(("R", right))
                for ri in groups[i + 1]:
                    proofs[ri].append(("L", left))
                next_groups.append(groups[i] + groups[i + 1])
            else:
                right = left  # 奇数节点复制自身
                for li in groups[i]:
                    proofs[li].append(("R", right))
                next_groups.append(groups[i])
            next_level.append(node_hash(left, right))
        level = next_level
        groups = next_groups

    return level[0], proofs


def verify_merkle_proof(leaf_hex: str, proof: list[tuple[str, str]], root_hex: str) -> bool:
    h = leaf_hex
    for position, sibling in proof:
        if position == "R":
            h = node_hash(h, sibling)
        elif position == "L":
            h = node_hash(sibling, h)
        else:
            return False
    return h == root_hex
