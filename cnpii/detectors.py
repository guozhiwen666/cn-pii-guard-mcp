"""敏感信息识别与脱敏。

设计要点（也是本项目的核心技术取舍）：
1. 每类实体都用「边界断言」限定，避免把长数字串里的片段误判为证件号——
   这是脱敏工具最常见的误报来源。
2. 命中后调用 validators 做校验位判定，把「看起来像」和「确实合法」分开报。
3. 重叠冲突按优先级裁决（身份证 > 统一社会信用代码 > 银行卡 > 手机号 > ...），
   保证一个字符区间只会被判定为一种实体。
"""

from __future__ import annotations

import hashlib
import re

from .validators import VALIDATORS

# 命中优先级：数字越大越优先，用于裁决区间重叠
PRIORITY = {
    "id_card": 70,
    "uscc": 60,
    "bank_card": 50,
    "mobile": 40,
    "ipv4": 30,
    "email": 20,
    "plate": 10,
}

REGISTRY: dict[str, dict] = {
    "id_card": {
        "label": "居民身份证号",
        "pattern": re.compile(r"(?<!\d)(\d{17}[\dXx])(?!\d)"),
        "risk": "high",
    },
    "uscc": {
        "label": "统一社会信用代码",
        "pattern": re.compile(r"(?<![0-9A-Z])([0-9A-HJ-NPQRTUWXY]{18})(?![0-9A-Z])"),
        "risk": "medium",
    },
    "bank_card": {
        "label": "银行卡号",
        "pattern": re.compile(r"(?<!\d)(\d{16,19})(?!\d)"),
        "risk": "high",
    },
    "mobile": {
        "label": "手机号",
        "pattern": re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)"),
        "risk": "medium",
    },
    "ipv4": {
        "label": "IPv4 地址",
        "pattern": re.compile(
            r"(?<![\d.])((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?![\d.])"
        ),
        "risk": "low",
    },
    "email": {
        "label": "电子邮箱",
        "pattern": re.compile(r"(?<![\w.+-])([\w.+-]+@[\w-]+(?:\.[\w-]+)+)(?![\w.-])"),
        "risk": "medium",
    },
    "plate": {
        "label": "中国大陆车牌",
        "pattern": re.compile(
            r"(?<![A-Z0-9])"
            r"([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]"
            r"[A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳])"
            r"(?![A-Z0-9])"
        ),
        "risk": "medium",
    },
}


def _resolve_overlaps(candidates: list[dict]) -> list[dict]:
    """按优先级裁决重叠区间，一个字符只会归属于一种实体。"""
    ordered = sorted(
        candidates,
        key=lambda c: (-PRIORITY.get(c["type"], 0), c["start"], -(c["end"] - c["start"])),
    )
    taken: list[tuple[int, int]] = []
    kept: list[dict] = []
    for item in ordered:
        span = (item["start"], item["end"])
        if any(span[0] < t[1] and t[0] < span[1] for t in taken):
            continue
        taken.append(span)
        kept.append(item)
    return sorted(kept, key=lambda c: c["start"])


def scan(
    text: str,
    types: list[str] | None = None,
    *,
    include_invalid: bool = True,
    context_size: int = 12,
) -> dict:
    """扫描文本中的敏感信息。

    Args:
        text: 待扫描文本
        types: 仅扫描指定类型；None 表示全部
        include_invalid: 是否保留未通过校验位判定的疑似命中
        context_size: 命中片段前后保留的上下文字符数

    Returns:
        {"hits": [...], "summary": {...}}
    """
    source = text or ""
    wanted = [t for t in (types or REGISTRY.keys()) if t in REGISTRY]

    candidates: list[dict] = []
    for type_name in wanted:
        spec = REGISTRY[type_name]
        validator = VALIDATORS.get(type_name)
        for match in spec["pattern"].finditer(source):
            value = match.group(1)
            valid, reason = validator(value) if validator else (None, "")
            candidates.append(
                {
                    "type": type_name,
                    "label": spec["label"],
                    "risk": spec["risk"],
                    "value": value,
                    "start": match.start(1),
                    "end": match.end(1),
                    "valid": valid,
                    "reason": reason,
                }
            )

    hits = _resolve_overlaps(candidates)
    if not include_invalid:
        hits = [h for h in hits if h["valid"] is not False]

    for hit in hits:
        hit["context"] = source[
            max(0, hit["start"] - context_size) : hit["end"] + context_size
        ]

    summary: dict[str, int] = {}
    for hit in hits:
        summary[hit["type"]] = summary.get(hit["type"], 0) + 1

    return {
        "total": len(hits),
        "summary": summary,
        "hits": hits,
    }


def _apply_strategy(value: str, strategy: str) -> str:
    if strategy == "full":
        return "*" * len(value)
    if strategy == "hash":
        return "H_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    if strategy == "keep_tail":
        return "*" * max(0, len(value) - 4) + value[-4:]
    # partial（默认）：保留前 3 后 4
    if len(value) <= 4:
        return "*" * len(value)
    keep_head = min(3, len(value) - 1)
    keep_tail = min(4, len(value) - keep_head)
    return value[:keep_head] + "*" * (len(value) - keep_head - keep_tail) + value[-keep_tail:]


def mask(
    text: str,
    strategy: str = "partial",
    types: list[str] | None = None,
    *,
    include_invalid: bool = True,
) -> dict:
    """按策略脱敏文本。

    Returns:
        {"text": 脱敏后文本, "items": [...], "summary": {...}}
    """
    if strategy not in {"full", "partial", "hash", "keep_tail"}:
        raise ValueError(f"未知脱敏策略：{strategy}，可选 full / partial / hash / keep_tail")

    result = scan(text, types, include_invalid=include_invalid)
    source = text or ""

    pieces: list[str] = []
    cursor = 0
    items: list[dict] = []

    for hit in result["hits"]:
        pieces.append(source[cursor : hit["start"]])
        replacement = _apply_strategy(hit["value"], strategy)
        pieces.append(replacement)
        cursor = hit["end"]
        items.append(
            {
                "type": hit["type"],
                "label": hit["label"],
                "risk": hit["risk"],
                "valid": hit["valid"],
                "replacement": replacement,
                "length": len(hit["value"]),
            }
        )
    pieces.append(source[cursor:])

    return {
        "text": "".join(pieces),
        "total": len(items),
        "summary": result["summary"],
        "items": items,
    }


def describe_types() -> list[dict]:
    """返回支持的实体类型清单，供工具描述与文档使用。"""
    return [
        {
            "type": name,
            "label": spec["label"],
            "risk": spec["risk"],
            "has_checksum": name in VALIDATORS,
        }
        for name, spec in REGISTRY.items()
    ]
