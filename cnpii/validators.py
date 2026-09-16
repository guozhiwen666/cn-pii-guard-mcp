"""中国证件与编码的校验位算法实现。

设计原则：
- 纯函数、零外部依赖、完全离线
- 算法严格按国标实现，不靠"看起来像"来判定
"""

from __future__ import annotations

import re
from datetime import date

# ---------- 居民身份证号码 GB 11643-1999 ----------

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_MAP = "10X98765432"
_ID_PATTERN = re.compile(r"^\d{17}[\dXx]$")

# ---------- 统一社会信用代码 GB 32100-2015 ----------

# 注意：该字符集不含 I、O、S、V、Z
_USCC_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)
_USCC_PATTERN = re.compile(r"^[0-9A-HJ-NPQRTUWXY]{18}$")

# ---------- 中国大陆手机号 ----------

_MOBILE_PATTERN = re.compile(r"^1[3-9]\d{9}$")


def _id_check_digit(body17: str) -> str:
    """由身份证前 17 位计算校验位。"""
    total = sum(int(c) * w for c, w in zip(body17, _ID_WEIGHTS))
    return _ID_CHECK_MAP[total % 11]


def _luhn_ok(digits: str) -> bool:
    """Luhn 算法。从最右位（校验位本身）开始，偶数序号位加倍。"""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def validate_cn_id(value: str, *, strict_date: bool = True) -> tuple[bool, str]:
    """校验 18 位居民身份证号。

    Returns:
        (是否合法, 说明)
    """
    raw = (value or "").strip().upper()
    if not _ID_PATTERN.match(raw):
        return False, "格式不符：应为 17 位数字加 1 位校验位（数字或 X）"

    expected = _id_check_digit(raw[:17])
    if raw[17] != expected:
        return False, f"校验位错误：期望 {expected}，实际 {raw[17]}"

    if strict_date:
        try:
            birth = date(int(raw[6:10]), int(raw[10:12]), int(raw[12:14]))
        except ValueError:
            return False, "出生日期段不合法"
        if birth > date.today():
            return False, "出生日期晚于今天"

    return True, "校验通过"


def validate_uscc(value: str) -> tuple[bool, str]:
    """校验 18 位统一社会信用代码。"""
    raw = (value or "").strip().upper()
    if len(raw) != 18:
        return False, f"长度不符：应为 18 位，实际 {len(raw)} 位"
    if not _USCC_PATTERN.match(raw):
        return False, "含非法字符：该编码体系不使用 I、O、S、V、Z"

    total = sum(_USCC_CHARSET.index(c) * w for c, w in zip(raw[:17], _USCC_WEIGHTS))
    expected_index = (31 - total % 31) % 31
    expected = _USCC_CHARSET[expected_index]
    if raw[17] != expected:
        return False, f"校验位错误：期望 {expected}，实际 {raw[17]}"

    return True, "校验通过"


def validate_bank_card(value: str) -> tuple[bool, str]:
    """校验银行卡号：剥离分隔符后走 Luhn。"""
    digits = re.sub(r"[\s\-]", "", value or "")
    if not digits:
        return False, "输入为空"
    if not digits.isdigit():
        return False, "含非数字字符"
    if not 12 <= len(digits) <= 19:
        return False, f"长度不符：银行卡号通常为 12-19 位，实际 {len(digits)} 位"
    if not _luhn_ok(digits):
        return False, "Luhn 校验未通过"
    return True, "校验通过"


def validate_cn_mobile(value: str) -> tuple[bool, str]:
    """校验中国大陆手机号。"""
    raw = re.sub(r"[\s\-]", "", value or "")
    if not _MOBILE_PATTERN.match(raw):
        return False, "格式不符：应为 1 开头的 11 位号码，第二位为 3-9"
    return True, "校验通过"


# ---------- 测试数据生成（用于构造合法测试样本） ----------


def generate_cn_id(
    region_code: str = "110105",
    birth: str = "19900101",
    sequence: int = 1,
    gender: str | None = None,
) -> str:
    """按校验位算法生成一个能通过校验的测试身份证号。

    仅供测试数据构造使用，不对应任何真实个人。
    """
    region = re.sub(r"\D", "", str(region_code))[:6].ljust(6, "0")
    birth_digits = re.sub(r"\D", "", str(birth))[:8].ljust(8, "0")
    seq = int(sequence) % 1000

    if gender in ("male", "男"):
        seq = seq - seq % 2 + 1
    elif gender in ("female", "女"):
        seq = seq - seq % 2

    body = f"{region}{birth_digits}{seq:03d}"
    return body + _id_check_digit(body)


def generate_uscc(prefix: str = "91350100") -> str:
    """按校验位算法补全统一社会信用代码（仅测试用）。"""
    body = re.sub(r"[^0-9A-Z]", "", (prefix or "").upper())[:17]
    if not body:
        body = "91350100"
    body = body.ljust(17, "0")
    # 兜底：若填充后出现非法字符，替换为 0
    body = "".join(c if c in _USCC_CHARSET else "0" for c in body)

    total = sum(_USCC_CHARSET.index(c) * w for c, w in zip(body, _USCC_WEIGHTS))
    expected = _USCC_CHARSET[(31 - total % 31) % 31]
    return body + expected


def generate_bank_card(prefix: str = "622202", length: int = 16) -> str:
    """按 Luhn 算法补全校验位生成测试卡号（仅测试用）。"""
    body = re.sub(r"\D", "", prefix or "622202")
    target = max(12, min(19, int(length)))
    body = (body + "0" * target)[: target - 1]

    for check in "0123456789":
        if _luhn_ok(body + check):
            return body + check
    return body + "0"


VALIDATORS = {
    "id_card": validate_cn_id,
    "uscc": validate_uscc,
    "bank_card": validate_bank_card,
    "mobile": validate_cn_mobile,
}
