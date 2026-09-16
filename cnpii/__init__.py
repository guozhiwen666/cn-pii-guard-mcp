"""cn-pii-guard-mcp：中文敏感信息识别、校验与脱敏 MCP 服务。

纯离线实现，不依赖任何第三方 API 或密钥。
"""

from .detectors import REGISTRY, describe_types, mask, scan
from .validators import (
    VALIDATORS,
    generate_bank_card,
    generate_cn_id,
    generate_uscc,
    validate_bank_card,
    validate_cn_id,
    validate_cn_mobile,
    validate_uscc,
)

__version__ = "0.1.0"

__all__ = [
    "REGISTRY",
    "VALIDATORS",
    "describe_types",
    "mask",
    "scan",
    "validate_cn_id",
    "validate_uscc",
    "validate_bank_card",
    "validate_cn_mobile",
    "generate_cn_id",
    "generate_uscc",
    "generate_bank_card",
]
