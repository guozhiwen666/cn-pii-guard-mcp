"""cn-pii-guard-mcp 服务入口。

工具面设计原则：
- 每个工具对应一条推理路径，而不是对应一个内部函数
- 支持的实体类型写进工具描述与 instructions，模型无需额外查询即可正确选参
- 返回值一律为结构化结论，不返回原始匹配过程

运行方式：
    python server.py                       # stdio（本地客户端）
    python server.py --transport sse       # SSE（魔搭托管部署）
    python server.py --transport streamable-http
"""

from __future__ import annotations

import argparse

from mcp.server.mcpserver import MCPServer

from cnpii import detectors, validators

INSTRUCTIONS = """本服务用于处理中文文本中的敏感信息，完全离线运行，不需要任何密钥。

使用建议：
- 需要「找出文本里有什么敏感信息」时用 scan_sensitive_info；
  若只想拿到干净结果、不想要形似的误报，把 include_invalid 设为 false。
- 需要「判断某个号码是否真实合法」时用 validate_identifier，它会执行校验位计算，
  能识别出格式正确但校验位错误的伪造号码。
- 需要「把敏感信息替换掉再输出」时用 mask_text，不要自己用字符串替换，
  否则会漏掉边界情况。
- 需要构造测试数据时用 generate_test_identifiers，
  它生成的值能通过校验位判定，比手写假号码更接近真实数据。

支持的实体类型：id_card（居民身份证号）、uscc（统一社会信用代码）、
bank_card（银行卡号）、mobile（中国大陆手机号）、email（电子邮箱）、
ipv4（IPv4 地址）、plate（中国大陆车牌）。
"""

mcp = MCPServer(
    name="cn-pii-guard",
    title="中文敏感信息识别与脱敏",
    version="0.1.0",
    instructions=INSTRUCTIONS,
)


@mcp.tool()
def scan_sensitive_info(
    text: str,
    types: list[str] | None = None,
    include_invalid: bool = True,
) -> dict:
    """扫描文本中的敏感信息，返回命中清单与风险分级。

    支持的类型与 type 取值：
    - id_card：居民身份证号
    - uscc：统一社会信用代码
    - bank_card：银行卡号
    - mobile：中国大陆手机号
    - email：电子邮箱
    - ipv4：IPv4 地址
    - plate：中国大陆车牌

    其中 id_card、uscc、bank_card、mobile 会额外做校验位判定，
    因此返回结果会区分「合法」与「仅形似」，便于人工判断误报。

    Args:
        text: 待扫描的文本，例如一段日志、工单或数据库导出内容
        types: 只扫描指定类型，留空表示全部扫描
        include_invalid: 是否保留校验位不通过的疑似命中，默认保留
    """
    return detectors.scan(text, types, include_invalid=include_invalid)


@mcp.tool()
def validate_identifier(kind: str, value: str) -> dict:
    """校验单个证件/编码的合法性（含校验位算法）。

    支持的 kind：id_card（居民身份证号）、uscc（统一社会信用代码）、
    bank_card（银行卡号）、mobile（中国大陆手机号）。

    与正则匹配不同，本工具会执行完整的校验位计算，
    能够识别出「长度对、格式像、但校验位错误」的伪造或录入错误号码。

    Args:
        kind: 实体类型
        value: 待校验的值
    """
    checker = validators.VALIDATORS.get(kind)
    if checker is None:
        return {
            "ok": False,
            "error": f"不支持的 kind：{kind}",
            "supported": list(validators.VALIDATORS.keys()),
        }

    valid, reason = checker(value)
    return {
        "ok": True,
        "kind": kind,
        "value": value,
        "valid": valid,
        "reason": reason,
    }


@mcp.tool()
def mask_text(
    text: str,
    strategy: str = "partial",
    types: list[str] | None = None,
) -> dict:
    """按指定策略脱敏文本，返回脱敏结果与逐项替换明细。

    可用策略：
    - partial：保留前 3 位与后 4 位（默认，适合人工核对）
    - full：全部替换为星号（适合彻底不可逆的对外输出）
    - hash：替换为可复现的哈希前缀（适合需要跨表关联但不暴露原值）
    - keep_tail：仅保留末 4 位（适合银行卡场景）

    注意：本工具返回的是脱敏后的文本，不会回传原始敏感值。

    Args:
        text: 待脱敏文本
        strategy: 脱敏策略
        types: 只处理指定类型，留空表示全部
    """
    return detectors.mask(text, strategy, types)


@mcp.tool()
def generate_test_identifiers(
    kind: str,
    count: int = 3,
    region_code: str = "110105",
    birth: str = "19900101",
) -> dict:
    """生成能通过校验位判定的测试用证件号，用于构造测试数据。

    生成结果均为合成数据，不对应任何真实个人或企业。
    支持的 kind：id_card、uscc、bank_card。

    Args:
        kind: 实体类型
        count: 生成数量，上限 20
        region_code: 身份证地区码（仅 kind=id_card 时生效）
        birth: 出生日期 yyyymmdd（仅 kind=id_card 时生效）
    """
    count = max(1, min(20, int(count)))
    results: list[str] = []

    if kind == "id_card":
        for i in range(count):
            results.append(
                validators.generate_cn_id(region_code, birth, sequence=i + 1)
            )
    elif kind == "uscc":
        for i in range(count):
            results.append(validators.generate_uscc(f"9135010{i}"))
    elif kind == "bank_card":
        for i in range(count):
            results.append(validators.generate_bank_card(length=16 + i % 4))
    else:
        return {
            "ok": False,
            "error": f"不支持的 kind：{kind}",
            "supported": ["id_card", "uscc", "bank_card"],
        }

    return {
        "ok": True,
        "kind": kind,
        "count": len(results),
        "values": results,
        "note": "均为合成测试数据，通过校验位验证，不对应真实主体",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="cn-pii-guard MCP server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="通信方式；本地客户端用 stdio，魔搭托管部署用 sse",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
