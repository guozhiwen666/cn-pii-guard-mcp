"""端到端冒烟测试：真实启动 MCP 服务并通过协议调用工具。

与单元测试的区别：这里走完整的 stdio 协议链路，
用于验证 server.py 能被客户端正常握手、列出工具并成功调用。

运行（需先安装 mcp）：
    python tests/e2e_smoke.py
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = pathlib.Path(__file__).resolve().parent.parent


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(ROOT / "server.py")],
        cwd=str(ROOT),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[1] 握手成功")

            listed = await session.list_tools()
            names = [t.name for t in listed.tools]
            print(f"[2] 工具列表：{names}")
            assert set(names) == {
                "scan_sensitive_info",
                "validate_identifier",
                "mask_text",
                "generate_test_identifiers",
            }, "工具集合与设计不符"

            for tool in listed.tools:
                desc = (tool.description or "").strip()
                assert desc, f"{tool.name} 缺少描述（模型无法正确选工具）"
            print("[3] 四个工具均有描述")

            sample = "客户张三，身份证 11010519491231002X，手机 13800138000，订单号 991380013800099912"

            res = await session.call_tool("scan_sensitive_info", {"text": sample})
            payload = json.loads(res.content[0].text)
            print(f"[4] scan_sensitive_info -> 命中 {payload['total']} 项，分布 {payload['summary']}")
            assert payload["total"] == 3, payload
            id_hit = next(h for h in payload["hits"] if h["type"] == "id_card")
            assert id_hit["valid"] is True

            res = await session.call_tool(
                "scan_sensitive_info", {"text": sample, "include_invalid": False}
            )
            filtered = json.loads(res.content[0].text)
            print(f"[5] include_invalid=False -> 命中 {filtered['total']} 项（订单号误报已滤除）")
            assert filtered["total"] == 2, filtered

            res = await session.call_tool(
                "validate_identifier", {"kind": "id_card", "value": "110105194912310021"}
            )
            bad = json.loads(res.content[0].text)
            print(f"[6] validate_identifier(错误校验位) -> valid={bad['valid']}，{bad['reason']}")
            assert bad["valid"] is False

            # 注意：上面 sample 里的订单号 991380013800099912 内嵌了
            # 「13800138000」这段合法手机号格式，脱敏断言必须避开它，
            # 否则会把「订单号未被误判」这件事误读成脱敏失败。
            mask_sample = "手机 13800138000，卡号 4111111111111111"

            res = await session.call_tool(
                "mask_text",
                {"text": mask_sample, "strategy": "keep_tail", "types": ["mobile"]},
            )
            masked = json.loads(res.content[0].text)
            print(f"[7] mask_text -> {masked['text']}")
            assert masked["total"] == 1, masked
            assert masked["items"][0]["replacement"] == "*******8000", masked
            assert "13800138000" not in masked["text"]
            assert "4111111111111111" in masked["text"], "未指定的类型不应被改动"

            res = await session.call_tool(
                "generate_test_identifiers", {"kind": "id_card", "count": 3}
            )
            gen = json.loads(res.content[0].text)
            print(f"[8] generate_test_identifiers -> {gen['values']}")
            for value in gen["values"]:
                check = await session.call_tool(
                    "validate_identifier", {"kind": "id_card", "value": value}
                )
                assert json.loads(check.content[0].text)["valid"] is True, value
            print("[9] 生成值全部通过自身校验")

            res = await session.call_tool(
                "validate_identifier", {"kind": "nope", "value": "x"}
            )
            err = json.loads(res.content[0].text)
            print(f"[10] 错误自解释：{err}")
            assert err["ok"] is False and err["supported"]

    print("\n端到端冒烟测试全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
