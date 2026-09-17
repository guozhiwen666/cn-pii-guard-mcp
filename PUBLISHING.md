# 发布指南

本仓库有两个发布目标：

1. **PyPI** —— 代码分发渠道，同时是官方 MCP Registry 的**硬性前置条件**
2. **官方 MCP Registry** —— 让各 MCP 客户端能检索到这个服务

> 官方 registry 只托管元数据、**不托管产物**，所以必须先发 PyPI。

---

## 前置条件

| 需要 | 用途 |
|---|---|
| PyPI 账号 + API Token | 上传包；官方 registry 的所有权验证依赖包元数据里的 `mcp-name` 标记 |
| GitHub 账号 | `mcp-publisher` 的登录方式；server 名称前缀必须是 `io.github.<用户名>/` |

---

## 1. 发布到 PyPI

```bash
# 构建 sdist 与 wheel
python -m build

# 上传（用户名固定填 __token__，密码填 PyPI API Token）
python -m twine upload dist/*
```

验证：访问 `https://pypi.org/project/cn-pii-guard-mcp/`

### 所有权标记（关键）

PyPI 类型的包必须在 **README 中声明 `mcp-name`**，registry 靠它验证「这个包确实属于这个 server 名」。
本项目已在 README 顶部以 HTML 注释形式声明：

```markdown
<!-- mcp-name: io.github.guozhiwen666/cn-pii-guard-mcp -->
```

注释形式在 GitHub 页面上不渲染，但会保留在包元数据中，registry 能读到。

---

## 2. 发布到官方 MCP Registry

### 安装发布工具

```powershell
# Windows
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq "Arm64") { "arm64" } else { "amd64" }
Invoke-WebRequest -Uri "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_$arch.tar.gz" -OutFile "mcp-publisher.tar.gz"
tar xf mcp-publisher.tar.gz mcp-publisher.exe
```

macOS / Linux 可用 `brew install mcp-publisher`，或从同一 release 页下载对应平台压缩包。

### 校验与发布

```bash
mcp-publisher validate          # 仅校验 server.json，不需要登录
mcp-publisher login github      # 打开浏览器完成设备码授权
mcp-publisher publish
```

### 验证

```bash
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.guozhiwen666/cn-pii-guard-mcp"
```

---

## 3. 版本更新

以下**三处版本号必须同步**，否则 registry 会拒绝发布：

| 位置 | 字段 |
|---|---|
| `pyproject.toml` | `project.version` |
| `server.json` | `version` |
| `server.json` | `packages[0].version` |

同时建议同步更新 `README.md` 中引用的版本相关描述（如有）。

---

## 注意事项

- `server.json` 的 `name` 必须与包元数据中的 `mcp-name` **完全一致**。
- `description` 上限 **100 字符**。
- 官方 registry 仅接受以下两类：安装方式公开可达（已发布到包 registry），或端点公网可达的远程 server。
- 推送 `main` 前建议先跑一遍测试：`python -m unittest discover -s tests -p "test_*.py"`。
