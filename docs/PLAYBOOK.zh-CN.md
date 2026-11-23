# 实战提效手册：免费与主流编程智能体的一行纯 Rust 接入指南（`ap` v2.45）

[English](./PLAYBOOK.md) | [简体中文](./PLAYBOOK.zh-CN.md) · [演进总手册](./HANDBOOK.zh-CN.md) · [架构深潜](./DESIGN.zh-CN.md) · [共同维护](../CONTRIBUTING.zh-CN.md) · [PR 模板](../.github/PULL_REQUEST_TEMPLATE.md)

`agent-primitives`（`v2.39`）交付为**单个零依赖原生 Rust 可执行文件（`ap` / `ap.exe`）**，静态内嵌 **6 语言 Tree-sitter 语法器**（`Py`/`TS`/`JS`/`Go`/`Rust`/`C`）、**内置 SQLite FTS5/BM25**、**纯 Rust 无头 Edge/Chrome CDP 引擎**、**万能文件/二进制/归档/网络审计器**以及**完整 MCP 2025-06-18（36 工具）标准服务端（`ap mcp`）**——用户电脑**无需安装 Python、Node、Playwright 或 Rust 编译器**。

---

## 1. 零配置一行命令接入（15+ 智能体开箱即用）

```bash
# macOS / Linux（自动识别并接线 OpenCode、Qwen、Gemini CLI、Goose、Pi、Codex、Antigravity、Claude、Grok、Cursor、Windsurf、VS Code、OpenClaw、Hermes）：
curl -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.sh | sh
```

```powershell
# Windows PowerShell：
curl.exe -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.ps1 | iex
```

```bash
# 仅接入当前项目目录（或一键应用 Pi 运行时补丁）：
ap init --here -a opencode
ap init --here --with-hooks --with-mcp
ap pi patch           # 幂等应用 12 项 Pi v1.5+/v1.6 运行时补丁（详见 docs/PI_RUNTIME.zh-CN.md）

# 随时一行无损卸载（完整保留你原有的个人配置）：
ap uninstall          # 或卸载当前项目：ap uninstall --here
```

### 原生支持的免费开源与商业智能体矩阵（$0 零 Key 即可提效）
- **OpenCode（`opencode`）**：自动写入 `opencode.json` 启用 `ap mcp`。哪怕使用 `$0` 免费模型（`opencode/big-pickle`、`glm-5.3-flash-free`、`deepseek-flash`），也能直接调用结构化工具，彻底告别 Windows 引号报错。
- **Qwen Code（`qwen`）与 Google Gemini CLI（`gemini`）**：自动向 `~/.qwen/settings.json` 与 `~/.gemini/settings.json` 注入 `"trust": true` 的 `ap mcp` 配置，免去每次弹窗确认。
- **Pi（`pi`）与 Goose（`goose`）**：自动同步 `~/.pi/agent/skills/`、`"exposure": "codemode"` 的 `mcp.json`、零前导词膨胀的 `zz-ap-accelerator.ts`，以及 **`ap pi status|patch|restore` 12 项运行时补丁**。
- **Claude Code、Codex、Antigravity、Grok、Cursor、Windsurf、VS Code、Claude Desktop、OpenClaw、Hermes**：自动接入 MCP、极简路由及 `<2ms` `exit 2` / JSON Hook（含 `rtk` 式测试日志自动脱水）。

---

## 2. 36 个原生 MCP 2025-06-18 工具（`--profile full|core|deferred`）与 CLI 原语协同矩阵

| 能力域（`ap mcp` + CLI） | 直接消除的模型思考与 OS 卡点 | 典型延迟 |
| :--- | :--- | ---: |
| **万能直读 / 多核检索 / SQL**（`ap read`、`ap search --pat`、`ap query`） | Tree-sitter `--symbol`/`--outline` + 12 文件批读；`--code-only --no-tests --exclude` 语法树过滤注释/字符串/单测噪音；Office/PDF/SQLite/`.asar`/`.map` VLQ；PE32+/ELF64（`--xref`/缓解审计/MS-RPC UUID/Go `.gopclntab`）；Java `.class`/`.jar`/`.NET CLR`/`--proto`/`--diff`/`--hex`；JS `--routes`/chunks/`--jwt`/脱敏 `--secrets`；免 Python 跨表 SQLite SQL。 | `1–20 ms` |
| **定向 / 9 轴表面图 / 定位追踪**（`ap_orient`、`atlas map/surface/locate/trace/changes`） | Personalized PageRank 核心地图、`<60ms` 守卫感知 9 轴表面图（源码+二进制+Web 路由）、`<25ms` 零提示故障定位、`<30ms` 多跳调用链与 Git Diff 影响面分析。 | `6–60 ms` |
| **AST 改写与全局重构**（`ap_edit`、`ap splice view/apply/rename/check`、`ap undo`） | 弹性链式补丁（自动剥离行号前缀、`@L<start>-L<end>` 行窗消歧、弯引号自愈 + 精确候选行定位、4 级缩进/空行与 Hashline `L:HH\|`）、严格避开注释/字符串的 Tree-sitter `rename`、6 语言+JSON/TOML 预检门禁及非 Git 快照。 | `0.7–5 ms` |
| **运行时、网络与双端 UI 质检**（`ap_smoke`、`ap probe smoke/ui/cdp/http/ws/tls/tcp/listen/ps/fs/mutate/fuzz`） | 空闲端口托管 + 进程树清零；无头 Edge/Chrome 桌面+移动 UI/4xx-5xx 巡检；非侵入式实时 `cdp --watch-ms`；单发/批量/并发竞态/CORS/CDP 会话复用 `http` 质检；RFC 6455 `ws --origin-matrix`；AST 变异测试与接口混沌 Fuzz。 | `0.2–4.5 s` |
| **深度六门禁、护栏与压缩**（`ap_verify`、`ap guard verify --deep/sec/diff/pack`、`ap exec`、`ap sieve`） | 单次跑通 6 重门禁（测试 + `.only`/零断言拦截 + OWASP C/C++/Java/TS/Py/Go/Rust `sec` + 语义 `diff` + 跨文件契约 + 活跃文件 `mutate`）、3 次死循环熔断、Windows UTF-8/长 `PATH` 治愈与 FTS5 无损日志压缩（`-98.8%`）。 | `<2 ms` (+测试) |
| **Pi 运行时、接力棒与微记忆**（`ap pi`、`ap baton frontier/claim/dedup`、`ap recall`） | 12 项幂等 Pi v1.5+/v1.6 运行时补丁（`codemode` `text()`/`.output` 兼容、Keep-Alive、串行 Shell 屏障、CJK 校准压缩、工具序锁缓存）、正交探索前沿调度、原子租约与 `3.3ms` CJK+BM25 微记忆。 | `<15 ms` |

---

## 3. 自检体检与基于本地日志的共同维护（`ap doctor` / `ap stats` / `ap audit`）

```bash
# 1. 一键核验运行环境、6 语言语法器、无头浏览器、智能体接线与 Pi 12 项补丁状态：
ap doctor

# 2. 查看 100% 本地离线省流与防翻车账本：
ap stats

# 3. 多 Agent 横向对比过程损耗（0 字节外传）：
ap audit --compare

# 4. 生成 100% 离线、零隐私泄露的纯数字“卡点→源码”共同维护简报（覆盖 6 款 Agent）：
ap audit --maintainer
```

如果你想让自己的 AI 基于「四源递归自我改进闭环 + 高可读性 PR 规范」一起维护 `ap`，请看 **[CONTRIBUTING.zh-CN.md](../CONTRIBUTING.zh-CN.md)** 与 **[.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md)**。
