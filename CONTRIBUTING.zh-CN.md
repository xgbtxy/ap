# 共同维护 `ap`（基于真实 AI 运行摩擦日志的开源自演进指南）

[English](./CONTRIBUTING.md) · **简体中文** · [项目主页](./README.zh-CN.md) · [研发理念](./docs/HANDBOOK.zh-CN.md)

`ap` 的核心研发方法非常直接：**不拍脑袋堆 Prompt，只从真实 AI 干活时的“过程卡点”出发，把反复出现的工具报错、环境水土不服、重复读文件、上下文爆炸和死循环，沉淀成 0 依赖的纯 Rust 底层原语。**

非常欢迎你用自己电脑上的 AI Coding Agent（`Claude Code`、`Codex`、`Cursor`、`Pi`、`Antigravity`、`Grok`、`OpenCode`、`Gemini CLI` 等）一起参与维护！

---

## 隐私底线与防误用约定（贡献前必读）

1. **只看“过程卡点”，绝不触碰业务内容**：分析本地 AI 历史记录时，只统计与抽象**执行过程问题**（例如：Shell 引号/转义崩溃、编码报错、命令超时、重复读同一文件、补丁失配、输出超长截断、手写一次性 Python/Node 胶水脚本、死循环重试、KV-Cache 跌落等）。**严禁**将任何私人项目名、业务代码、本机用户名/绝对路径、内网地址、厂商/客户名、账号、Token 或密钥写入代码、测试、文档或 Commit/PR。
2. **如果你介意让 AI 扫描本机历史记录**：完全不必勉强！你有两种更轻量的替代方案：
   - **方案 A（零隐私纯数字简报）**：先自己在本机跑一遍 `ap audit --maintainer`（100% 本地离线 Rust 程序，源码见 [`src/audit.rs`](./src/audit.rs)，只输出纯数字卡点统计与对应源码模块，绝不输出任何提示词、路径或业务内容），你亲眼确认无敏感信息后，再把这段简报贴给 AI。
   - **方案 B（跳过日志直接提 PR）**：直接脱敏粘贴一条你遇到的真实报错片段，或直接阅读 `ap` 源码针对某个原语提 Issue / PR。
3. **合法与防御性使用边界（严禁误用）**：`ap` 仅面向通用软件工程、排障调试、QA 自动化测试以及对自有或已获明确授权系统的防御性安全配置核查。**严禁**提交任何攻击载荷生成、未授权利用、凭据窃取或绕过安全边界的功能。

---

## 快速上手：把下面的提示词直接发给你的 AI

> **使用方式**：先 `git clone https://github.com/xgbtxy/ap.git` 并在仓库目录打开你的 AI Agent，然后复制下面整段提示词发给它。

```text
请帮我以开源维护者身份，基于本机 AI 工具运行过程中的“真实执行卡点”，对照当前仓库（ap）的源代码提出并实现 1–3 项高价值、100% 通用的纯 Rust 优化。

【隐私与防误用硬红线（必须严格遵守）】
1. 只观察“过程问题”，严禁泄露业务内容：
   - 优先先运行本地离线命令 `ap audit --maintainer` 获取脱敏后的纯数字过程卡点简报；
   - 若需要进一步确认某类高频工具报错（如 Shell 语法崩溃、编码错误、超时、编辑失配、输出过长、反复手写一次性脚本等），只允许抽象出**最小复现报错模式**，严禁在分析结论、代码、注释、测试样例、文档或 Commit 信息中出现任何真实项目名、业务代码、用户提示词原文、本机用户名/绝对路径、域名、账号、Cookie、Token 或密钥。
   - （注：如果宿主用户介意扫描本机全部 AI 历史记录文件，请立即停止扫描原日志，改为仅依据 `ap audit --maintainer` 的数字统计或用户手动提供的脱敏片段开展优化。）
2. 严禁误用：所有新增/优化能力必须严格属于通用软件工程、排障调试、自动化测试或防御性配置核查范畴，禁止任何未授权攻击、漏洞利用载荷或凭据窃取功能。

【审计与优化步骤】
1. 采集过程摩擦：运行 `ap audit --maintainer`（或在用户明确同意下，只读抽样 `~/.codex/sessions`、`~/.claude/projects`、`~/.pi/agent/sessions`、`~/.grok/sessions`、`~/.gemini/` 等本地历史中的**工具调用失败模式与低效过程**，按频次排 Top 5 通用卡点）。
2. 对照 `ap` 源码定位根因（见下方映射表）：
   - Shell 引号/转义/GBK/路径崩溃 -> `src/exec.rs`、`src/install.rs`
   - 反复手写 `python -c`/`node -e` 解析文件/日志/二进制/HTTP -> `src/read.rs`、`src/query.rs`、`crates/ap-probe/src/`
   - 重复读大文件 / 手工 `head`/`tail`/`sed` 翻页 -> `src/read.rs`、`crates/ap-atlas/src/`、`crates/ap-splice/src/`
   - 编辑/补丁行失配反复重试 -> `crates/ap-splice/src/lib.rs`
   - 工具输出 >8KB 刷屏或被截断 -> `crates/ap-sieve/src/lib.rs`
   - `grep`/`find` 慢搜或超时 -> `src/search.rs`、`src/exec.rs`
   - 相同错误死循环 / 压缩失忆 -> `crates/ap-guard/src/`、`crates/ap-baton/src/`
   - Pi / DeepSeek 思考空转或 KV-Cache 跌落 -> `src/pi_patch.rs`、`src/install.rs`
3. 严守仓库架构铁律（详见 `AGENTS.md`）：
   - 零新增外部运行时依赖，尽量不新增 Cargo 依赖；
   - `crates/ap-*` 7 个子 crate 之间保持 0 相互依赖（物理隔离）；
   - 热循环里禁止 `Regex::new`（用 `OnceLock`）；不做纯 Prompt 堆砌，把规则沉淀成确定性代码；
   - 每项改动必须附带脱敏合成的单元测试（用虚构数据如 `example.com` / 临时目录），并同步更新中英文文档（如有 CLI/MCP 参数变化，同步更新 `src/mcp.rs`）。
4. 提交前必须通过全部本地门禁：
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
   - `git diff` 逐行复核确认 0 隐私泄露、0 硬编码本机路径。
```

---

## 模块地图（给人类维护者速查）

| 源码位置 | 职责 |
| :--- | :--- |
| [`src/read.rs`](./src/read.rs) / [`src/binary.rs`](./src/binary.rs) / [`src/inspect.rs`](./src/inspect.rs) | 通用万能直读（Office/PDF/SQLite/AST 符号/压缩包/PE/ELF/Java/.NET/Protobuf/路由/JWT/脱敏密钥审计） |
| [`src/search.rs`](./src/search.rs) / [`src/query.rs`](./src/query.rs) | 多核并发正则/归档检索与零依赖 SQLite/Excel/CSV 精确 SQL 查询 |
| [`src/exec.rs`](./src/exec.rs) / [`src/win_job.rs`](./src/win_job.rs) | 跨平台 Shell 自动纠偏、UTF-8 锁死、慢 `grep` 改写与 Win32 Job Object 孤儿进程清理 |
| [`src/audit.rs`](./src/audit.rs) / [`src/stats.rs`](./src/stats.rs) | 100% 本地零隐私摩擦审计器（`ap audit --maintainer`）与离线提效账本 |
| [`src/mcp.rs`](./src/mcp.rs) / [`src/install.rs`](./src/install.rs) / [`src/pi_patch.rs`](./src/pi_patch.rs) | MCP 2025-06-18 36 工具服务器、15+ 智能体一键接线与 Pi v1.5+ 11 项运行时补丁器 |
| [`crates/ap-atlas`](./crates/ap-atlas) · [`ap-splice`](./crates/ap-splice) · [`ap-probe`](./crates/ap-probe) · [`ap-sieve`](./crates/ap-sieve) · [`ap-guard`](./crates/ap-guard) · [`ap-recall`](./crates/ap-recall) · [`ap-baton`](./crates/ap-baton) | 7 个零耦合独立 Rust 子 crate（结构地图/AST 精确改写/HTTP·CDP·运行时探针/日志压缩 FTS5/反 Slop 门禁/微记忆/跨压缩接力棒） |
