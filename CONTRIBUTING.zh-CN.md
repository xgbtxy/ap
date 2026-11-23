# 共同维护 `ap`（四源递归自我改进与 PR 交付指南）

[English](./CONTRIBUTING.md) · **简体中文** · [项目主页](./README.zh-CN.md) · [研发理念](./docs/HANDBOOK.zh-CN.md) · [PR 模板](./.github/PULL_REQUEST_TEMPLATE.md)

`ap` 的持续演进依靠一条**四源递归自我改进闭环（Recursive Self-Improvement Loop）**，绝不拍脑袋堆 Prompt：

1. **外部社区与成熟工具调研**：持续关注开源社区（GitHub Issues / Discussions / 主流 Agent 生态）高频痛点，以及成熟工程工具（`ripgrep`、`fd`、`ast-grep`、`Aider`、`RTK`、`SWE-agent`、`tree-sitter`、`SQLite FTS5`、`Chrome DevTools / Playwright`、`oh-my-pi`）经过实战验证的设计，提炼最本质的算法精髓，用零依赖纯 Rust 实现。
2. **本地分析 Agent 跑动日志**：优先用离线 `ap audit --maintainer` 或在宿主同意下只读观察真实工具执行过程中的卡点（引号/转义、GBK 编码、超时、重读、补丁失配、输出截断、反复手写一次性脚本、死循环、KV-Cache 跌落）。
3. **对照源码最小化落地**：映射到 [`src/`](./src) 与 [`crates/ap-*`](./crates) 对应原语，严守 [`AGENTS.md`](./AGENTS.md) 架构铁律，不留 AI Slop。
4. **真实实践对照测试 + 结构化 PR 交付**：不止跑单元测试，还必须构造**脱敏真实实践场景**做改前/改后实测对照（耗时、步数、报错率、输出字节、缓存/Token 收益），并按 [`.github/PULL_REQUEST_TEMPLATE.md`](./.github/PULL_REQUEST_TEMPLATE.md) 输出**精确到 `文件:符号/行号` 的改动地图**，让维护者不用通读全仓代码也能在几分钟内精准 Review 并合并，驱动下一轮迭代。

欢迎你用自己的 Coding Agent（`Claude Code`、`Codex`、`Cursor`、`Pi`、`Antigravity`、`Grok`、`OpenCode`、`Gemini CLI` 等）一起加入这个飞轮！

---

## 隐私底线与防误用约定（贡献前必读）

1. **只观察“过程问题”，严禁泄露业务内容**：
   - 分析本地 AI 运行日志时，只提取**执行过程问题**与**最小脱敏复现错误模式**。
   - **严禁**将任何私人项目名、业务代码、用户提示词原文、本机用户名/绝对路径、内网地址、厂商/客户名、账号、Cookie、Token 或密钥写入结论、代码、注释、测试、文档或 PR 描述。
2. **如果你介意扫描本机历史记录**：完全不必勉强，任选两种轻量方案：
   - **方案 A（零隐私纯数字简报）**：自己先跑一遍 `ap audit --maintainer`（100% 本地离线 Rust 程序，源码见 [`src/audit.rs`](./src/audit.rs)，只输出脱敏纯数字统计与对应 `ap` 源码模块，无任何提示词/路径/业务内容），亲眼核验无敏感信息后再贴给 AI。
   - **方案 B（跳过原日志）**：结合外部社区/工具调研，或手动脱敏一条具体报错片段，直接对照 `ap` 源码优化并提 PR。
3. **合法与防御性使用边界（严禁误用）**：`ap` 仅面向通用软件工程、排障调试、QA 自动化测试以及对自有或已获明确授权系统的防御性安全配置核查。**严禁**提交任何攻击载荷生成、未授权漏洞利用、凭据窃取或绕过安全控制的功能。

---

## 一键复制：让你的 AI 进入「递归自我改进」维护模式

> **用法**：`git clone https://github.com/xgbtxy/ap.git` → 在仓库目录打开你的 AI Agent → 复制发送下方整段提示词。完成后直接按 AI 生成的 PR 报告审核提交即可。

```text
请作为当前开源项目 `ap` 的共同维护者，启动一轮【四源递归自我改进闭环】：结合外部社区与成熟工具调研、本地 Agent 运行过程日志分析、当前仓库源码审计、以及真实实践前后对照测试，设计并实现 1–3 项高价值、100% 通用的纯 Rust 优化，并严格按照 `.github/PULL_REQUEST_TEMPLATE.md` 输出便于维护者快速审阅合并的结构化 PR 报告。

【隐私与防误用硬红线（最高优先级）】
1. 只看“过程卡点”，绝不触碰业务隐私：
   - 优先先运行本地离线命令 `ap audit --maintainer` 获取脱敏纯数字简报；
   - 若宿主用户介意扫描本机全部 AI 历史记录文件，请立即停止扫描原日志，改为仅依据 `ap audit --maintainer` 数字简报、外部社区调研或用户手动提供的脱敏报错片段开展工作；
   - 若获同意抽样本地日志，只允许抽象最小合成复现报错模式；结论、代码、注释、测试、文档、Commit 与 PR 文本中严禁出现任何真实项目名、业务代码、用户提示词原文、本机用户名/绝对路径、内网域名、账号、Cookie、Token 或密钥。
2. 严禁误用：所有能力严格限定在通用软件工程、排障调试、QA 自动化测试或授权防御性配置核查范畴，禁止任何未授权攻击、利用载荷或凭据窃取功能。

【四步递归自驱执行流程】
Step 1 · 外部社区与成熟工具调研：
- 若当前环境允许联网检索，调研近期开发者社区（GitHub / HN / 主流 Coding Agent 生态）关于 AI 编程代理工具链的高频执行痛点（Windows/macOS Shell 崩溃、MCP 阻塞、长日志膨胀、编辑失配、死循环、KV-Cache 失效等）与成熟开源工具（ripgrep/ast-grep/Aider/RTK/SWE-agent/oh-my-pi 等）的工程解法；若离线受限，则基于成熟工程经验明确标注检索限制并聚焦实证机制。
- 只提炼核心算法/确定性规则，拒绝简单套壳或堆砌 Prompt。

Step 2 · 本地过程摩擦剖析 + 源码映射：
- 运行 `ap audit --maintainer`（或在明确同意下只读抽样 `~/.codex/sessions`、`~/.claude/projects`、`~/.pi/agent/sessions`、`~/.grok/sessions`、`~/.gemini/` 中的工具调用失败与低效模式），交叉对比 Step 1 调研结果，选出 Top 1–3 个“高频 × 可机械根治”的通用卡点。
- 对照 `ap` 源码精确定位：
  * Shell 引号/转义/GBK/路径/超长 PATH -> `src/exec.rs`, `src/install.rs`
  * 反复手写 `python -c`/`node -e` 解析文件/HTTP/二进制/日志 -> `src/read.rs`, `src/query.rs`, `crates/ap-probe/src/`
  * 重复读大文件 / 手工 `head`/`tail`/`sed` -> `src/read.rs`, `crates/ap-atlas/src/`, `crates/ap-splice/src/`
  * 编辑/补丁行失配反复重试 -> `crates/ap-splice/src/lib.rs`
  * 输出 >8KB 刷屏或截断 -> `crates/ap-sieve/src/lib.rs`
  * 搜索慢或超时 -> `src/search.rs`, `src/exec.rs`
  * 相同报错死循环 / 压缩失忆 -> `crates/ap-guard/src/`, `crates/ap-baton/src/`
  * Pi / 推理模型缓存跌落或工具调度抖动 -> `src/pi_patch.rs`, `src/install.rs`

Step 3 · 纯 Rust 实现与架构铁律遵守（`AGENTS.md`）：
- 零新增外部运行时依赖，非必要不增 Cargo 依赖；
- `crates/ap-*` 7 个子 crate 之间保持 0 兄弟依赖（物理隔离）；
- 热循环禁用 `Regex::new`（用 `OnceLock`）；不做纯 Prompt 堆砌；
- CLI 参数/子命令若有变动，同步更新 `src/mcp.rs`（含 `outputSchema`）与中英文文档（`*.md` & `*.zh-CN.md`），不擅自撑大 `skills/*/SKILL.md` 前导词预算。

Step 4 · 真实实践测试（Before vs After）与门禁验收：
- 为每项改动编写脱敏合成的单元/集成测试（使用 `example.com` 与临时目录）；
- 额外构造一个贴近真实工程的脱敏实践场景（如真实命令行噪声、多文件补丁失配、超长日志或真实回归复现），实测并记录**改前 vs 改后**客观对比数据（耗时、步数、报错率、输出字节或缓存/Token 效果）；
- 必须全部通过：
  1) `cargo fmt --all -- --check`
  2) `cargo clippy --workspace --all-targets -- -D warnings`
  3) `cargo test --workspace`
  4) `git diff` 逐行复核确认 0 隐私泄露与 0 硬编码本机路径。

【PR 交付规范（强制：免维护者通读全仓代码即可审核合并）】
最终汇报请**严格按照 `.github/PULL_REQUEST_TEMPLATE.md` 的 6 段结构输出完整 PR 说明**，必须清晰指出：
1. 一句话结论（解决什么具体卡点）；
2. 四源依据（外部调研对象 + 脱敏日志计数/模式 + 复现方式）；
3. **精准改动地图**：列出每一处 `文件路径 :: 符号名 (行号范围)`，写明改前、改后与原因，外加架构一致性自检；
4. **真实实践测试前后对照表** + 全部 CI 门禁通过实证；
5. 跨平台风险边界、放弃方案与干净回滚路径；
6. 隐私与防误用红线逐项自检结果（附下一轮可继续递归审计的 1 个观察方向）。
```

---

## 仓库维护者怎么高速审阅与合并 PR？

所有 PR 模板（[`.github/PULL_REQUEST_TEMPLATE.md`](./.github/PULL_REQUEST_TEMPLATE.md)）已强制要求提交方写出「**精确改动地图（`文件:符号/行号` + 改前/改后/原因）+ 实测对照表**」。审阅者只需 4 步即可拍板合入：

1. 看 **「第 1 段 + 第 3 段改动地图」**：30 秒确认改动范围是否克制、是否守住 7 个子 crate 零耦合与零外部依赖边界。
2. 看 **「第 4 段 Before vs After 实测表」**：核验是否真有真实实践场景量化收益，而不只是形式单测；确认 GitHub Actions 三平台 CI 全绿。
3. 抽查地图列出的 `文件:行号` 与 **「第 5 段回滚路径」**：重点看跨平台边界（Windows/macOS/Linux）及是否可能误伤破坏性护栏。
4. 看 **「第 6 段隐私与防误用自检」**：确认 0 私人数据与 0 越界能力后即可合并。

---

## 源码模块速查地图

| 源码位置 | 职责 |
| :--- | :--- |
| [`src/read.rs`](./src/read.rs) · [`src/binary.rs`](./src/binary.rs) · [`src/inspect.rs`](./src/inspect.rs) | 通用万能直读（Office/PDF/SQLite/AST 符号/压缩包/PE/ELF/Java/.NET/Protobuf/JS 路由/JWT/脱敏密钥） |
| [`src/search.rs`](./src/search.rs) · [`src/query.rs`](./src/query.rs) | 多核并发正则/归档检索与零依赖 SQLite/Excel/CSV 精确 SQL 查询 |
| [`src/exec.rs`](./src/exec.rs) · [`src/win_job.rs`](./src/win_job.rs) | 跨平台 Shell 自动纠偏、UTF-8 锁死、慢 `grep` 改写与 Win32 Job Object 孤儿进程清理 |
| [`src/audit.rs`](./src/audit.rs) · [`src/stats.rs`](./src/stats.rs) | 100% 本地零隐私摩擦审计器（`ap audit --maintainer`）与离线提效账本 |
| [`src/mcp.rs`](./src/mcp.rs) · [`src/install.rs`](./src/install.rs) · [`src/pi_patch.rs`](./src/pi_patch.rs) | MCP 2025-06-18 36 工具服务器、15+ 智能体一键接线与 Pi v1.5+ 11 项运行时补丁器 |
| [`crates/ap-atlas`](./crates/ap-atlas) · [`ap-splice`](./crates/ap-splice) · [`ap-probe`](./crates/ap-probe) · [`ap-sieve`](./crates/ap-sieve) · [`ap-guard`](./crates/ap-guard) · [`ap-recall`](./crates/ap-recall) · [`ap-baton`](./crates/ap-baton) | 7 个零耦合独立 Rust 子 crate（结构地图 / AST 改写 / HTTP·WS·UI·运行时探针 / 日志 FTS5 / 防 Slop 门禁 / 微记忆 / 跨压缩接力棒） |
