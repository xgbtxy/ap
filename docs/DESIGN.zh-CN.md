# 反淘汰架构深潜：瞄准思考链与物理边界的纯 Rust 原语设计（`ap` v2.43）

[English](./DESIGN.md) | [简体中文](./DESIGN.zh-CN.md) · [演进总手册](./HANDBOOK.zh-CN.md) · [实战手册](./PLAYBOOK.zh-CN.md) · [共同维护](../CONTRIBUTING.zh-CN.md) · [PR 模板](../.github/PULL_REQUEST_TEMPLATE.md)

## 1. 为什么 95% 的开源 Agent 项目活不过半年？

- **纯提示词角色扮演与套路清单最先消亡**：前沿模型每次强化学习后训练都会吸收这些软套路，冗长的 `AGENTS.md` 说教反而退化为注意力噪音与延迟税。
- **重型多智能体包装器其次消亡**：各大官方宿主（`codex`、`opencode`、`pi`、`claude`、`agy`、`qwen`、`gemini`、`grok`、`hermes`、`openclaw`）原生掌控对话循环与子智能体调度。
- **有损向量 RAG 包装器随之淘汰**：近似语义切片不仅需要 Docker 与 API Key，更比不上毫秒级精确语法树地图与确定性检索。

**架构铁律**：绝不生产 AI Slop，只在**自回归 Token 生成与操作系统/语法树/二进制/网络/浏览器进程发生物理错位的四道边界**上，用**纯 Rust 单文件二进制（`ap` / `ap.exe`）** 同时输出 **Unix CLI** 与 **标准 `ap mcp` JSON-RPC 服务**。

---

## 2. 大模型不可逾越的四道认知与物理边界（`v2.41`）

| `<thinking>` 思考链与系统边界 | 本机 `11.3 万+` 次调用与真实推理流实测损耗 | 纯 Rust 确定性器官与开源顶尖算法融合（`v2.41`） |
| :--- | :--- | :--- |
| **1. 冷启动高熵盲猜、二进制盲区与旧屎山污染** | `3 万+` 次超 `8 KB` 输出刷屏；`650+` 次裸 `ls` 刷屏；反复手写脆弱 `node -e`/`python -c` 解析 Office/PDF/SQLite/`.asar`/PE/ELF/Java/.NET/Protobuf/SourceMap/Markdown 章节。 | **`ap ls`**（限深列目录 + MSYS2 路径规范化）+ **`ap-atlas`**（Aider **Personalized PageRank**、`<60ms` 守卫感知 9 轴 `surface --include-binaries`、`<25ms` `locate`、`<30ms` `trace`/`changes`、DOM `#id`/路由与 Slop 雷达）+ **`ap read`**（`--section`/`--around`/C++ `--outline`）/ **`ap search`**（`-F`/`-i`/`--max`/`--include`/`--code-only --no-tests`）/ **`ap query`** + **`ap-sieve`**（`-98.8%` 日志、FTS5 `search`/`peek`、300 行错误洪流封顶）+ **`ap-probe slice`** |
| **2. 跨文件记忆漂移、补丁失配与 Shell 转义崩溃** | 跨文件写串 `#id`/路由；`735+` 次缩进/空行漂移补丁失配；`528+` 次 Windows PowerShell `$_` 变量剥离、`rg` 正则报错、GBK 编码与超长 `PATH` 截断崩溃。 | **`ap-splice`**（`view`、避开注释字符串的 `rename`、Aider 三级 + 四级空行容错与 Hashline `L:HH\|` `apply`、`<5ms` 跨文件静态链接 `check`、`ap undo`）+ **`ap exec`**（UTF-8 锁死、PS 单引号自愈、慢 `grep -rl`/`rg -F` 自愈、Win32 Job Object）+ **`ap mcp`**（`36` 个强类型 `outputSchema` 工具 = `0` Shell 转义） |
| **3. Windows 验证税、网络/浏览器实测与内存脑补** | **71%–75% 的原生步骤**耗在服务挂死、残留端口、手写 150 行浏览器/WS/HTTP 鉴权与 CORS/并发脚本、零断言假绿灯测试。 | **`ap-probe`**（空闲端口 `smoke`、桌面/移动双端 `ui` 巡检、非侵入式 `cdp --watch-ms`、`http --principal/--principal-cdp/--cors-origin/--select/--race/--batch-stdin`、RFC 6455 `ws --origin-matrix`、`tls`/`tcp`/`listen`/`ps`/`fs`、AST 变异 `mutate`、`fuzz`、`run`/`diff`）+ **`ap guard verify --deep`** |
| **4. 叮嘱失灵、死循环、压缩失忆与长程 KV-Cache 跌落** | 长会话下模型无视文字规则；相同命令反复报错空转；QuickJS `codemode` `.output.slice()` `TypeError`；中文压缩超留 2–3 倍或中途打穿 KV-Cache。 | **`ap-guard`**（`<2ms` `exit 2` 硬规则、`sec` C/C++/Java/TS/Py/Go/Rust CWE 检测、语义 `diff`、交付门禁 `pack`、3 次死循环熔断）+ **`ap-baton`**（正交 `frontier` 调度、`claim` 租约、CJK+BM25 `dedup`）+ **`ap-recall`** + **`ap pi`**（12 项 Pi 运行时补丁 + `zz-ap-accelerator.ts`）+ **`ap audit --maintainer`**（100% 离线零隐私 6 智能体简报） |

---

## 3. 为什么选择纯 Rust（`v2.41`）+ 原生内置 `ap mcp`？

1. **编译期零开销安全与微秒启动（`Rust > C & Python`）**：所有权安全、`OnceLock` 全局单次编译自动机（热循环零正则重编译）、零 GC 停顿、零外部运行时依赖，内置 Windows 长 `PATH` 裁剪、UTF-8 锁定与 Win32 Job Object 进程树回收。
2. **渐进式 MCP 按需发现（`ap mcp --profile full|core|deferred`）**：完整支持 **MCP 2025-06-18** stdio JSON-RPC：默认 `full` 暴露全量 **36 个带强类型 `outputSchema` 工具**；也可选 `core`（8 常用工具 + `ap_discover`/`ap_call`）或 `deferred`（仅 2 个元工具，削减约 **94%** 前置 Schema Token 税），全面淘汰脆弱命令行转义。
3. **7 个物理隔离 Crate（`0` 兄弟依赖）**：每个 `crates/ap-*` 均可独立编译安装，与根模块共同编译为单个约 `15 MB` 原生二进制（全量 7 技能静默描述仅占 **`390 tokens`**）。
