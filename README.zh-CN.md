<div align="center">
  <img src="./assets/logo.svg" width="60" height="60" alt="ap logo" />
  <h1>ap</h1>
  <p><strong>不只是编程：顺着大模型真实 <code>&lt;thinking&gt;</code> 卡点打造的通用与编程智能体底座 —— 把「读任意文件、跑终端命令、安全改文档、真机验功能」在 Windows 和 Mac 上彻底铺平。</strong></p>
  <p>
    <a href="https://github.com/xgbtxy/ap/actions/workflows/ci.yml"><img src="https://github.com/xgbtxy/ap/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
    <a href="https://github.com/xgbtxy/ap/releases/latest"><img src="https://img.shields.io/github/v/release/xgbtxy/ap?color=22c55e&label=%E7%9B%B4%E6%8E%A5%E4%B8%8B%E8%BD%BD" alt="Latest Release" /></a>
    <img src="https://img.shields.io/badge/%E5%B9%B3%E5%8F%B0-Windows%20%7C%20macOS%20%7C%20Linux-0ea5e9" alt="Platform" />
    <img src="https://img.shields.io/badge/%E8%BF%90%E8%A1%8C%E6%97%B6%E4%BE%9D%E8%B5%96-0%20(Rust%20%E5%8D%95%E6%96%87%E4%BB%B6)-f59e0b" alt="Zero Dependencies" />
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-64748b" alt="MIT License" /></a>
  </p>
  <p>
    <a href="./README.md"><strong>English</strong></a> · <strong>简体中文</strong> · <a href="./CONTRIBUTING.zh-CN.md"><strong>一起维护 / 贡献指南</strong></a> · <a href="./docs/HANDBOOK.zh-CN.md">核心研发理念</a> · <a href="https://github.com/xgbtxy/ap/releases/latest">安装包下载</a>
  </p>
  <img src="./assets/hero-comparison.zh-CN.svg" width="100%" alt="ap 如何顺着 AI 思考过程解决卡点并提效" />
</div>

---

## 10 秒一行安装，装完即忘

不需要装 `Python`、不需要装 `Node`、不需要装 400MB `Playwright`，**更不需要你背任何新命令**。复制一行执行，自动识别并接好你电脑上的通用桌面助手、AI 编辑器与终端 Agent（`Claude Desktop`、`OpenClaw`、`Hermes`、`Cursor`、`Windsurf`、`VS Code`、`Claude Code`、`Codex`、`OpenCode`、`Gemini CLI`、`Qwen Code`、`Pi`、`Goose`、`Antigravity`、`Grok`）：

**Windows（打开 PowerShell 粘贴回车）：**
```powershell
curl.exe -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.ps1 | iex
```

**macOS / Linux：**
```bash
curl -fsSL https://raw.githubusercontent.com/xgbtxy/ap/main/install.sh | sh
```

> **喜欢直接下载单文件？** 点击直链下载（**[Windows 64位 `ap.exe` (.zip)](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-pc-windows-msvc.zip)** · **[macOS M芯片](https://github.com/xgbtxy/ap/releases/latest/download/ap-aarch64-apple-darwin.tar.gz)** · **[macOS Intel](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-apple-darwin.tar.gz)** · **[Linux x64](https://github.com/xgbtxy/ap/releases/latest/download/ap-x86_64-unknown-linux-musl.tar.gz)** · **[Linux ARM64](https://github.com/xgbtxy/ap/releases/latest/download/ap-aarch64-unknown-linux-gnu.tar.gz)**），解压运行 `ap init` 即可。随时可用 `ap uninstall` 一键干净还原。

---

## 我们的核心理念：不是为了“抠 Token”，而是解决 AI 思考过程中的真实卡点

省 Token 只是水到渠成的副产物。**AI Coding 真正决定体验的，是模型能不能不卡壳、不被带偏、写错了也能自己发现并改过来。**

复盘本机 **101,108 次真实工具调用** 与大模型原始 `<thinking>` 轨迹后，我们发现 AI 变慢、变蠢、写出烂代码（AI Slop），往往不是因为模型智商不够，而是它在干活的 **5 个关键节点被打断了工作记忆**：

| AI `<thinking>` 真实卡点 | 没装 `ap` 时为什么会越干越乱？ | `ap` 怎么自动铺平？（完整命令清单见 [实战手册](./docs/PLAYBOOK.zh-CN.md)） |
| :--- | :--- | :--- |
| **1. 复杂代码、办公文档与二进制精准读写搜**<br>*(AST 过滤、Office、PE/ELF、前端)* | 缺 Python/`pefile` 读不了文档和二进制，传统 `grep` 搜出大量注释/字符串/单测噪音，或被 GNU `grep -rn` 卡死。 | **`ap ls` / `ap read` / `ap search` / `ap query`**：限深列目录 `ap ls`；Markdown `--section`/`--around`/AST `--symbol`/C++ `--outline` 与 12 文件批读；`-o`/`-u`/`--no-filename`/`-F`/`--include`/`--code-only --no-tests` 语法树与 Token 抽取；PE·ELF·Java·.NET·Protobuf 与 JS `--routes`/`--jwt`/`--secrets`；免 Python SQL。 |
| **2. 开局盲猜、表面图与真机接口/UI 质检**<br>*(定向、故障定位、HTTP/WS 鉴权)* | 面对多文件客诉靠 `ls`/`rg` 盲搜，手写脆弱 `curl`/Python 鉴权/CORS/并发脚本，或长会话遗漏测试维度。 | **`ap atlas` + `ap probe`**：`<15 ms` 全局骨架图、`<60 ms` 守卫感知 9 轴表面图、`<25 ms` 症状直达定位、零标签复用本地回环 CDP 会话（`--principal-cdp`）、HTTP `--race`/`--cors-origin` 与 WebSocket 跨源矩阵测试。 |
| **3. 安全创造与弹性链式精确改码**<br>*(跨模块契约、防误拷行号与重名歧义)* | 全局替换误伤注释/字符串，重构漏改调用方，或因复制了行号前缀、同名代码块歧义、智能引号导致补丁失配重读。 | **`ap splice` + `ap undo`**：弹性链式补丁（自动剥离读取行号前缀、`@L` 行窗消歧、候选行定位与弯引号自愈）、避开注释的 `rename`、6 语言+JSON/TOML 预检门禁及无 Git 快照。 |
| **4. 终端水土不服、慢搜索与死循环**<br>*(Windows/Mac Shell 与噪音日志)* | 撞上 **`528+` 次 OS/Shell 崩溃**（GBK/BOM、PS `&&`/`$_` 剥离、`rg` 正则报错、`dir /b`、长 `PATH` 截断）、慢 `grep -rhoE`、40KB 日志刷屏与死循环。 | **`ap exec` + `ap sieve` + `ap guard`**：透明 Hook 自动修复 UTF-8、`curl.exe`、PS `$var` 引号、`dir /b -> ap ls`、`rg -F` 与 `grep -rhoE` 自愈、临时服务 TTL 护栏，日志无损脱水 **-98.8%**，并内置 `3x` 死循环与批处理熔断。 |
| **5. 深度六门禁、按需 MCP 与 Pi 缓存经济学**<br>*(渐进发现 MCP、14 项 Pi 补丁、共维护)* | 全量 MCP 每次空烧 **11k+ Schema Token**，产出假绿灯测试或安全隐患，或长会话中途打穿 KV-Cache。 | **MCP 2025-06-18（`--profile full\|core\|deferred` + `ap_discover`/`ap_call`）** + **`ap guard verify --deep`** + **`ap pi`**（14 项幂等 Pi 补丁）+ **`ap audit --maintainer`**。 |

---

## 架构分层与演进方向：通用底座 + 真实运行日志 + 按需「模型 × 框架」适配

```text
+-------------------------------------------------------------------+
|  3. 按需适配层（按当前使用的 Agent 框架 x 模型家族按需装配）         |
|     - 宿主接线与 MCP 档位：`ap init -a <harness>` / `--profile`    |
|     - 可选运行时补丁包：`ap pi patch`（14 项 Pi 运行时增强）        |
|     - 模型特性经济学：KV-Cache 续热、快模型脱水阈值与 Schema 裁剪   |
+-------------------------------------------------------------------+
|  2. 实证驱动层：各家 Harness 与模型的真实运行过程日志                |
|     - 100% 离线零隐私轨迹审计（`ap audit --maintainer`）            |
|     - 从真实报错、重试、截断与缓存跌落中定位高杠杆改进点            |
+-------------------------------------------------------------------+
|  1. 通用能力底座（`ap` / `ap.exe` 单文件纯 Rust 核心）              |
|     - 与模型/框架解耦的物理原子能力：读写搜、语法树、二进制/归档、    |
|       SQLite、HTTP/WS/CDP 验证与 `37` 工具强类型 `ap mcp`          |
+-------------------------------------------------------------------+
```

- **通用能力底座放最底层**：把文件/Office/二进制/归档直读、Tree-sitter 语义搜索与安全改码、Shell/编码护盾、SQLite 查询及无头浏览器/接口门禁沉淀在零依赖纯 Rust 内核里，所有宿主通过统一 CLI 与 `ap mcp` 无差别复用。
- **由各家 Harness 与模型真实过程日志驱动演进**：通过离线零隐私 `ap audit --maintainer` 持续观察不同框架（`Claude Code`、`Codex`、`Pi`、`OpenCode`、`Cursor`、`Gemini CLI`、`Antigravity`、`Grok` 等）与不同模型档位的真实过程摩擦，共性痛点反哺通用底座，个性痛点精准归类。
- **「通用 `ap` + 特定模型/框架按需适配」组合使用**：用户只启用自己当前宿主与模型所需的薄适配（如 `ap init -a <harness>`、`ap pi patch` 或 `--profile deferred`），未使用的框架和模型零 Token 税、零运行时负担，也可随上游模型/框架升级随时安全退场。

---

## 装完之后怎么用？（零学习成本）

1. **完全不用改变习惯**：像平时一样打开你的 Coding Agent，哪怕用大白话提一句需求（甚至用 `$0` 免费模型），`ap` 都会在后台自动托底。
2. **想看它帮 AI 少踩了多少坑**，随时敲一下 **`ap stats`**（或 `ap doctor` 体检环境）：

```text
$ ap stats
[ap stats] Coding-Agent Efficiency & Thinking-Flow Ledger (100% offline)
------------------------------------------------------------------------
  Accelerated Agent Steps      : 28 actions
  Thinking Derailments Healed  : 11 Windows/shell crashes prevented before retry loops
  1-Shot Edits & Browser Gates : 14 verified (Tree-sitter AST + Headless Edge/Chrome + 0-slop)
  Working-Memory Noise Filtered: 612.4 KB -> 19.2 KB (-96.9% log/context clutter)
  Byproduct Token Savings      : ~186,800 wasted tokens avoided
```

---

## Windows 11 真机端到端提效实测（零水分）

在 Windows 11 真机上用 `$0` 免费智能体与主流商业 CLI 同题盲测（覆盖小白一句话需求、无 Python 非编程办公、存量跨模块重构、空目录从零新建与专项全栈实测）：

| 测试 Agent 与真实任务 | 未装 `ap` → **安装 `ap` 后**（速度与步数） | 代码质量与自纠错结果 | 顺带避免的冤枉 Token |
| :--- | :--- | :---: | :--- |
| **`OpenCode` 免费版 (`$0` `big-pickle`)** · *小白一句话需求* | `430.2s`（乱撞 `60` 步）→ **`182.4s`（`23` 步直达，快 2.36 倍）** | `7/8` *(留吞错 Slop)* → **`8/8`（0 Slop）** | **`-75.1%`** (`1.61M → 402k`) |
| **非编程日常办公（无 Python 电脑）** · *核对 `.docx` + `.xlsx` + `GBK` 流水* | `70.5s` *(读出乱码+调 Python 报错)* → **`46.5s`（快 1.52 倍）** | **`5/5` → `5/5`** *(`ap read` 一次直读零报错)* | **`-54.3%`** (`127k → 58k`) |
| **`Codex CLI` (`gpt-6-astra`)** · *14 文件跨模块函数签名重构* | `151.6s` → **`96.6s`（快 1.57 倍）** | **`7/7` → `7/7`** *(5 处下游调用与无头 Edge 一次全通)* | **`-57.4%`** (`296k → 126k`) |
| **`Codex CLI` (`gpt-6-astra`)** · *空目录随机新项目* | `345.3s`（`23` 步）→ **`244.6s`（`9` 步完成，少走 61% 弯路）** | **`6/6` → `6/6`** *(1 次无头 Edge 验通)* | **`-83.3%`** (`1.12M → 186k`) |
| **`Pi CLI` (`deepseek-flash`)** · *全栈功能升级* | `483.0s`（`81` 步）→ **`271.5s`（`70` 步，提速 1.78 倍）** | **`8/8` → `8/8`** *(`<thinking>` 空转降 42.7%)* | **`-36.7%`** (`3.63M → 2.30M`) |

<details>
<summary><strong>展开查看其余 12 项专项真机实测（SQL 对账、PE/ELF、异步 CDP、SourceMap、变异测试等）</strong></summary>

<br/>

| 测试 Agent 与真实任务 | 未装 `ap` → **安装 `ap` 后**（速度与步数） | 代码质量与自纠错结果 | 顺带避免的冤枉 Token |
| :--- | :--- | :---: | :--- |
| **复杂财务跨表与动态内网对账** · *2500 行双表 `.xlsx` + `GBK` 流水 + 动态 SPA* | `118.4s` *(连写 5 遍 XML 解析脚本)* → **`94.3s`（快 1.26 倍）** | **`5/5` → `5/5`** *(`ap query` 精确到分 + 无头 Edge 渲染)* | **`-35.1%`** (`212k → 138k`) |
| **无 Python 全栈排障与跨库稽核** · *`.sqlite` + 3000 行 `.xlsx` + `.log.gz` + 代码单测* | `112.0s` *(手拼 .NET 解压+4 遍脚本)* → **`94.3s`（快 1.19 倍）** | **`6/6` → `6/6`** *(`.gz` 首屏抓 `[FATAL]` + SQLite↔Excel 联表 + `APPEND`)* | **`-28.7%`** (`235k → 167k`) |
| **原生 PE 插件、在线 TCP Worker、目录 Diff 与 Webhook 捕获** · *PE32+ 导出/导入/Hex + 命令行/TCP + 原子目录对比 + 回调捕获* | `77.70s` *(手写 120 行 Python `struct`/socket/HTTP 脚本)* → **`73.23s`（快 1.06 倍，单步直出 PE 导入导出与 SHA-256）** | **`4/4` → `4/4`** *（`ap read *.dll` 一次直出导出/导入表；Worker 进程零中断）* | *免手写 PE/ELF 解析器* |
| **批量诊断、异步 CDP 监听与 HTTP 批探** · *180KB 压缩 JS 三偏移批切 + 5 路 HTTP 批探 + 实时 CDP 异步日志/网络捕获 + 边界修复* | `89.12s`（`10` 步，手写 `capture-audit.mjs`）→ **`83.92s`（`8` 步，步数 `-20%`，零手写脚本）** | **`5/5` + `--deep` 全绿** *（宿主浏览器零中断；`--offset` 批切 + `probe http --batch-stdin` + `probe cdp --watch-ms`）* | **`-6.0%`** (`135k → 127k`) |
| **线上 SourceMap 崩溃与嵌套 JWT 日志排障修复** · *VLQ 栈还原 + 500 行 JSONL JWT + Git Diff 门禁* | `106.05s` *(手写 VLQ + JWT + 变异脚本)* → **`94.36s`（快 1.12 倍）** | **`5/5` + 变异率 `100%`** *(`--map-pos` 一次直出源码行 + `--deep` 含 `guard diff` 全通)* | *零手写 VLQ/Diff 审计脚本* |
| **桌面端归档、二进制与运行中 CDP 全栈审计** · *`.asar` + 180KB 单行压缩 JS + PE 宽字符 + 运行中 CDP + 3 跳追踪* | `98.88s` *(手写 Node/WS/ASAR 解析脚本)* → **`83.43s`（快 1.19 倍，零手写脚本）** | **`5/5` → `5/5`** *（`15` vs `4` 条单测 + `--deep` 全绿，宿主浏览器零中断）* | **`-17.8%`** (`146k → 120k`) |
| **全栈安全与双端 UI 创造验收** · *`EventDesk`（SQLite + 桌面/移动布局 + XSS + 并发 Fuzz）* | 零手写浏览器脚本 *(`probe ui` + `smoke` 替代手写 `test/browser.mjs`)* | **单测变异杀伤率：`62.5%` (`5/8`) → `100.0%` (`8/8`)**，**`5/5`（0 安全缺陷 / 0 404 / 0 溢出）** | *6 门禁实证回执将调用步数压降 `-30.8%` (`13→9`)* |
| **18 模块零提示客诉排障定位** · *`CommerceCore` 优惠券叠加资损（零文件名提示）* | `123.37s` → **`107.59s`（快 1.15 倍，`atlas locate` + `--deep` 一次直通）** | **`5/5` + 变异率 `100%`** *（联动 `atlas impact` 与活跃文件变异门禁）* | **`-7.2%`** (`111k → 103k`) |
| **从零创造高并发服务与深度自测** · *秒杀与钱包引擎 `FlashVault`（10 路并发压测）* | 仅 `7` 步完成创造 + 五合一深度门禁 | **单测变异杀伤率：`62.5%` (`5/8`) → `100.0%` (`8/8` 全杀，黑盒 `10/10`)** | *自主揪出并消灭 3 处漏测边界缺陷* |
| **“假绿灯”存量仓库排雷加固** · *`OrderGate`（含 `.only` 跳测 + 损坏 JSON `500` + 差一错误）* | `200.6s` → **`183.2s`（反超原生且多跑 5 重门禁）** | **`6/6` + 变异率 `100%` + 接口混沌 Fuzz 全绿** | *单次 `--deep` 替代 5 轮串行验证（步数 `-43%`）* |
| **`Codex CLI` (`gpt-6-astra`)** · *全栈功能升级* | `333.6s`（`24` 步）→ **`294.3s`（`11` 步，少调 54% 工具）** | **`8/8` → `8/8`** | **`-65.4%`** (`1.05M → 365k`) |
| **`Pi CLI` (`deepseek-flash`)** · *空目录随机新项目* | `1,821.1s` → **`1,499.3s`（快 322 秒）** | `5/6` *(2 处空 `catch {}`)* → **`6/6`（0 Slop）** | *模型主动加跑了子集和暴力对拍* |

</details>

---

## 和你的 AI 一起维护 `ap`

`ap` 依靠一条**四源递归自我改进闭环**持续进化：调研外部社区与成熟工具经验 → 离线分析本地 AI 运行过程卡点（只看过程、不碰业务）→ 纯 Rust 最小化沉淀 → 脱敏真实实践对照验证并提交可秒审的 PR：

```bash
# 先在本机离线生成脱敏纯数字“卡点→源码”简报（覆盖 6 款智能体，零提示词/路径/业务内容，安全可先自查）：
ap audit --maintainer
```

- **复制现成提示词让你的 AI 参与维护**：查看 **[CONTRIBUTING.zh-CN.md](./CONTRIBUTING.zh-CN.md)**（内置完整「四源递归自我改进」提示词、**“介意扫本机日志”**的零隐私替代方案，以及**严禁误用**红线）。
- **PR 规范免读全仓**：提 PR 严格对齐 **[.github/PULL_REQUEST_TEMPLATE.md](./.github/PULL_REQUEST_TEMPLATE.md)**，由提交方 AI 标注精确到 `文件:符号/行号` 的改动地图与前后实测对照表，维护者几分钟即可拍板合入。

---

<details>
<summary><strong>给想看源码的开发者：纯 Rust 架构、微基准与研发手册</strong></summary>

<br/>

- **纯 Rust 零耦合单文件架构**：1 个原生二进制内聚 7 个物理隔离 crate（`crates/ap-{atlas,splice,probe,sieve,guard,recall,baton}`），子 crate 之间 `0` 相互依赖，内置 SQLite FTS5 与 6 语言编译态 Tree-sitter C 语法树，常驻提示词仅 `390` Tokens。
- **一键复现底层微基准**：运行 `ap bench`（详见 [`bench/results.json`](./bench/results.json)）。
- **深度工程文档**：
  - [四源递归共维护指南与一键提示词 (`CONTRIBUTING.zh-CN.md`)](./CONTRIBUTING.zh-CN.md) | [Contributing (`CONTRIBUTING.md`)](./CONTRIBUTING.md) | [PR 交付规范 (`.github/PULL_REQUEST_TEMPLATE.md`)](./.github/PULL_REQUEST_TEMPLATE.md)
  - [核心研发理念与演进手册 (`docs/HANDBOOK.zh-CN.md`)](./docs/HANDBOOK.zh-CN.md) | [R&D Philosophy (`docs/HANDBOOK.md`)](./docs/HANDBOOK.md)
  - [系统架构设计 (`docs/DESIGN.zh-CN.md`)](./docs/DESIGN.zh-CN.md) | [Architecture (`docs/DESIGN.md`)](./docs/DESIGN.md)
  - [高阶实战手册 (`docs/PLAYBOOK.zh-CN.md`)](./docs/PLAYBOOK.zh-CN.md) | [Playbook (`docs/PLAYBOOK.md`)](./docs/PLAYBOOK.md)
  - [Pi 运行时维护 (`docs/PI_RUNTIME.zh-CN.md`)](./docs/PI_RUNTIME.zh-CN.md) | [Pi Runtime Maintenance (`docs/PI_RUNTIME.md`)](./docs/PI_RUNTIME.md)

</details>

## 隐私边界与合法使用声明

- **100% 本地离线、零云端上传**：`ap stats` 与 `ap audit --maintainer` 完全在本机离线运行；`ap audit --maintainer` 仅输出脱敏后的纯数字过程卡点统计，绝不输出或上传任何提示词、业务源码、本机路径或凭据。
- **合理使用边界（严禁误用）**：`ap` 仅用于通用软件工程、排障调试、QA 自动化测试以及对自有或已获明确授权系统的防御性安全配置核查，严禁用于未授权访问或恶意用途。

## 开源协议

[MIT](./LICENSE)
