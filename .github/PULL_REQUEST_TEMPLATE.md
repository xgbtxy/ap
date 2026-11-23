## 1. 一句话结论 / Summary (`What & Why`)

- **改动类型 / Change Type**：
  - [ ] 性能与延迟 / Performance & Latency
  - [ ] 稳定性与跨平台修复 / Reliability & Cross-OS Fix
  - [ ] 零依赖纯 Rust 新原语 / New Zero-Dep Primitive
  - [ ] Pi 运行时与缓存 / Pi Runtime & KV-Cache
  - [ ] 文档与协同规范 / Docs & DX
- **一句话说明（解决什么过程卡点）**：

---

## 2. 问题来源与依据 / Evidence & Research Sources（四源循环）

- [ ] **外部社区讨论 / 成熟开源工具调研**（公开 Issue/Discussion/论文/成熟工具中提炼了哪项机制，为何不包壳、如何最小化纯 Rust 化）：
- [ ] **本地 Agent 跑动日志分析**（贴 `ap audit --maintainer` 脱敏纯数字简报或最小复现报错模式；**严禁**出现真实业务/路径/提示词）：
- [ ] **真实实践复现**（能触发原卡点的最小脱敏复现命令或步骤）：

---

## 3. 精准改动地图 / Exact Change Map（Review 直达坐标）

> 请列出每一处实质改动，让审阅者**不必通读全仓**即可直接定位校验：

| 文件与符号/行号 (`File :: Symbol / Lines`) | 改前 (`Before`) | 改后 (`After`) | 改动原因 (`Why`) |
| :--- | :--- | :--- | :--- |
| `src/... :: fn_name (L..)` | | | |
| `crates/ap-.../src/lib.rs :: ...` | | | |

**架构一致性自检（Architecture Parity）**：
- [ ] CLI 参数/命令变更已同步更新 `src/mcp.rs`（Schema & Tool 描述）
- [ ] 中英文文档已同步（`*.md` & `*.zh-CN.md`）
- [ ] 0 新增外部运行时依赖；未引入不必要的 Cargo 依赖
- [ ] `crates/ap-*` 7 个子 crate 保持 **0 兄弟依赖**
- [ ] 热循环中无 `Regex::new`（统一使用 `OnceLock`）
- [ ] `skills/*/SKILL.md` 前导词预算未超标

---

## 4. 真实实践测试与前后对照 / Empirical Verification (Before vs After)

- **新增/更新的合成测试**（`cargo test` 用例名，使用虚构路径/`example.com`）：
  - `...`

| 对比维度 (`Metric`: 耗时 / 步数 / 报错率 / 输出字节 / 缓存·Token) | 改前 (`Before`) | 改后 (`After`) | 复现实验命令 (`Repro Command`) |
| :--- | :--- | :--- | :--- |
| 实测场景 1 | | | |
| 基准耗时 / 体积 | | | |

**本地门禁实测全部通过**：
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`（注明通过总数：`__/__`）
- [ ] `ap doctor` / 目标场景实操冒烟通过

---

## 5. 风险边界、取舍与回滚 / Risks, Trade-offs & Rollback

- **跨平台影响（Windows / macOS / Linux）与已知边界**：
- **放弃的备选方案与取舍原因**：
- **清晰回滚路径**（例如：`git revert <sha>` / `ap pi restore`）：

---

## 6. 隐私与防误用红线自检 / Privacy & Anti-Misuse Checklist（必填）

- [ ] 已逐行复核 `git diff` 与提交信息：**0** 私人项目名、业务代码、用户提示词原文、本机用户名/绝对路径、内网地址、账号、Cookie、Token 或密钥。
- [ ] 所有测试样例、Fixture 与示例输出均 100% 脱敏合成。
- [ ] 所有新增/修改能力严格限定于**通用软件工程、排障调试、QA 自动化测试及授权防御性配置核查**，**严禁误用**（不含任何未授权攻击载荷、漏洞利用或凭据窃取功能）。
