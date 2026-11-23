# Pi Coding Agent 运行时维护手册（`ap pi` + `zz-ap-accelerator.ts`）

`ap` 统一维护面向 `@earendil-works/pi-coding-agent` v1.5+ 的零提示词开销扩展（`zz-ap-accelerator.ts`，经 `ap init -a pi --with-hooks --no-rules` 安装）与纯 Rust 幂等运行时补丁器（`ap pi`）。

## 常用命令

```bash
# 查看自动发现的 @earendil-works/pi-coding-agent 安装目录与 11 项补丁状态
ap pi status

# 幂等应用全部 11 项通用运行时补丁（原文件安全备份至 ~/.ap/pi-backups/<version>/，不污染 node_modules）
ap pi patch

# 仅预演不写盘
ap pi patch --dry-run

# 从 ~/.ap/pi-backups/<version>/ 一键还原原始文件
ap pi restore
```

若 Pi 安装在自定义目录，可传 `--pi-dir <path>` 或设置环境变量 `PI_PACKAGE_DIR`。

## 维护的 11 项通用 Pi v1.5+ 运行时补丁

1. **`before_agent_start_entries`**：扩展 `emitBeforeAgentStart` 与 `AgentSession._prepareRun`，允许 `before_agent_start` 钩子返回 `entries?: SessionBoundaryDraft[]`，实现 0ms 原位清脑边界且保留完整日志与前缀缓存。
2. **`windows_python_utf8`**：在 Windows 子进程环境中自动注入 `PYTHONUTF8=1`、`PYTHONIOENCODING=utf-8`、`LANG=C.UTF-8` 与 `LC_ALL=C.UTF-8`，根治 GBK 编解码崩溃。
3. **`codemode_sleep_and_workers`**：向 QuickJS `codemode` 沙箱注入可中止的 `await sleep(ms)`（上限 30s），并将并发 worker 上限从 `2` 提升至 `4`。
4. **`http_keepalive_and_transient_retry`**：加固 HTTP/TCP Keep-Alive（15s/28s/10s）、250ms Happy-Eyeballs 故障转移，及瞬时 TLS/Socket/网关断流的抖动指数退避重试。
5. **`virtual_model_cache_warmer`**：让虚拟模型（`api === "pi-virtual"`，如 `deepseek/flash-auto`）正确匹配物理会话的 `CacheWarmer` 保温。
6. **`codemode_web_builtins`**：向 QuickJS `codemode` 沙箱注入 `setTimeout`/`clearTimeout`/`atob`/`btoa`/`TextEncoder`/`TextDecoder`/`Buffer`，且避免包装器遮蔽全局 prelude。
7. **`sequential_shell_tool_barrier`**：将 `bash`/`powershell` 作为串行屏障执行，同时保持相邻只读 `read`/搜索调用并行，消除 `bash`+`read` 竞态 `ENOENT`。
8. **`boundary_compaction_event`**：扩展提交边界压缩草案时同步派发 `session_compact` 事件，确保缓存追踪器与扩展在自动轮换后状态干净重置。
9. **`cjk_calibrated_compaction_budget`**：对 CJK 全角字符加权并用模型实报 `prompt_tokens` 校准 `keepRecentTokens`，杜绝中文会话压缩过留 2–3 倍。
10. **`deterministic_tool_order`**：按工具名确定性字典序排列上下文工具列表，彻底杜绝 MCP 重连/重载触发的 KV-Cache 击穿。
11. **`codemode_text_returns_rendered`**：让 QuickJS `codemode` 助手函数 `text(value)` 输出并返回渲染后字符串，根除 `text(x).slice()` 的 `TypeError`。

## 联动守卫感知 `ap atlas surface` 与 `ap baton frontier` 消除长任务疲劳

长会话后期仅靠上下文记忆容易误判覆盖度或重复死胡同，推荐将清脑轮换（`/ap fresh [goal]` 或 `before_agent_start` 零历史边界）与外部确定性探索前沿搭配使用：

```bash
# 1. 一次扫描源码、配置清单、归档及原生 PE/ELF/Mach-O 二进制，按 9 条正交轴线与守卫位置标注（none_nearby/guard_after/guard_before）建立前沿
ap atlas surface . --include-binaries --json | ap baton frontier seed --stdin

# 2. 按“未探轴线绝对优先”策略取出下一批 Top-K 未测目标
ap baton frontier next -k 5

# 3. 标记已测/已停项，确保每次清脑切换后绝不重跑死胡同
ap baton frontier mark <id-or-target> --status stopped --reason "已核实"
```
