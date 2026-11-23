# Security & Responsible-Use Policy / 安全与负责任使用政策

## Responsible Engineering Scope / 合法使用边界

`ap` (`xgbtxy/ap`) is built strictly for **general software engineering, debugging, automated QA verification, and authorized defensive security/configuration hygiene** on systems you own or have explicit permission to inspect.

Do **not** submit or use `ap` for exploit payloads, unauthorized access, credential harvesting, or bypassing access controls.

`ap` 仅面向**通用软件工程、排障调试、QA 自动化测试以及对自有或已获明确授权系统的防御性安全配置核查**。严禁用于未授权访问、攻击载荷生成、凭据窃取或绕过安全边界。

---

## Local-Only Telemetry & Privacy / 本地离线隐私保障

- `ap stats` and `ap audit --maintainer` execute **100% offline** with zero cloud telemetry or external uploads.
- `ap audit --maintainer` emits anonymized numeric friction counters and mapped `ap` source modules **only** — zero prompts, business code, local host paths, or credentials.

---

## Reporting a Vulnerability / 漏洞报告渠道

If you discover a security vulnerability in `ap` (e.g., command-injection edge cases in shell auto-healing, path-traversal issues in archive extraction, or unintended secret disclosure):

- **Do not** disclose the issue in public GitHub Issues or Pull Requests before a fix is released.
- Report privately via **[GitHub Security Advisories](https://github.com/xgbtxy/ap/security/advisories/new)**.
- Include the `ap --version` output, OS/architecture, minimal synthetic repro steps (using dummy data/paths only), and suggested mitigation if available.
