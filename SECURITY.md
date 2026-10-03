# Security Policy

## 支持的版本

预览阶段（`0.1.0.dev*`），**只有 `main` 接受安全修复**。

## 报告漏洞

**请不要用公开 issue。** 请用仓库 **Security → Report a vulnerability** 私密提交。

请尽量包含：受影响版本/提交、复现步骤、影响范围、以及（可选）修复建议。

## 处理预期

数天内确认；修复前请勿公开；修复后在 release 说明致谢（可要求匿名）。

## 已知边界（设计如此）

- **Agent 以 root 启动以切换普通账号**：最小权限由**账号白名单**保证；unit 不带 `NoNewPrivileges`（会破坏切账号），见主服务 `docs/operations.md`。
- **不提供 exactly-once / 绝对安全**：断连不等于命令已停止；`unknown` 必须人工处置。
- **cgroup 清理依赖 cgroup v2 可写**，缺失时降级为进程组终止。
