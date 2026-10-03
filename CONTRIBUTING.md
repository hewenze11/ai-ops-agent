# 贡献指南

感谢你想参与 AI Ops 执行端（Linux Agent）。这是**执行链路预览**，接口与协议仍会变动。

## 开始之前

- 协议权威文档在主服务仓库 `hewenze11/ai-ops` 的 `docs/protocol-v11.md`。改协议相关行为时，两个仓库要一起考虑兼容性。
- 本项目**由所有者驱动**：欢迎 issue，较大改动先开 issue 对齐方向再提 PR。
- 安全优先于便利：任何降低隔离的改动（换 root、放宽账号检查、静默重放命令）默认不接受。

## 开发环境

```sh
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install '.[test]'
pytest -q
```

部分测试仅 Linux 有效；跨用户执行测试需要 root，建议在隔离容器内跑。

## 提交规范

- 提交信息用祈使句，说明"做了什么/为什么"。
- 一个 PR 聚焦一件事；新行为要有测试。

## 安全红线

- 不要硬编码任何真实密钥 / token。
- 不要让 Agent 在失败时"换 root 或其他账号"重试。
- 不要把 `started` 的命令在重启后重放。

## 报告问题

- 普通 bug / 功能建议：开 issue。
- **安全漏洞：不要开公开 issue**，见 [SECURITY.md](SECURITY.md)。

## 许可证

本项目采用 **AGPL-3.0**（见 [LICENSE](LICENSE)）。提交 PR 即表示你同意贡献在 AGPL-3.0 下发布。
