# AI Ops Linux Agent

独立 Linux 执行端，版本 `0.1.0.dev2`，支持执行协议 `1.1`（兼容 1.0 服务端）。**执行链路预览，不是生产版本。**不调用LLM、不需要模型Key、不管理聊天和记忆。

主服务仓库 `hewenze11/ai-ops` 中的 `docs/protocol-v11.md` 是当前协议权威来源（`protocol-v1.md` 为 1.0）。两个仓库独立构建和版本发布；当前精确匹配协议1.1，不假装兼容未知版本。

## Linux 安装

需要 Python 3.11+。为了原生系统用户切换，推荐独立venv + systemd，不推荐把宿主机用户执行塞进特权容器。

```sh
python3 -m venv /opt/ai-ops-agent/venv
/opt/ai-ops-agent/venv/bin/pip install .
install -d -m 700 /etc/ai-ops-agent /var/lib/ai-ops-agent
```

示例配置另存为 `/etc/ai-ops-agent/config.json`，以实际服务运行用户拥有，权限0600。Token通过主服务管理员资产配置一次性取得，不要粘贴到聊天或提交Git。

```json
{
  "server_url": "https://your-control.example",
  "asset_id": "your-registered-asset",
  "agent_token": "REPLACE_FROM_SECURE_PROVISIONING",
  "allowed_users": ["ops_read"],
  "journal_dir": "/var/lib/ai-ops-agent"
}
```

账号必须提前真实存在，并由用户配置原生权限。账号名称不意味着只读。切换其他用户需要root启动Agent；命令子进程按指定账户降权，清空继承环境，不继承Token。若允许执行root，该账号能够控制机器及读取Agent秘密，这是明确的剩余风险。

```sh
chmod 600 /etc/ai-ops-agent/config.json
/opt/ai-ops-agent/venv/bin/ai-ops-agent --config /etc/ai-ops-agent/config.json
```

`--once` 适用于联调：处理待回传结果并尝试领取一个任务。仅本机开发可设置 `server_url=http://127.0.0.1:18765`、`allow_loopback_http=true`，不能用于非loopback明文连接。

## 已实现

- 双重账号检查：既在主服务任务的execution_users中，也在本地allowed_users中。
- 系统账号不存在明确失败，不换root、不尝试其他账号。
- 受控环境变量、超时与进程组终止、各流64KiB输出限制和截断标记。
- 原子写入并fsync的执行日记；重启时started标unknown，不重放。
- 结果回传失败持久化重试；同一日记目录进程锁。
- 心跳与取消轮询：约每 2 秒一次，使用短超时，不阻塞正在运行的命令。
- 运行中取消：轮询到取消请求后杀整个进程组，上报 `cancelled`；取消前再确认一次，避免启动即被取消的命令。
- cgroup后代清理：cgroup v2可写时为每条命令建独立任务cgroup，结束时写`cgroup.kill`回收，包括用setsid脱离进程组的逃逸后代；不可用时退回进程组终止。
- 原始输出归档：stdout/stderr 边读边写本地文件，上传前重新核对摘要，分块幂等重传。
- HTTPS证书验证、拒绝认证请求重定向和环境代理。

## 未完成/不可宣称

压缩和保留策略、凭据轮换、长任务恢复观察、注册向导。当前没有对任意命令提供绝对安全或exactly-once保证；断连不等于命令已停止。cgroup清理依赖cgroup v2可写，缺失时降级为进程组终止。

## 测试与交付

`pip install '.[test]' && pytest -q`。部分测试要求Linux，跨用户测试要求root（在隔离容器内验证）。CI同时测试Python3.11/3.12、运行容器内原生用户测试、打包wheel/sdist，并构建非特权测试镜像推送GHCR。版本标签触发GitHub Release附件。

容器镜像只管理其容器内用户/文件，不代表可以管理宿主机。默认镜像以nobody运行，不提供自动特权容器部署。

常驻安装、升级与卸载使用 `ai-ops-agent-install`（生成 systemd 单元与 0600 配置，不隐式删除任何东西），步骤见主服务 `docs/operations.md`。

许可证待项目所有者确定。
