# Agent容器：自己配置，从零接入主服务

需要Linux、Docker、Compose v2。镜像不含Token、主服务地址或旧执行日记，不运行一键安装脚本。

## 先确定你要管理哪里

- **本容器部署**：管理容器内 `aiops` 用户及 `work/` 工作目录，适合体验Agent注册、心跳、授权、执行、结果回传。容器里未预装业务软件，请自己构建派生镜像或安装所需工具。
- **管理真正的Linux宿主**：用主服务SSH方式，或按本仓库README手工安装原生Agent。普通容器不能直接使用宿主用户/systemd；`network_mode: host`只共享网络，不改变这一事实。
- 不需要 `--privileged`，不默认挂Docker socket、宿主根目录或宿主PID空间。

## 1. 先在主服务登记

主服务“资产 → 注册资产 → Agent”，允许账号填 **aiops**。保存返回的资产ID与一次性Agent Token；不是主服务管理员Token。

## 2. 获取配置，亲自编辑

```sh
git clone https://github.com/hewenze11/ai-ops-agent.git
cd ai-ops-agent
cp .env.example .env
cp config.example.json config.json
chmod 600 config.json
# 先用你习惯的编辑器修改，再调整为容器账号所有。
vi config.json
sudo install -d -m 700 -o 10001 -g 10001 journal work
sudo chown 10001:10001 config.json
sudo chmod 600 config.json
```

`config.json` 中：
- `asset_id`：主服务实际返回的资产ID，不能只填显示名称。
- `controllers[0].url`：主服务HTTPS入口，仅scheme+主机+端口，无 `/api/...` 路径。
- `controllers[0].token`：该资产的Agent Token。
- `allowed_users`：默认镜像只需 `["aiops"]`，与主服务登记相同；此账号UID/GID是10001。
- `journal_dir`：保持 `/var/lib/ai-ops-agent`，Compose将宿主 `journal/` 挂到这里。
- `allow_loopback_http`：一般保持false。只有下面的本机回环测试才改true。

### 没有HTTPS域名，怎么试？

如果主服务就在Agent宿主，URL填 `http://127.0.0.1:8765`，`allow_loopback_http`填true。

如果主服务在另一台机器，先在 **Agent宿主Linux** 单独开一个终端保持隧道：

```sh
ssh -N -L 127.0.0.1:18765:127.0.0.1:8765 your-user@CONTROL_SERVER_IP
```

然后URL填 `http://127.0.0.1:18765`，`allow_loopback_http`填true。Compose使用Linux host网络，因此容器能访问宿主的回环隧道。关闭该SSH进程后连接会断开；这个手工体验步骤不自动创建systemd服务。

**不能**填 `http://192.168...`/公网IP后只设置true来放开明文；程序只允许显式loopback HTTP，其他地址用HTTPS。

## 3. 拉取启动

当前GHCR包需要登录授权（代码仓库公开不等于镜像可匿名拉取）：

```sh
docker login ghcr.io -u YOUR_GITHUB_USERNAME
```

在密码提示中输入你自己的、有 `read:packages` 且能访问该包的GitHub Token，不是GitHub账号密码；勿把Token放进命令行。也可直接使用下方本地构建，不依赖GHCR授权。

```sh
docker compose pull && docker compose up -d --no-build
docker compose ps
docker compose logs --tail=100 agent
```

自己构建仓库Dockerfile：

```sh
AI_OPS_AGENT_IMAGE=ai-ops-agent:manual docker compose up -d --build
```

无入站端口，无模型配置。进入主服务核对该资产心跳/在线状态，才算连通；容器running本身不代表鉴权成功。

在聊天中选该资产与 `aiops`，confirm模式测试 `id; hostname; pwd`，应看到容器环境、UID10001和 `/home/aiops`。可在该目录创建测试文件，再在宿主 `work/` 查看。不把容器文件当宿主系统文件。

## 4. 文件与权限

- `config.json`：UID10001所有，0600，只读挂进容器。权限错会明确启动失败，不自动放宽。
- `journal/`：执行日记/回传状态。重建容器仍保留，避免丢失结果；不是业务工作目录。
- `work/`：你测试的业务文件，容器路径 `/home/aiops`。
- `.env`：仅镜像标签，无真实Token。

默认Agent以aiops运行，只执行自身账号；同UID任务有能力读到该Agent配置，因此这是一个共同信任域，不是同账号凭据隔离沙箱。若要试多账号，需自行定制镜像中真实账号和执行权限；宿主运维建议走原生Agent或SSH，不靠容器root冒充宿主root。

```sh
# 修改配置后
sudoedit config.json
docker compose restart agent
# 停止删除容器（保留你自己的配置/日记/工作文件）
docker compose down
```

先停止/核实执行，再清空任何journal目录。不以删除日记处理未知执行。进程组终止不等于在所有容器环境中都能清理逃逸后台进程；cgroup v2回收取决于可写委派，本Compose不授予宿主cgroup管理权限。
