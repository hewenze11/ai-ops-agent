#!/usr/bin/env bash
# AI Ops 执行 Agent · 一条命令部署脚本
#
# 用法：
#   curl -fsSL https://github.com/hewenze11/ai-ops-agent/releases/latest/download/install.sh | bash
#
# 部署后请编辑配置文件：$AI_OPS_AGENT_DIR/agent.json
# 需要填入主服务注册资产时返回的 asset_id 与一次性 Token。

set -euo pipefail

APP_NAME="ai-ops-agent"
IMAGE_DEFAULT="ghcr.io/hewenze11/ai-ops-agent:latest"
INSTALL_DIR="${AI_OPS_AGENT_DIR:-/opt/ai-ops-agent}"
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    -d=*|--dir=*) INSTALL_DIR="${arg#*=}" ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^set -euo/d'; exit 0 ;;
  esac
done

c_reset=$'\033[0m'; c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_info=$'\033[36m'
say(){ printf '%s\n' "$*"; }
ok(){ printf '%s✓%s %s\n' "$c_ok" "$c_reset" "$*"; }
warn(){ printf '%s!%s %s\n' "$c_warn" "$c_reset" "$*"; }
err(){ printf '%s✗%s %s\n' "$c_err" "$c_reset" "$*" >&2; }
step(){ printf '\n%s==> %s%s\n' "$c_info" "$*" "$c_reset"; }

ask_yes_no() {
  if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
  if [ ! -t 0 ]; then warn "非交互环境，默认不安装：$1"; return 1; fi
  local reply; read -r -p "$1 [y/N] " reply </dev/tty || true
  case "$reply" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}
require_sudo() {
  if [ "$(id -u)" -eq 0 ]; then SUDO=""; return; fi
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; return; fi
  err "需要 root 权限创建 $INSTALL_DIR，且系统没有 sudo。"; exit 1
}

step "检查运行环境"
missing=()
command -v docker >/dev/null 2>&1 && ok "docker 已安装" || { warn "缺少 docker"; missing+=("docker"); }
if command -v docker >/dev/null 2>&1; then
  docker compose version >/dev/null 2>&1 && ok "docker compose v2 已安装" || { warn "缺少 compose v2"; missing+=("compose"); }
fi
if printf '%s\n' "${missing[@]:-}" | grep -q docker; then
  warn "自动安装 Docker 会修改系统软件源并需要 root。"
  if ask_yes_no "是否现在自动安装 Docker（官方 get.docker.com 脚本）？"; then
    require_sudo; curl -fsSL https://get.docker.com | $SUDO sh; $SUDO systemctl enable --now docker || true
  else
    err "请先手动安装 Docker Engine + Compose v2。"; exit 1
  fi
fi
require_sudo

step "准备专属目录 $INSTALL_DIR"
if [ ! -e "$INSTALL_DIR" ]; then
  $SUDO install -d -m 700 -o 10001 -g 10001 "$INSTALL_DIR"
  $SUDO install -d -m 700 -o 10001 -g 10001 "$INSTALL_DIR/journal"
  $SUDO install -d -m 700 -o 10001 -g 10001 "$INSTALL_DIR/work"
  $SUDO install -d -m 700 -o 10001 -g 10001 "$INSTALL_DIR/logs"
  ok "已创建 journal / work / logs"
else
  ok "目录已存在：$INSTALL_DIR"
fi

cfg="$INSTALL_DIR/agent.json"
if [ -f "$cfg" ]; then
  ok "配置文件已存在，保留不覆盖：$cfg"
else
  $SUDO tee "$cfg" >/dev/null <<'EOF'
{
  "_说明": "AI Ops 执行 Agent 配置。删掉本行注释字段不影响运行。",
  "asset_id": "在此填入主服务注册资产后返回的资产ID",
  "controllers": [
    {
      "name": "main",
      "url": "http://主服务IP:8765",
      "token": "在此填入该资产的一次性Agent Token",
      "enabled": true
    }
  ],
  "allowed_users": ["aiops"],
  "journal_dir": "/var/lib/ai-ops-agent",
  "allow_loopback_http": true
}
EOF
  $SUDO chown 10001:10001 "$cfg"; $SUDO chmod 600 "$cfg"
  ok "已生成配置文件：$cfg（含示例与提示）"
fi

step "写入 Compose 文件"
$SUDO tee "$INSTALL_DIR/docker-compose.yml" >/dev/null <<'EOF'
services:
  agent:
    image: ${AI_OPS_AGENT_IMAGE:-ghcr.io/hewenze11/ai-ops-agent:latest}
    restart: unless-stopped
    init: true
    network_mode: host
    volumes:
      - ./agent.json:/etc/ai-ops-agent/config.json:ro
      - ./journal:/var/lib/ai-ops-agent
      - ./work:/home/aiops
      - ./logs:/var/log/ai-ops
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
EOF
ok "已写入 docker-compose.yml"

step "下一步"
warn "请先编辑 $cfg 填入 asset_id 与 Token，然后执行："
say "  cd $INSTALL_DIR && sudo docker compose pull && sudo docker compose up -d"
say ""
say "  查看日志：cd $INSTALL_DIR && sudo docker compose logs -f agent"
say "  配置文件：$cfg"
