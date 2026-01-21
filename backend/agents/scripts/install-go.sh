#!/bin/sh
# Go Agent 安装脚本（单二进制版本）
# 支持系统：Linux (amd64/arm64/armv7)
# 服务类型：{service_type}
# Agent 名称：{agent_name}

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

printf "%b\n" "${{GREEN}}================================${{NC}}"
printf "%b\n" "${{GREEN}}Go Agent 安装脚本${{NC}}"
printf "%b\n" "${{GREEN}}服务类型: {service_type}${{NC}}"
printf "%b\n" "${{GREEN}}Agent 名称: {agent_name}${{NC}}"
printf "%b\n" "${{YELLOW}}模式: Go 版本（单二进制，高性能）${{NC}}"
printf "%b\n" "${{GREEN}}================================${{NC}}"

# 检查是否为 root 用户
if [ "$(id -u)" -ne 0 ]; then
    printf "%b\n" "${{RED}}请使用 root 用户运行此脚本${{NC}}"
    exit 1
fi

# 检查是否已安装
ALREADY_INSTALLED=0
if [ -f /usr/local/bin/configflow-agent ] || [ -f /etc/systemd/system/configflow-agent.service ] || [ -f /etc/init.d/configflow-agent ]; then
    ALREADY_INSTALLED=1
fi

# 显示操作菜单
printf "\n"
if [ $ALREADY_INSTALLED -eq 1 ]; then
    printf "%b\n" "${{YELLOW}}检测到 Go Agent 已安装${{NC}}"
else
    printf "%b\n" "${{GREEN}}准备安装 Go Agent${{NC}}"
fi
printf "\n"
printf "%b\n" "${{BLUE}}请选择操作:${{NC}}"
printf "%b\n" "  1) 安装 (如已安装则覆盖)"
printf "%b\n" "  2) 卸载"
printf "%b\n" "  3) 取消"
printf "\n"
printf "%b" "${{BLUE}}请输入选项 [1-3]: ${{NC}}"

read -r choice < /dev/tty

case "$choice" in
    1)
        if [ $ALREADY_INSTALLED -eq 1 ]; then
            printf "%b\n" "${{YELLOW}}开始重新安装...${{NC}}"
        else
            printf "%b\n" "${{YELLOW}}开始安装...${{NC}}"
        fi
        ;;
    2)
        printf "%b\n" "${{YELLOW}}开始卸载 Go Agent...${{NC}}"

        # 检测系统类型
        if [ -f /etc/alpine-release ]; then
            OS_TYPE="alpine"
        elif command -v systemctl >/dev/null 2>&1; then
            OS_TYPE="systemd"
        else
            OS_TYPE="unknown"
        fi

        # 停止并删除服务
        if [ "$OS_TYPE" = "alpine" ]; then
            printf "%b\n" "${{YELLOW}}停止 OpenRC 服务...${{NC}}"
            rc-service configflow-agent stop 2>/dev/null || true
            rc-update del configflow-agent default 2>/dev/null || true
            rm -f /etc/init.d/configflow-agent
            rc-update -u 2>/dev/null || true
        elif [ "$OS_TYPE" = "systemd" ]; then
            printf "%b\n" "${{YELLOW}}停止 systemd 服务...${{NC}}"
            systemctl stop configflow-agent 2>/dev/null || true
            systemctl disable configflow-agent 2>/dev/null || true
            rm -f /etc/systemd/system/configflow-agent.service
            systemctl daemon-reload 2>/dev/null || true
        fi

        # 删除文件
        printf "%b\n" "${{YELLOW}}删除程序文件和配置...${{NC}}"
        rm -f /usr/local/bin/configflow-agent
        rm -rf /opt/configflow-agent
        rm -f /var/log/configflow-agent.log
        rm -f /var/log/configflow-agent.log.*
        rm -f /etc/logrotate.d/configflow-agent

        printf "\n"
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{GREEN}}Go Agent 卸载完成！${{NC}}"
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        exit 0
        ;;
    3|*)
        printf "%b\n" "${{YELLOW}}操作已取消${{NC}}"
        exit 0
        ;;
esac

# 继续安装流程
set -e

# 检测系统架构
printf "%b\n" "${{YELLOW}}检测系统架构...${{NC}}"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        AGENT_ARCH="linux-amd64"
        ;;
    aarch64|arm64)
        AGENT_ARCH="linux-arm64"
        ;;
    armv7l|armhf)
        AGENT_ARCH="linux-armv7"
        ;;
    *)
        printf "%b\n" "${{RED}}不支持的系统架构: $ARCH${{NC}}"
        printf "%b\n" "${{YELLOW}}支持的架构: x86_64, aarch64, armv7l${{NC}}"
        exit 1
        ;;
esac
printf "%b\n" "${{GREEN}}检测到架构: $ARCH -> $AGENT_ARCH${{NC}}"

# 检测系统类型
if [ -f /etc/alpine-release ]; then
    OS_TYPE="alpine"
    INIT_SYSTEM="openrc"
    printf "%b\n" "${{GREEN}}检测到系统: Alpine Linux (OpenRC)${{NC}}"
elif command -v systemctl >/dev/null 2>&1; then
    OS_TYPE="systemd"
    INIT_SYSTEM="systemd"
    printf "%b\n" "${{GREEN}}检测到系统: Linux with systemd${{NC}}"
else
    printf "%b\n" "${{RED}}不支持的系统类型${{NC}}"
    exit 1
fi

# 检查并安装必要工具
printf "%b\n" "${{YELLOW}}检查必要工具...${{NC}}"

# 检查 wget 或 curl
if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    printf "%b\n" "${{RED}}需要 wget 或 curl 来下载二进制文件${{NC}}"
    exit 1
fi

# 下载 Go Agent 二进制
BINARY_URL="{binary_download_url}/configflow-agent-$AGENT_ARCH"
printf "%b\n" "${{YELLOW}}下载 Go Agent 二进制...${{NC}}"
printf "%b\n" "${{BLUE}}URL: $BINARY_URL${{NC}}"

if command -v wget >/dev/null 2>&1; then
    wget -O /tmp/configflow-agent "$BINARY_URL" || {{
        printf "%b\n" "${{RED}}下载失败！${{NC}}"
        exit 1
    }}
else
    curl -L -o /tmp/configflow-agent "$BINARY_URL" || {{
        printf "%b\n" "${{RED}}下载失败！${{NC}}"
        exit 1
    }}
fi

# 设置可执行权限
chmod +x /tmp/configflow-agent

# 安装二进制到系统
printf "%b\n" "${{YELLOW}}安装 Go Agent 到系统...${{NC}}"
mv /tmp/configflow-agent /usr/local/bin/configflow-agent

# 创建配置目录
AGENT_DIR="/opt/configflow-agent"
printf "%b\n" "${{YELLOW}}创建配置目录: $AGENT_DIR${{NC}}"
mkdir -p $AGENT_DIR

# 创建配置文件
printf "%b\n" "${{YELLOW}}创建配置文件...${{NC}}"
cat > $AGENT_DIR/config-{service_type}.json << EOF
{{
  "server_url": "{server_url}",
  "agent_name": "{agent_name}",
  "agent_host": "{agent_host}",
  "agent_port": {agent_port},
  "agent_ip": "{agent_ip}",
  "service_type": "{service_type}",
  "service_name": "{service_name}",
  "config_path": "{config_path}",
  "restart_command": "{restart_command}",
  "heartbeat_interval": 30
}}
EOF

# 配置日志轮转
printf "%b\n" "${{YELLOW}}配置日志轮转...${{NC}}"

# 如果没有 logrotate，尝试安装
if ! command -v logrotate >/dev/null 2>&1; then
    if [ -f /etc/alpine-release ]; then
        # Alpine Linux
        apk add --no-cache logrotate >/dev/null 2>&1 || true
    elif command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu
        apt-get update -qq && apt-get install -y -qq logrotate >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        # CentOS/RHEL
        yum install -y -q logrotate >/dev/null 2>&1 || true
    fi
fi

# 配置 logrotate（如果安装成功）
if command -v logrotate >/dev/null 2>&1; then
    cat > /etc/logrotate.d/configflow-agent << 'LOGROTATE_EOF'
/var/log/configflow-agent.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    size 50M
    copytruncate
}
LOGROTATE_EOF
    printf "%b\n" "${{GREEN}}日志轮转配置完成（保留7天，超过50M自动轮转）${{NC}}"
else
    printf "%b\n" "${{YELLOW}}跳过日志轮转配置（logrotate 未安装）${{NC}}"
fi

# 根据 Init 系统创建服务
if [ "$INIT_SYSTEM" = "openrc" ]; then
    # Alpine Linux - OpenRC 服务
    printf "%b\n" "${{YELLOW}}创建 OpenRC 服务...${{NC}}"
    cat > /etc/init.d/configflow-agent << 'INITEOF'
#!/sbin/openrc-run

name="ConfigFlow Agent (Go)"
description="ConfigFlow Agent for remote service management"

command="/usr/local/bin/configflow-agent"
command_args="-config /opt/configflow-agent/config-{service_type}.json"
pidfile="/run/configflow-agent.pid"
output_log="/var/log/configflow-agent.log"
error_log="/var/log/configflow-agent.log"
directory="/opt/configflow-agent"
command_background="yes"

depend() {{
    need net
    after firewall
}}

start_pre() {{
    checkpath --directory --mode 0755 /var/log
    checkpath --file --mode 0644 --owner root:root /var/log/configflow-agent.log
}}
INITEOF

    chmod +x /etc/init.d/configflow-agent

    # 清理旧服务状态
    printf "%b\n" "${{YELLOW}}清理旧的服务状态...${{NC}}"
    rc-service configflow-agent stop 2>/dev/null || true
    rc-update del configflow-agent default 2>/dev/null || true
    rc-update -u 2>/dev/null || true
    sleep 1

    # 启动服务
    printf "%b\n" "${{YELLOW}}启动 Agent 服务...${{NC}}"
    rc-update add configflow-agent default
    rc-service configflow-agent start

    sleep 2

    # 检查服务状态
    if rc-service configflow-agent status | grep -q "started"; then
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{GREEN}}Go Agent 安装成功！${{NC}}"
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{YELLOW}}服务状态: ${{NC}}"
        rc-service configflow-agent status
        printf "%b\n" ""
        printf "%b\n" "${{YELLOW}}查看日志: ${{NC}}tail -f /var/log/configflow-agent.log"
        printf "%b\n" "${{YELLOW}}停止服务: ${{NC}}rc-service configflow-agent stop"
        printf "%b\n" "${{YELLOW}}重启服务: ${{NC}}rc-service configflow-agent restart"
    else
        printf "%b\n" "${{RED}}================================${{NC}}"
        printf "%b\n" "${{RED}}Agent 启动失败！${{NC}}"
        printf "%b\n" "${{RED}}================================${{NC}}"
        printf "%b\n" "${{YELLOW}}查看错误日志: ${{NC}}tail -n 50 /var/log/configflow-agent.log"
        exit 1
    fi

elif [ "$INIT_SYSTEM" = "systemd" ]; then
    # systemd 服务
    printf "%b\n" "${{YELLOW}}创建 systemd 服务...${{NC}}"
    cat > /etc/systemd/system/configflow-agent.service << EOF
[Unit]
Description=ConfigFlow Agent (Go)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/configflow-agent
ExecStart=/usr/local/bin/configflow-agent -config /opt/configflow-agent/config-{service_type}.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # 重载 systemd
    printf "%b\n" "${{YELLOW}}重载 systemd...${{NC}}"
    systemctl daemon-reload

    # 清理旧服务状态
    printf "%b\n" "${{YELLOW}}清理旧的服务状态...${{NC}}"
    systemctl stop configflow-agent 2>/dev/null || true
    sleep 1

    # 启动服务
    printf "%b\n" "${{YELLOW}}启动 Agent 服务...${{NC}}"
    systemctl enable configflow-agent
    systemctl start configflow-agent

    sleep 2

    # 检查服务状态
    if systemctl is-active --quiet configflow-agent; then
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{GREEN}}Go Agent 安装成功！${{NC}}"
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{YELLOW}}服务状态: ${{NC}}"
        systemctl status configflow-agent --no-pager -l
        printf "%b\n" ""
        printf "%b\n" "${{YELLOW}}查看日志: ${{NC}}journalctl -u configflow-agent -f"
        printf "%b\n" "${{YELLOW}}停止服务: ${{NC}}systemctl stop configflow-agent"
        printf "%b\n" "${{YELLOW}}重启服务: ${{NC}}systemctl restart configflow-agent"
    else
        printf "%b\n" "${{RED}}================================${{NC}}"
        printf "%b\n" "${{RED}}Agent 启动失败！${{NC}}"
        printf "%b\n" "${{RED}}================================${{NC}}"
        printf "%b\n" "${{YELLOW}}查看错误日志: ${{NC}}journalctl -u configflow-agent -n 50"
        exit 1
    fi
else
    printf "%b\n" "${{RED}}不支持的 Init 系统${{NC}}"
    exit 1
fi
