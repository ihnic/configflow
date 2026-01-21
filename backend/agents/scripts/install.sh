#!/bin/sh
# Agent 轻量级安装脚本（Shell 版本，无 Python 依赖）
# 支持系统：Alpine Linux, Debian, Ubuntu, CentOS, RHEL, Rocky Linux, AlmaLinux 等
# 服务类型：{service_type}
# Agent 名称：{agent_name}

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

printf "%b\n" "${{GREEN}}================================${{NC}}"
printf "%b\n" "${{GREEN}}Agent 轻量级安装脚本${{NC}}"
printf "%b\n" "${{GREEN}}服务类型: {service_type}${{NC}}"
printf "%b\n" "${{GREEN}}Agent 名称: {agent_name}${{NC}}"
printf "%b\n" "${{YELLOW}}模式: Shell 版本（无 Python 依赖）${{NC}}"
printf "%b\n" "${{GREEN}}================================${{NC}}"

# 检查是否为 root 用户
if [ "$(id -u)" -ne 0 ]; then
    printf "%b\n" "${{RED}}请使用 root 用户运行此脚本${{NC}}"
    exit 1
fi

# 检查是否已安装
ALREADY_INSTALLED=0
if [ -f /etc/init.d/configflow-agent ] || [ -f /etc/systemd/system/configflow-agent.service ]; then
    ALREADY_INSTALLED=1
fi

# 显示操作菜单（每次都显示）
printf "\n"
if [ $ALREADY_INSTALLED -eq 1 ]; then
    printf "%b\n" "${{YELLOW}}检测到 Agent 已安装${{NC}}"
else
    printf "%b\n" "${{GREEN}}准备安装 Agent${{NC}}"
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
        # 继续安装流程
        ;;
    2)
        printf "%b\n" "${{YELLOW}}开始卸载 Agent...${{NC}}"

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
            # 刷新 OpenRC 缓存
            rc-update -u 2>/dev/null || true
        elif [ "$OS_TYPE" = "systemd" ]; then
            printf "%b\n" "${{YELLOW}}停止 systemd 服务...${{NC}}"
            systemctl stop configflow-agent 2>/dev/null || true
            systemctl disable configflow-agent 2>/dev/null || true
            rm -f /etc/systemd/system/configflow-agent.service
            systemctl daemon-reload 2>/dev/null || true
        fi

        # 杀掉所有进程
        printf "%b\n" "${{YELLOW}}清理进程...${{NC}}"
        pkill -9 -f "agent.sh" 2>/dev/null || true
        pkill -9 -f "nc -l" 2>/dev/null || true
        pkill -9 -f "configflow-agent" 2>/dev/null || true

        # 删除文件
        printf "%b\n" "${{YELLOW}}删除程序文件和配置...${{NC}}"
        rm -rf /opt/configflow-agent
        rm -f /var/log/configflow-agent.log
        rm -f /var/log/configflow-agent.log.*
        rm -f /run/configflow-agent.pid
        rm -f /etc/logrotate.d/configflow-agent

        # 清理锁文件和临时文件
        printf "%b\n" "${{YELLOW}}清理锁文件和临时文件...${{NC}}"
        rm -rf /tmp/configflow-agent-main.lock
        rm -rf /tmp/configflow-agent-heartbeat.lock
        rm -f /tmp/agent_fifo_* 2>/dev/null || true

        printf "\n"
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{GREEN}}Agent 卸载完成！${{NC}}"
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

# 检测系统类型（更详细的检测）
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_VERSION="$VERSION_ID"
    OS_NAME="$NAME"
elif [ -f /etc/alpine-release ]; then
    OS_ID="alpine"
    OS_NAME="Alpine Linux"
    OS_VERSION=$(cat /etc/alpine-release)
elif [ -f /etc/centos-release ]; then
    OS_ID="centos"
    OS_NAME=$(cat /etc/centos-release)
elif [ -f /etc/redhat-release ]; then
    OS_ID="rhel"
    OS_NAME=$(cat /etc/redhat-release)
else
    OS_ID="unknown"
    OS_NAME="Unknown"
fi

# 根据发行版确定包管理器和系统类型
case "$OS_ID" in
    alpine)
        OS_TYPE="alpine"
        PKG_MANAGER="apk"
        INIT_SYSTEM="openrc"
        ;;
    debian|ubuntu|linuxmint|pop)
        OS_TYPE="debian"
        PKG_MANAGER="apt"
        INIT_SYSTEM="systemd"
        ;;
    centos|rhel|rocky|almalinux|fedora)
        OS_TYPE="redhat"
        # CentOS 8+, RHEL 8+, Rocky, AlmaLinux 使用 dnf
        if command -v dnf >/dev/null 2>&1; then
            PKG_MANAGER="dnf"
        else
            PKG_MANAGER="yum"
        fi
        INIT_SYSTEM="systemd"
        ;;
    arch|manjaro)
        OS_TYPE="arch"
        PKG_MANAGER="pacman"
        INIT_SYSTEM="systemd"
        ;;
    *)
        # 尝试检测包管理器
        if command -v apt-get >/dev/null 2>&1; then
            OS_TYPE="debian"
            PKG_MANAGER="apt"
        elif command -v dnf >/dev/null 2>&1; then
            OS_TYPE="redhat"
            PKG_MANAGER="dnf"
        elif command -v yum >/dev/null 2>&1; then
            OS_TYPE="redhat"
            PKG_MANAGER="yum"
        elif command -v apk >/dev/null 2>&1; then
            OS_TYPE="alpine"
            PKG_MANAGER="apk"
        else
            OS_TYPE="unknown"
            PKG_MANAGER="unknown"
        fi

        # 检测 init 系统
        if command -v systemctl >/dev/null 2>&1; then
            INIT_SYSTEM="systemd"
        elif command -v rc-service >/dev/null 2>&1; then
            INIT_SYSTEM="openrc"
        else
            INIT_SYSTEM="unknown"
        fi
        ;;
esac

printf "%b\n" "${{YELLOW}}检测到系统: $OS_NAME${{NC}}"
printf "%b\n" "${{YELLOW}}系统类型: $OS_TYPE, 包管理器: $PKG_MANAGER, Init系统: $INIT_SYSTEM${{NC}}"

# 检查必要的工具
printf "%b\n" "${{YELLOW}}检查必要工具...${{NC}}"

# 安装 curl
if ! command -v curl >/dev/null 2>&1; then
    printf "%b\n" "${{RED}}curl 未安装，正在安装...${{NC}}"
    case "$PKG_MANAGER" in
        apk)
            apk add --no-cache curl
            ;;
        apt)
            apt-get update && apt-get install -y curl
            ;;
        yum)
            yum install -y curl
            ;;
        dnf)
            dnf install -y curl
            ;;
        pacman)
            pacman -Sy --noconfirm curl
            ;;
        *)
            printf "%b\n" "${{RED}}无法自动安装 curl，请手动安装${{NC}}"
            exit 1
            ;;
    esac
fi

# 安装 netcat
if ! command -v nc >/dev/null 2>&1; then
    printf "%b\n" "${{YELLOW}}netcat 未安装，尝试安装...${{NC}}"
    case "$PKG_MANAGER" in
        apk)
            # Alpine 的 BusyBox 通常已包含 nc
            printf "%b\n" "${{GREEN}}BusyBox nc 可用${{NC}}"
            ;;
        apt)
            apt-get install -y netcat-openbsd || apt-get install -y netcat || true
            ;;
        yum)
            yum install -y nc || yum install -y nmap-ncat || true
            ;;
        dnf)
            dnf install -y nc || dnf install -y nmap-ncat || true
            ;;
        pacman)
            pacman -Sy --noconfirm openbsd-netcat || pacman -Sy --noconfirm gnu-netcat || true
            ;;
    esac
fi

# 安装 socat（推荐，特别是 Debian/Ubuntu 系统，性能更好）
if ! command -v socat >/dev/null 2>&1; then
    printf "%b\n" "${{YELLOW}}socat 未安装，尝试安装...${{NC}}"
    case "$PKG_MANAGER" in
        apk)
            apk add --no-cache socat || printf "%b\n" "${{YELLOW}}socat 安装失败，将使用 netcat (BusyBox nc)${{NC}}"
            ;;
        apt)
            apt-get install -y socat || printf "%b\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        yum)
            yum install -y socat || printf "%b\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        dnf)
            dnf install -y socat || printf "%b\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        pacman)
            pacman -Sy --noconfirm socat || printf "%b\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        *)
            printf "%b\n" "${{YELLOW}}未知包管理器，跳过 socat 安装，将使用 netcat${{NC}}"
            ;;
    esac
else
    printf "%b\n" "${{GREEN}}socat 已安装${{NC}}"
fi

# 创建 Agent 目录
AGENT_DIR="/opt/configflow-agent"
printf "%b\n" "${{YELLOW}}创建 Agent 目录: $AGENT_DIR${{NC}}"
mkdir -p $AGENT_DIR
cd $AGENT_DIR

# 创建 Agent 主程序文件
printf "%b\n" "${{YELLOW}}创建 Agent 程序...${{NC}}"
cat > agent.sh << 'AGENT_SHELL_EOF'
{agent_shell_content}
AGENT_SHELL_EOF

chmod +x agent.sh

# 创建配置文件
printf "%b\n" "${{YELLOW}}创建 Agent 配置文件...${{NC}}"
cat > config.json << EOF
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
    # Alpine Linux - 使用 OpenRC
    printf "%b\n" "${{YELLOW}}创建 OpenRC 服务...${{NC}}"
    cat > /etc/init.d/configflow-agent << 'INITEOF'
#!/sbin/openrc-run

name="Proxy Configuration Agent"
description="Proxy Configuration Agent for remote management"

pidfile="/run/configflow-agent.pid"
output_log="/var/log/configflow-agent.log"
error_log="/var/log/configflow-agent.log"
directory="/opt/configflow-agent"

depend() {{
    need net
    after firewall
}}

start_pre() {{
    # 杀掉所有可能残留的进程（包括 nc）
    pkill -9 -f "agent.sh" 2>/dev/null || true
    pkill -9 -f "nc -l.*8080" 2>/dev/null || true

    # 清理 PID 文件
    rm -f "$pidfile"

    # 清理所有锁文件和临时文件
    rm -f /tmp/agent_fifo_* 2>/dev/null || true
    rm -rf /tmp/configflow-agent-main.lock 2>/dev/null || true
    rm -rf /tmp/configflow-agent-heartbeat.lock 2>/dev/null || true

    # 等待进程完全退出
    sleep 2

    checkpath --directory --mode 0755 /var/log
    checkpath --file --mode 0644 --owner root:root /var/log/configflow-agent.log
}}

start() {{
    ebegin "Starting $name"

    # 直接使用 nohup 启动，避免 start-stop-daemon 的复杂性
    cd "$directory"
    nohup /bin/sh /opt/configflow-agent/agent.sh >> "$output_log" 2>&1 &
    local agent_pid=$!

    # 保存 PID
    echo "$agent_pid" > "$pidfile"

    # 等待确认启动成功
    sleep 2

    if kill -0 "$agent_pid" 2>/dev/null; then
        eend 0
    else
        eerror "Failed to start agent"
        rm -f "$pidfile"
        eend 1
    fi
}}

stop() {{
    ebegin "Stopping $name"
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        start-stop-daemon --stop --pidfile "$pidfile" --signal TERM --retry 5
        # 确保所有子进程也被杀掉
        pkill -P "$pid" 2>/dev/null || true
    fi
    # 强制清理所有 agent.sh 进程
    pkill -f "agent.sh" 2>/dev/null || true
    rm -f "$pidfile"
    eend $?
}}
INITEOF

    chmod +x /etc/init.d/configflow-agent

    # 启动服务前彻底清理
    printf "%b\n" "${{YELLOW}}清理旧的服务状态...${{NC}}"
    # 停止可能存在的旧服务
    rc-service configflow-agent stop 2>/dev/null || true
    # 从 runlevel 移除
    rc-update del configflow-agent default 2>/dev/null || true
    # 杀掉残留进程
    pkill -9 -f "agent.sh" 2>/dev/null || true
    pkill -9 -f "nc -l" 2>/dev/null || true
    # 清理 PID 文件
    rm -f /run/configflow-agent.pid
    # 清理锁文件和临时文件
    rm -rf /tmp/configflow-agent-main.lock
    rm -rf /tmp/configflow-agent-heartbeat.lock
    rm -f /tmp/agent_fifo_* 2>/dev/null || true
    # 重新缓存依赖
    rc-update -u 2>/dev/null || true
    sleep 1

    # 启动服务
    printf "%b\n" "${{YELLOW}}启动 Agent 服务...${{NC}}"
    rc-update add configflow-agent default
    sleep 1
    rc-service configflow-agent start

    # 等待服务启动
    sleep 2

    # 检查服务状态
    if rc-service configflow-agent status | grep -q "started"; then
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{GREEN}}Agent 安装成功！${{NC}}"
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
    # Debian/Ubuntu/CentOS/RHEL 等 - 使用 systemd
    printf "%b\n" "${{YELLOW}}创建 systemd 服务...${{NC}}"
    cat > /etc/systemd/system/configflow-agent.service << EOF
[Unit]
Description=Proxy Configuration Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/configflow-agent
ExecStart=/opt/configflow-agent/agent.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # 重载 systemd
    printf "%b\n" "${{YELLOW}}重载 systemd...${{NC}}"
    systemctl daemon-reload

    # 启动服务前清理旧的锁文件和临时文件
    printf "%b\n" "${{YELLOW}}清理旧的锁文件和临时文件...${{NC}}"
    systemctl stop configflow-agent 2>/dev/null || true
    pkill -9 -f "agent.sh" 2>/dev/null || true
    pkill -9 -f "nc -l" 2>/dev/null || true
    rm -rf /tmp/configflow-agent-main.lock
    rm -rf /tmp/configflow-agent-heartbeat.lock
    rm -f /tmp/agent_fifo_* 2>/dev/null || true
    sleep 1

    # 启动服务
    printf "%b\n" "${{YELLOW}}启动 Agent 服务...${{NC}}"
    systemctl enable configflow-agent
    systemctl start configflow-agent

    # 等待服务启动
    sleep 2

    # 检查服务状态
    if systemctl is-active --quiet configflow-agent; then
        printf "%b\n" "${{GREEN}}================================${{NC}}"
        printf "%b\n" "${{GREEN}}Agent 安装成功！${{NC}}"
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
    printf "%b\n" "${{RED}}不支持的 Init 系统: $INIT_SYSTEM${{NC}}"
    printf "%b\n" "${{YELLOW}}Agent 程序已安装到 $AGENT_DIR，但无法创建系统服务${{NC}}"
    printf "%b\n" "${{YELLOW}}请手动配置服务启动${{NC}}"
    exit 1
fi
