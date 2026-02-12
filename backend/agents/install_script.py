"""Agent 安装脚本生成器"""
from typing import Dict, Any


# Agent Shell 脚本模板（内嵌）
AGENT_SHELL_TEMPLATE = """#!/bin/sh
# Proxy Configuration Agent - Shell 版本
# 支持系统：Alpine Linux, Debian, Ubuntu, CentOS, RHEL 等主流 Linux 发行版

# 注意：不使用 set -e，因为 HTTP 服务器中的某些错误不应导致整个进程退出

# Agent 版本号
AGENT_VERSION="1.0.0"

# 配置文件路径
CONFIG_FILE="/opt/configflow-agent/config.json"
LOG_FILE="/var/log/configflow-agent.log"

# 日志函数
log() {{
    # 检查日志是否启用（默认启用）
    local logging_enabled=$(grep '"logging_enabled"' "$CONFIG_FILE" 2>/dev/null | sed 's/.*: *\\([^,}}]*\\).*/\\1/' | tr -d ' "')
    if [ "$logging_enabled" = "false" ]; then
        return 0
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE" 2>/dev/null || true
}}

log_error() {{
    # 错误日志始终记录
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - $1" >> "$LOG_FILE" 2>/dev/null || true
}}

# 读取配置
load_config() {{
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "配置文件不存在: $CONFIG_FILE"
        exit 1
    fi

    # 使用简单的 grep/sed 解析 JSON
    SERVER_URL=$(grep '"server_url"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    AGENT_NAME=$(grep '"agent_name"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    AGENT_HOST=$(grep '"agent_host"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    AGENT_PORT=$(grep '"agent_port"' "$CONFIG_FILE" | sed 's/.*: *\\([0-9]*\\).*/\\1/')
    AGENT_IP=$(grep '"agent_ip"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
    SERVICE_TYPE=$(grep '"service_type"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    SERVICE_NAME=$(grep '"service_name"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    CONFIG_PATH=$(grep '"config_path"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    RESTART_CMD=$(grep '"restart_command"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    HEARTBEAT_INTERVAL=$(grep '"heartbeat_interval"' "$CONFIG_FILE" | sed 's/.*: *\\([0-9]*\\).*/\\1/' || echo 30)
    AGENT_ID=$(grep '"agent_id"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
    TOKEN=$(grep '"token"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")

    log "配置加载成功: $AGENT_NAME"
}}

# 保存配置
save_config() {{
    local agent_id="$1"
    local token="$2"

    # 备份原配置
    cp "$CONFIG_FILE" "${{CONFIG_FILE}}.bak"

    # 一次性添加 agent_id 和 token
    if ! grep -q '"agent_id"' "$CONFIG_FILE"; then
        # 读取配置，去掉最后的 }}，添加两个新字段，再加回 }}
        sed '$ d' "$CONFIG_FILE" > "${{CONFIG_FILE}}.tmp"
        printf '  ,\\n' >> "${{CONFIG_FILE}}.tmp"
        printf '  "agent_id": "%s",\\n' "$agent_id" >> "${{CONFIG_FILE}}.tmp"
        printf '  "token": "%s"\\n' "$token" >> "${{CONFIG_FILE}}.tmp"
        printf '}}\\n' >> "${{CONFIG_FILE}}.tmp"
        mv "${{CONFIG_FILE}}.tmp" "$CONFIG_FILE"
    fi
}}

# 获取本机 IP（内网IP）
get_local_ip() {{
    local local_ip=""

    # 检查 IP 是否有效（排除保留地址段）
    is_valid_ip() {{
        local test_ip="$1"

        # 排除空值
        [ -z "$test_ip" ] && return 1

        # 排除 127.0.0.1（回环地址）
        [ "$test_ip" = "127.0.0.1" ] && return 1

        # 排除 198.18.0.0/15（Clash/Mihomo TUN 地址段）
        echo "$test_ip" | grep -qE '^198\\.1[89]\\.' && return 1

        # 排除 169.254.0.0/16（链路本地地址）
        echo "$test_ip" | grep -qE '^169\\.254\\.' && return 1

        # 排除 0.0.0.0
        [ "$test_ip" = "0.0.0.0" ] && return 1

        # 检查是否为有效的IPv4格式
        echo "$test_ip" | grep -qE '^[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}$' || return 1

        return 0
    }}

    # 方法1: 从 ip addr 获取本地网络接口IP
    if [ -z "$local_ip" ] && command -v ip >/dev/null 2>&1; then
        for test_ip in $(ip addr show 2>/dev/null | grep 'inet ' | awk '{{print $2}}' | cut -d/ -f1); do
            if is_valid_ip "$test_ip"; then
                local_ip="$test_ip"
                break
            fi
        done
    fi

    # 方法2: 使用 hostname -I (注意是大写 I，返回所有地址)
    if [ -z "$local_ip" ] && command -v hostname >/dev/null 2>&1; then
        for test_ip in $(hostname -I 2>/dev/null); do
            if is_valid_ip "$test_ip"; then
                local_ip="$test_ip"
                break
            fi
        done
    fi

    # 方法3: 使用 ifconfig（适用于老系统）
    if [ -z "$local_ip" ] && command -v ifconfig >/dev/null 2>&1; then
        for test_ip in $(ifconfig 2>/dev/null | grep 'inet ' | awk '{{print $2}}' | cut -d: -f2); do
            if is_valid_ip "$test_ip"; then
                local_ip="$test_ip"
                break
            fi
        done
    fi

    # 返回获取到的内网IP
    if [ -n "$local_ip" ]; then
        log "获取到本机IP: $local_ip"
        echo "$local_ip"
    else
        log "无法获取IP，使用回环地址"
        echo "127.0.0.1"
    fi
}}

# 注册到服务器
register_to_server() {{
    log "正在向主服务器注册..."

    # 优先使用配置中的 IP，如果没有则自动获取
    local local_ip=""
    if [ -n "$AGENT_IP" ] && [ "$AGENT_IP" != "" ]; then
        local_ip="$AGENT_IP"
        log "使用配置的IP: $local_ip"
    else
        local_ip=$(get_local_ip)
        log "自动检测到本机IP: $local_ip"
    fi

    local register_url="${{SERVER_URL}}/api/agents/register"
    log "注册URL: $register_url"

    # 构建 JSON 数据
    local json_data="{{\\"name\\":\\"$AGENT_NAME\\",\\"host\\":\\"$local_ip\\",\\"port\\":$AGENT_PORT,\\"service_type\\":\\"$SERVICE_TYPE\\",\\"version\\":\\"$AGENT_VERSION\\"}}"

    log "注册数据: $json_data"

    # 发送注册请求
    local response=$(curl -s -w "\\n%{{http_code}}" -X POST "$register_url" \\
        -H "Content-Type: application/json" \\
        -H "Accept: application/json" \\
        -d "$json_data" 2>&1)

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    log "注册响应状态码: $http_code"
    log "注册响应内容: $body"

    if [ "$http_code" = "200" ]; then
        # 解析 JSON 响应
        local success=$(echo "$body" | grep -o '\\"success\\"[[:space:]]*:[[:space:]]*true')
        if [ -n "$success" ]; then
            local agent_id=$(echo "$body" | grep -o '\\"id\\"[[:space:]]*:[[:space:]]*\\"[^\\"]*\\"' | head -1 | sed 's/.*\\"\\([^\\"]*\\)".*/\\1/')
            local token=$(echo "$body" | grep -o '\\"token\\"[[:space:]]*:[[:space:]]*\\"[^\\"]*\\"' | head -1 | sed 's/.*\\"\\([^\\"]*\\)".*/\\1/')

            save_config "$agent_id" "$token"
            AGENT_ID="$agent_id"
            TOKEN="$token"

            log "注册成功! Agent ID: $agent_id"
            return 0
        else
            log_error "注册失败: 服务器返回 success=false"
            return 1
        fi
    else
        log_error "注册失败，状态码: $http_code"
        return 1
    fi
}}

# 发送心跳
send_heartbeat() {{
    if [ -z "$AGENT_ID" ] || [ -z "$TOKEN" ]; then
        log_error "心跳发送跳过: AGENT_ID 或 TOKEN 为空"
        return
    fi

    local heartbeat_url="${{SERVER_URL}}/api/agents/${{AGENT_ID}}/heartbeat"

    # 获取服务状态 - 支持 systemd 和 OpenRC
    local service_status="unknown"
    if command -v systemctl >/dev/null 2>&1; then
        # systemd (Debian/Ubuntu/CentOS 7+/RHEL 7+ 等)
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            service_status="active"
        else
            service_status="inactive"
        fi
    elif command -v rc-service >/dev/null 2>&1; then
        # OpenRC (Alpine Linux)
        if rc-service "$SERVICE_NAME" status 2>/dev/null | grep -q "started"; then
            service_status="active"
        else
            service_status="inactive"
        fi
    elif command -v service >/dev/null 2>&1; then
        # SysV init (老版本 Debian/Ubuntu/CentOS 等)
        if service "$SERVICE_NAME" status 2>/dev/null | grep -q "running"; then
            service_status="active"
        else
            service_status="inactive"
        fi
    fi

    local json_data="{{\\"version\\":\\"$AGENT_VERSION\\",\\"service_status\\":\\"$service_status\\"}}"

    # 打印心跳命令（方便调试）
    local token_prefix=$(echo "$TOKEN" | cut -c1-10)
    log "发送心跳: curl -X POST '$heartbeat_url' -H 'Authorization: Bearer ${{token_prefix}}...' -H 'Content-Type: application/json' -d '$json_data'"

    # 发送心跳并记录详细结果
    local response=$(curl -s -w "\\n%{{http_code}}" --connect-timeout 5 --max-time 10 -X POST "$heartbeat_url" \\
        -H "Authorization: Bearer $TOKEN" \\
        -H "Content-Type: application/json" \\
        -d "$json_data" 2>&1)

    local exit_code=$?
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')

    log "心跳响应: 退出码=$exit_code, HTTP状态码=$http_code"

    if [ $exit_code -ne 0 ]; then
        log_error "心跳发送失败: curl 退出码 $exit_code"
        log_error "完整响应: $response"
    elif [ "$http_code" = "200" ]; then
        log "心跳发送成功 (服务状态: $service_status)"
    else
        log_error "心跳发送失败，HTTP状态码: $http_code"
        log_error "响应内容: $body"
    fi
}}

# 备份配置
backup_config() {{
    if [ -f "$CONFIG_PATH" ]; then
        local backup_path="${{CONFIG_PATH}}.backup.$(date +%s)"
        cp "$CONFIG_PATH" "$backup_path"
        log "配置已备份: $backup_path"

        # 只保留最近 5 个备份
        local backup_dir=$(dirname "$CONFIG_PATH")
        local backup_name=$(basename "$CONFIG_PATH")
        ls -t "${{backup_dir}}/${{backup_name}}.backup."* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
    fi
}}

# 重启服务
restart_service() {{
    log "执行重启命令: $RESTART_CMD"

    # 判断是 URL 还是命令
    if echo "$RESTART_CMD" | grep -qE '^https?://'; then
        # URL 方式：使用 curl 发送请求
        log "检测到 URL，使用 curl 发送重启请求"
        local response=$(curl -s -w "\\n%{{http_code}}" --connect-timeout 10 --max-time 30 -X POST "$RESTART_CMD" 2>&1)
        local http_code=$(echo "$response" | tail -n1)
        local body=$(echo "$response" | sed '$d')

        log "重启请求响应: HTTP状态码=$http_code, 响应内容=$body"

        if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
            log "服务重启成功 (URL方式)"
            return 0
        else
            log_error "服务重启失败 (URL方式), HTTP状态码: $http_code"
            return 1
        fi
    else
        # 命令方式：直接执行命令
        log "检测到命令，直接执行"
        # 将输出直接写入日志文件，避免污染 HTTP 响应
        if eval "$RESTART_CMD" >> "$LOG_FILE" 2>&1; then
            log "服务重启成功 (命令方式)"
            return 0
        else
            log_error "服务重启失败 (命令方式)"
            return 1
        fi
    fi
}}

# HTTP 服务器（处理 API 请求）
start_http_server() {{
    log "启动 HTTP API 服务器在 ${{AGENT_HOST}}:${{AGENT_PORT}}"

    # 优先使用 socat（更可靠），fallback 到 netcat
    if command -v socat >/dev/null 2>&1; then
        log "使用 socat 启动 HTTP 服务器"
        start_http_server_socat
    else
        log "socat 未安装，使用 netcat"
        start_http_server_netcat
    fi
}}

# 使用 socat 的 HTTP 服务器（推荐，适用于 Debian/Ubuntu）
start_http_server_socat() {{
    # socat 会为每个连接fork一个子进程，并调用我们的处理脚本
    # 使用SYSTEM模式，通过shell执行，可能有更好的stdin/stdout处理

    # 捕获 socat 的错误输出
    local error_output=$(mktemp)
    socat TCP-LISTEN:$AGENT_PORT,fork,reuseaddr SYSTEM:"$0 __handle_request__" 2>"$error_output" || {{
        local socat_error=$(cat "$error_output" 2>/dev/null)
        rm -f "$error_output"

        # 检查是否是端口占用错误
        if echo "$socat_error" | grep -qi "address already in use\\|bind.*already in use"; then
            log_error "端口 $AGENT_PORT 已被占用，无法启动服务"
            log_error "请检查是否有其他程序正在使用端口 $AGENT_PORT"
            log_error "可以使用以下命令查看: lsof -i :$AGENT_PORT 或 netstat -tulpn | grep $AGENT_PORT"
            echo "错误: 端口 $AGENT_PORT 已被占用" >&2
            echo "请检查是否有其他程序正在使用此端口" >&2
        else
            log_error "socat 启动失败: $socat_error"
            echo "错误: socat 启动失败" >&2
            if [ -n "$socat_error" ]; then
                echo "详细信息: $socat_error" >&2
            fi
        fi
        exit 1
    }}
    rm -f "$error_output"
}}

# HTTP 请求处理函数（被 socat 调用）
handle_http_request() {{
    # 重新加载配置（因为这是新进程）
    if [ -f "$CONFIG_FILE" ]; then
        TOKEN=$(grep '"token"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/' || echo "")
        CONFIG_PATH=$(grep '"config_path"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
        RESTART_CMD=$(grep '"restart_command"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
        SERVICE_NAME=$(grep '"service_name"' "$CONFIG_FILE" | sed 's/.*: *"\\([^"]*\\)".*/\\1/')
    fi

    # 忽略管道错误
    trap '' PIPE

    # 读取 HTTP 请求（不加超时，让socat正常传递数据）
    read -r request_line
    local method=$(echo "$request_line" | awk '{{print $1}}')
    local path=$(echo "$request_line" | awk '{{print $2}}')

    # 记录收到的请求
    log "收到HTTP请求: $method $path"

    # 跳过 HTTP 头（改用更兼容的方式）
    local auth_token=""
    local content_length=""
    local line_count=0
    while IFS= read -r header; do
        # 移除行尾的回车符
        header=$(echo "$header" | tr -d '\\r\\n')

        # 如果是空行，说明headers结束
        if [ -z "$header" ]; then
            break
        fi

        line_count=$((line_count + 1))

        # 检查 Authorization 头
        if echo "$header" | grep -qi "^Authorization:"; then
            auth_token=$(echo "$header" | sed 's/Authorization: *Bearer *//i')
        fi

        # 检查 Content-Length
        if echo "$header" | grep -qi "^Content-Length:"; then
            content_length=$(echo "$header" | sed 's/Content-Length: *//i')
        fi

        # 防止无限循环，最多读取50行headers
        if [ $line_count -gt 50 ]; then
            log_error "Headers过多，停止读取"
            break
        fi
    done

    log "Content-Length: $content_length"

    # 读取请求体（使用head读取精确字节数，添加超时保护）
    local body=""
    if [ -n "$content_length" ] && [ "$content_length" -gt 0 ]; then
        log "开始读取请求体: $content_length 字节"
        # 使用timeout避免head阻塞，大配置文件最多等待30秒
        if command -v timeout >/dev/null 2>&1; then
            body=$(timeout 30 head -c "$content_length" 2>/dev/null || echo "")
        else
            # 如果没有timeout命令，直接使用head
            body=$(head -c "$content_length" 2>/dev/null || echo "")
        fi
        log "请求体读取完成，长度: ${{#body}} 字节"
    fi

    # 路由处理
    case "$path" in
        /health)
            local response_body='{{\\"status\\":\\"ok\\"}}'
            local response_length=${{#response_body}}
            printf "HTTP/1.1 200 OK\\r\\n"
            printf "Content-Type: application/json\\r\\n"
            printf "Content-Length: %d\\r\\n" "$response_length"
            printf "\\r\\n"
            printf "%s" "$response_body"
            ;;

        /api/config/update)
            # 验证 token
            if [ "$auth_token" != "$TOKEN" ]; then
                local response_body='{{\\"success\\":false,\\"message\\":\\"Unauthorized\\"}}'
                local response_length=${{#response_body}}
                printf "HTTP/1.1 401 Unauthorized\\r\\n"
                printf "Content-Type: application/json\\r\\n"
                printf "Content-Length: %d\\r\\n" "$response_length"
                printf "\\r\\n"
                printf "%s" "$response_body"
            else
                        # 提取配置内容（处理 JSON 转义）
                        # 1. 先删除开头到 "config":" 的部分
                        local config_json=$(echo "$body" | sed 's/.*"config"[[:space:]]*:[[:space:]]*"//')

                        # 2. 保护转义的引号，避免被误匹配
                        config_json=$(echo "$config_json" | sed 's/\\\\"/<<ESCAPED_QUOTE>>/g')

                        # 3. 现在删除真正的结束引号及 md5 字段（此时所有 \\" 都被替换成了标记）
                        config_json=$(echo "$config_json" | sed 's/"[[:space:]]*,[[:space:]]*"md5".*//')

                        # 4. 恢复转义的引号
                        config_json=$(echo "$config_json" | sed 's/<<ESCAPED_QUOTE>>/\\\\"/g')

                        # 5. 使用 printf '%b' 解释转义序列（\\n, \\t等）
                        # 注意：需要先将 \\\\\\\\ 替换为临时占位符，避免被printf误解释
                        local config_temp=$(echo "$config_json" | sed 's/\\\\\\\\\\\\\\\\/\\x00/g')
                        local config_decoded=$(printf '%b' "$config_temp" | sed 's/\\x00/\\\\/g')

                        # 6. 最后处理转义的引号
                        local new_config=$(echo "$config_decoded" | sed 's/\\\\"/"/g')

                        # 备份旧配置
                        backup_config

                        # 确保配置文件的父目录存在
                        local config_dir=$(dirname "$CONFIG_PATH")
                        if [ ! -d "$config_dir" ]; then
                            log "创建配置目录: $config_dir"
                            mkdir -p "$config_dir" 2>/dev/null || true
                        fi

                        # 写入新配置（不添加额外换行）
                        printf '%s' "$new_config" > "$CONFIG_PATH"
                        log "配置已更新: $CONFIG_PATH"

                        # 处理目录创建（用于 MosDNS 规则文件）
                        if echo "$body" | grep -q '"directories"'; then
                            log "检测到 directories 字段，开始创建目录..."
                            # 提取 directories 数组内容
                            local dirs=$(echo "$body" | sed -n 's/.*"directories"[[:space:]]*:[[:space:]]*\\[\\([^]]*\\)\\].*/\\1/p' | tr -d '"' | tr ',' ' ')
                            for dir in $dirs; do
                                dir=$(echo "$dir" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                                if [ -n "$dir" ]; then
                                    local full_dir_path="${{config_dir}}/${{dir}}"
                                    if [ ! -d "$full_dir_path" ]; then
                                        log "创建目录: $full_dir_path"
                                        mkdir -p "$full_dir_path" 2>/dev/null || true
                                    fi
                                fi
                            done
                        fi

                        # 处理规则集下载（用于 MosDNS）
                        if echo "$body" | grep -q '"ruleset_downloads"'; then
                            log "检测到 ruleset_downloads 字段，开始下载规则文件..."

                            local download_count=0
                            local temp_names=$(mktemp)
                            local temp_urls=$(mktemp)
                            local temp_paths=$(mktemp)

                            # 提取 ruleset_downloads 部分到临时文件
                            local temp_rulesets=$(mktemp)
                            echo "$body" | sed -n '/"ruleset_downloads"/,/\\]/p' > "$temp_rulesets"

                            # 从 ruleset_downloads 部分提取所有 name, url, local_path 值
                            grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$temp_rulesets" | sed 's/.*"\\([^"]*\\)".*/\\1/' > "$temp_names"
                            grep -o '"url"[[:space:]]*:[[:space:]]*"[^"]*"' "$temp_rulesets" | sed 's/.*"\\([^"]*\\)".*/\\1/' > "$temp_urls"
                            grep -o '"local_path"[[:space:]]*:[[:space:]]*"[^"]*"' "$temp_rulesets" | sed 's/.*"\\([^"]*\\)".*/\\1/' > "$temp_paths"

                            rm -f "$temp_rulesets"

                            # 统计数量
                            local count=$(wc -l < "$temp_names" | tr -d ' ')
                            log "找到 $count 个规则集需要下载"

                            # 如果数量为0，输出调试信息
                            if [ "$count" -eq 0 ]; then
                                log_error "未能从 ruleset_downloads 中提取到规则集信息"
                                log "检查 body 前 500 字符: $(echo "$body" | head -c 500)"
                            fi

                            # 逐行读取并下载
                            local i=1
                            while [ $i -le "$count" ]; do
                                local item_name=$(sed -n "${{i}}p" "$temp_names")
                                local item_url=$(sed -n "${{i}}p" "$temp_urls")
                                local item_path=$(sed -n "${{i}}p" "$temp_paths")

                                if [ -n "$item_url" ] && [ -n "$item_path" ]; then
                                    log "下载规则集 [$i/$count]: $item_name"
                                    local full_path="${{config_dir}}/${{item_path}}"
                                    local full_dir=$(dirname "$full_path")
                                    mkdir -p "$full_dir" 2>/dev/null || true

                                    # 下载文件，添加超时和重试
                                    if curl -s -f --connect-timeout 10 --max-time 30 -o "$full_path" "$item_url" 2>/dev/null; then
                                        log "规则集下载成功: $full_path"
                                        download_count=$((download_count + 1))
                                    else
                                        log_error "规则集下载失败: $item_url"
                                    fi
                                else
                                    log_error "规则集信息不完整: name=$item_name, url=$item_url, path=$item_path"
                                fi

                                i=$((i + 1))
                            done

                            # 清理临时文件
                            rm -f "$temp_names" "$temp_urls" "$temp_paths"

                            log "规则文件下载完成，共 $download_count 个文件"
                        fi

                        # 发送响应（使用 printf 确保精确输出）
                        local response_body='{{\\"success\\":true,\\"message\\":\\"Config updated\\"}}'
                        local response_length=${{#response_body}}

                        printf "HTTP/1.1 200 OK\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"

                        # 强制刷新标准输出
                        exec >&-
                        exec >/dev/null
                    fi
                    ;;

                /api/restart)
                    # 验证 token
                    if [ "$auth_token" != "$TOKEN" ]; then
                        local response_body='{{\\"success\\":false,\\"message\\":\\"Unauthorized\\"}}'
                        local response_length=${{#response_body}}
                        printf "HTTP/1.1 401 Unauthorized\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"
                    else
                        log "收到重启请求"
                        if restart_service; then
                            local response_body='{{\\"success\\":true,\\"message\\":\\"Service restarted\\"}}'
                            local response_length=${{#response_body}}
                            printf "HTTP/1.1 200 OK\\r\\n"
                            printf "Content-Type: application/json\\r\\n"
                            printf "Content-Length: %d\\r\\n" "$response_length"
                            printf "\\r\\n"
                            printf "%s" "$response_body"
                        else
                            local response_body='{{\\"success\\":false,\\"message\\":\\"Restart failed\\"}}'
                            local response_length=${{#response_body}}
                            printf "HTTP/1.1 500 Internal Server Error\\r\\n"
                            printf "Content-Type: application/json\\r\\n"
                            printf "Content-Length: %d\\r\\n" "$response_length"
                            printf "\\r\\n"
                            printf "%s" "$response_body"
                        fi

                        # 强制刷新标准输出
                        exec >&-
                        exec >/dev/null
                    fi
                    ;;

                /api/logs/validate)
                    # 验证自定义日志路径
                    if [ "$auth_token" != "$TOKEN" ]; then
                        local response_body='{{\\"success\\":false,\\"message\\":\\"Unauthorized\\"}}'
                        local response_length=${{#response_body}}
                        printf "HTTP/1.1 401 Unauthorized\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"
                    else
                        # 读取请求体中的日志路径
                        local content_length=0
                        while IFS=: read -r header value; do
                            header=$(echo "$header" | tr -d '\\r\\n' | tr '[:upper:]' '[:lower:]')
                            if [ "$header" = "content-length" ]; then
                                content_length=$(echo "$value" | tr -d ' \\r\\n')
                            fi
                            [ -z "$header" ] && break
                        done

                        local request_body=""
                        if [ "$content_length" -gt 0 ]; then
                            request_body=$(dd bs=1 count="$content_length" 2>/dev/null)
                        fi

                        # 提取路径（简单JSON解析）
                        local log_path=$(echo "$request_body" | grep -o '"path"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\\([^"]*\\)".*/\\1/')

                        # 验证路径
                        local valid=false
                        local error_msg=""
                        local file_size=0

                        # 检查路径是否包含目录遍历
                        if echo "$log_path" | grep -q "\\.\\."; then
                            error_msg="路径不能包含 .."
                        # 检查是否为绝对路径
                        elif ! echo "$log_path" | grep -q "^/"; then
                            error_msg="必须使用绝对路径"
                        # 检查是否在白名单目录内
                        elif ! echo "$log_path" | grep -qE "^/var/log|^/etc/mosdns|^/data|^/opt/configflow-agent"; then
                            error_msg="路径必须在允许的目录内: /var/log, /etc/mosdns, /data, /opt/configflow-agent"
                        # 检查文件是否存在
                        elif [ ! -e "$log_path" ]; then
                            error_msg="文件不存在"
                        # 检查是否为普通文件
                        elif [ ! -f "$log_path" ]; then
                            error_msg="路径不是文件"
                        # 检查是否可读
                        elif [ ! -r "$log_path" ]; then
                            error_msg="文件不可读"
                        else
                            valid=true
                            file_size=$(stat -f%z "$log_path" 2>/dev/null || stat -c%s "$log_path" 2>/dev/null || echo 0)
                        fi

                        # 返回验证结果
                        if [ "$valid" = true ]; then
                            printf "HTTP/1.1 200 OK\\r\\n"
                            printf "Content-Type: application/json\\r\\n"
                            printf "\\r\\n"
                            printf '{{\\"success\\":true,\\"valid\\":true,\\"size\\":%d}}' "$file_size"
                        else
                            printf "HTTP/1.1 200 OK\\r\\n"
                            printf "Content-Type: application/json\\r\\n"
                            printf "\\r\\n"
                            printf '{{\\"success\\":false,\\"valid\\":false,\\"error\\":"%s"}}' "$error_msg"
                        fi
                    fi
                    ;;

                /api/config/logging)
                    # 日志配置管理
                    if [ "$auth_token" != "$TOKEN" ]; then
                        local response_body='{{\\"success\\":false,\\"message\\":\\"Unauthorized\\"}}'
                        local response_length=${{#response_body}}
                        printf "HTTP/1.1 401 Unauthorized\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"
                    else
                        if [ "$method" = "GET" ]; then
                            # 获取日志配置状态
                            local logging_enabled=$(grep '"logging_enabled"' "$CONFIG_FILE" 2>/dev/null | sed 's/.*: *\\([^,}}]*\\).*/\\1/' | tr -d ' "')
                            if [ -z "$logging_enabled" ]; then
                                logging_enabled="true"
                            fi

                            printf "HTTP/1.1 200 OK\\r\\n"
                            printf "Content-Type: application/json\\r\\n"
                            printf "\\r\\n"
                            printf '{{\\"success\\":true,\\"enabled\\":%s}}' "$logging_enabled"
                        elif [ "$method" = "POST" ]; then
                            # 设置日志配置
                            local content_length=0
                            while IFS=: read -r header value; do
                                header=$(echo "$header" | tr -d '\\r\\n' | tr '[:upper:]' '[:lower:]')
                                if [ "$header" = "content-length" ]; then
                                    content_length=$(echo "$value" | tr -d ' \\r\\n')
                                fi
                                [ -z "$header" ] && break
                            done

                            local request_body=""
                            if [ "$content_length" -gt 0 ]; then
                                request_body=$(dd bs=1 count="$content_length" 2>/dev/null)
                            fi

                            # 提取 enabled 值
                            local enabled=$(echo "$request_body" | grep -o '"enabled"[[:space:]]*:[[:space:]]*[^,}}]*' | sed 's/.*:[[:space:]]*\\([^,}}]*\\).*/\\1/' | tr -d ' "')

                            # 更新配置文件
                            if [ -f "$CONFIG_FILE" ]; then
                                # 备份
                                cp "$CONFIG_FILE" "${{CONFIG_FILE}}.bak"

                                # 检查是否已存在 logging_enabled 字段
                                if grep -q '"logging_enabled"' "$CONFIG_FILE"; then
                                    # 更新现有值
                                    sed -i.tmp 's/"logging_enabled"[[:space:]]*:[[:space:]]*[^,}}]*/"logging_enabled": '$enabled'/g' "$CONFIG_FILE"
                                    rm -f "${{CONFIG_FILE}}.tmp"
                                else
                                    # 添加新字段
                                    sed '$ d' "$CONFIG_FILE" > "${{CONFIG_FILE}}.tmp"
                                    printf ',\\n  "logging_enabled": %s\\n}}\\n' "$enabled" >> "${{CONFIG_FILE}}.tmp"
                                    mv "${{CONFIG_FILE}}.tmp" "$CONFIG_FILE"
                                fi
                            fi

                            printf "HTTP/1.1 200 OK\\r\\n"
                            printf "Content-Type: application/json\\r\\n"
                            printf "\\r\\n"
                            printf '{{\\"success\\":true,\\"message\\":\\"日志配置已更新\\"}}'
                        fi
                    fi
                    ;;

                /api/logs*)
                    # 验证 token
                    if [ "$auth_token" != "$TOKEN" ]; then
                        local response_body='{{\\"success\\":false,\\"message\\":\\"Unauthorized\\"}}'
                        local response_length=${{#response_body}}
                        printf "HTTP/1.1 401 Unauthorized\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"
                    else
                        # 从 URL 中提取参数
                        local lines=100
                        local log_path="$LOG_FILE"

                        if echo "$path" | grep -q "lines="; then
                            lines=$(echo "$path" | sed 's/.*lines=\\([0-9]*\\).*/\\1/')
                        fi

                        # 提取 log_path 参数（URL解码）
                        if echo "$path" | grep -q "log_path="; then
                            log_path=$(echo "$path" | sed 's/.*log_path=\\([^&]*\\).*/\\1/' | sed 's/%2F/\\//g' | sed 's/%20/ /g')
                        fi

                        # 验证自定义路径（如果提供）
                        if [ "$log_path" != "$LOG_FILE" ]; then
                            # 安全检查
                            if echo "$log_path" | grep -q "\\.\\."; then
                                printf "HTTP/1.1 400 Bad Request\\r\\n"
                                printf "Content-Type: application/json\\r\\n"
                                printf "\\r\\n"
                                printf '{{\\"success\\":false,\\"message\\":\\"非法路径\\"}}'
                                return
                            elif ! echo "$log_path" | grep -qE "^/var/log|^/etc/mosdns|^/data|^/opt/configflow-agent"; then
                                printf "HTTP/1.1 403 Forbidden\\r\\n"
                                printf "Content-Type: application/json\\r\\n"
                                printf "\\r\\n"
                                printf '{{\\"success\\":false,\\"message\\":\\"路径不在允许范围内\\"}}'
                                return
                            fi
                        fi

                        # 读取日志文件（如果文件不存在则返回空）
                        local logs=""
                        if [ -f "$log_path" ]; then
                            logs=$(tail -n "$lines" "$log_path" 2>/dev/null || echo "")
                        fi

                        # 转义日志内容用于 JSON
                        # 需要转义的字符：\\ " 换行 回车 制表符等
                        local logs_escaped=""
                        if [ -n "$logs" ]; then
                            # 1. 转义反斜杠
                            logs_escaped=$(printf '%s' "$logs" | sed 's/\\\\/\\\\\\\\/g')
                            # 2. 转义双引号
                            logs_escaped=$(printf '%s' "$logs_escaped" | sed 's/"/\\\\"/g')
                            # 3. 转义换行符为 \\n
                            logs_escaped=$(printf '%s' "$logs_escaped" | sed ':a;N;$!ba;s/\\n/\\\\n/g')
                            # 4. 转义回车符
                            logs_escaped=$(printf '%s' "$logs_escaped" | sed 's/\\r/\\\\r/g' | tr -d '\\r')
                            # 5. 转义制表符
                            logs_escaped=$(printf '%s' "$logs_escaped" | sed 's/\\t/\\\\t/g' | tr -d '\\t')
                        fi

                        # 使用 printf 构建 JSON，避免 shell 变量展开问题
                        printf "HTTP/1.1 200 OK\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "\\r\\n"
                        printf '{{\\"success\\":true,\\"logs\\":"%s"}}' "$logs_escaped"
                    fi
                    ;;

                /api/uninstall)
                    # 验证 token
                    if [ "$auth_token" != "$TOKEN" ]; then
                        local response_body='{{\\"success\\":false,\\"message\\":\\"Unauthorized\\"}}'
                        local response_length=${{#response_body}}
                        printf "HTTP/1.1 401 Unauthorized\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"
                    else
                        # 先返回成功响应
                        local response_body='{{\\"success\\":true,\\"message\\":\\"Uninstall started\\"}}'
                        local response_length=${{#response_body}}
                        printf "HTTP/1.1 200 OK\\r\\n"
                        printf "Content-Type: application/json\\r\\n"
                        printf "Content-Length: %d\\r\\n" "$response_length"
                        printf "\\r\\n"
                        printf "%s" "$response_body"

                        # 在完全独立的后台进程中执行卸载
                        nohup sh -c '
                            sleep 5

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
                                rc-service configflow-agent stop 2>/dev/null || true
                                rc-update del configflow-agent default 2>/dev/null || true
                                rm -f /etc/init.d/configflow-agent
                                rc-update -u 2>/dev/null || true
                            elif [ "$OS_TYPE" = "systemd" ]; then
                                systemctl stop configflow-agent 2>/dev/null || true
                                systemctl disable configflow-agent 2>/dev/null || true
                                rm -f /etc/systemd/system/configflow-agent.service
                                systemctl daemon-reload 2>/dev/null || true
                            fi

                            # 删除程序文件
                            rm -rf /opt/configflow-agent
                            rm -f /var/log/configflow-agent.log
                            rm -f /run/configflow-agent.pid

                            # 清理锁文件
                            rm -rf /tmp/configflow-agent-main.lock
                            rm -rf /tmp/configflow-agent-heartbeat.lock
                        ' >/dev/null 2>&1 &
                    fi
                    ;;

                *)
                    local response_body='{{\\"success\\":false,\\"message\\":\\"Not found\\"}}'
                    local response_length=${{#response_body}}
                    printf "HTTP/1.1 404 Not Found\\r\\n"
                    printf "Content-Type: application/json\\r\\n"
                    printf "Content-Length: %d\\r\\n" "$response_length"
                    printf "\\r\\n"
                    printf "%s" "$response_body"
                    ;;
            esac
}}

# 使用 netcat 的 HTTP 服务器（fallback）
start_http_server_netcat() {{
    # TODO: 保留原来的FIFO+netcat实现作为fallback
    log_error "Netcat fallback 未实现，请安装 socat"
    exit 1
}}

# 心跳循环
heartbeat_loop() {{
    # 使用文件锁确保只有一个心跳进程
    local LOCK_FILE="/tmp/configflow-agent-heartbeat.lock"

    # 尝试获取锁
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        log "心跳进程已在运行，退出"
        return
    fi

    # 确保退出时删除锁
    trap "rm -rf $LOCK_FILE" EXIT

    log "心跳报告器已启动，间隔: ${{HEARTBEAT_INTERVAL}}秒"

    while true; do
        send_heartbeat
        sleep "$HEARTBEAT_INTERVAL"
    done
}}

# 主函数
main() {{
    # 使用文件锁确保只有一个主进程运行
    local MAIN_LOCK="/tmp/configflow-agent-main.lock"

    if ! mkdir "$MAIN_LOCK" 2>/dev/null; then
        log_error "Agent 主进程已在运行，退出"
        exit 1
    fi

    # 确保退出时删除锁
    trap "rm -rf $MAIN_LOCK" EXIT

    log "Agent 启动... (版本: $AGENT_VERSION)"

    # 加载配置
    load_config

    # 如果未注册，先注册
    if [ -z "$AGENT_ID" ]; then
        if ! register_to_server; then
            log_error "注册失败，退出"
            exit 1
        fi
    fi

    # 启动心跳循环（后台）
    heartbeat_loop &

    # 启动 HTTP 服务器（前台）
    start_http_server
}}

# 捕获退出信号
trap 'log "收到退出信号，正在关闭..."; exit 0' INT TERM

# 运行主程序或HTTP请求处理
if [ "$1" = "__handle_request__" ]; then
    # 被socat调用，处理单个HTTP请求
    handle_http_request
else
    # 正常启动Agent
    main
fi
"""

# Shell Agent 安装脚本模板（内嵌）
INSTALL_SHELL_TEMPLATE = """#!/bin/sh
# Agent 轻量级安装脚本（Shell 版本，无 Python 依赖）
# 支持系统：Alpine Linux, Debian, Ubuntu, CentOS, RHEL, Rocky Linux, AlmaLinux 等
# 服务类型：{service_type}
# Agent 名称：{agent_name}

# 颜色定义
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

printf "%b\\n" "${{GREEN}}================================${{NC}}"
printf "%b\\n" "${{GREEN}}Agent 轻量级安装脚本${{NC}}"
printf "%b\\n" "${{GREEN}}服务类型: {service_type}${{NC}}"
printf "%b\\n" "${{GREEN}}Agent 名称: {agent_name}${{NC}}"
printf "%b\\n" "${{YELLOW}}模式: Shell 版本（无 Python 依赖）${{NC}}"
printf "%b\\n" "${{GREEN}}================================${{NC}}"

# 检查是否为 root 用户
if [ "$(id -u)" -ne 0 ]; then
    printf "%b\\n" "${{RED}}请使用 root 用户运行此脚本${{NC}}"
    exit 1
fi

# 检查是否已安装
ALREADY_INSTALLED=0
if [ -f /etc/init.d/configflow-agent ] || [ -f /etc/systemd/system/configflow-agent.service ]; then
    ALREADY_INSTALLED=1
fi

# 显示操作菜单（每次都显示）
printf "\\n"
if [ $ALREADY_INSTALLED -eq 1 ]; then
    printf "%b\\n" "${{YELLOW}}检测到 Agent 已安装${{NC}}"
else
    printf "%b\\n" "${{GREEN}}准备安装 Agent${{NC}}"
fi
printf "\\n"
printf "%b\\n" "${{BLUE}}请选择操作:${{NC}}"
printf "%b\\n" "  1) 安装 (如已安装则覆盖)"
printf "%b\\n" "  2) 卸载"
printf "%b\\n" "  3) 取消"
printf "\\n"
printf "%b" "${{BLUE}}请输入选项 [1-3]: ${{NC}}"

read -r choice < /dev/tty

case "$choice" in
    1)
        if [ $ALREADY_INSTALLED -eq 1 ]; then
            printf "%b\\n" "${{YELLOW}}开始重新安装...${{NC}}"
        else
            printf "%b\\n" "${{YELLOW}}开始安装...${{NC}}"
        fi
        # 继续安装流程
        ;;
    2)
        printf "%b\\n" "${{YELLOW}}开始卸载 Agent...${{NC}}"

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
            printf "%b\\n" "${{YELLOW}}停止 OpenRC 服务...${{NC}}"
            rc-service configflow-agent stop 2>/dev/null || true
            rc-update del configflow-agent default 2>/dev/null || true
            rm -f /etc/init.d/configflow-agent
            # 刷新 OpenRC 缓存
            rc-update -u 2>/dev/null || true
        elif [ "$OS_TYPE" = "systemd" ]; then
            printf "%b\\n" "${{YELLOW}}停止 systemd 服务...${{NC}}"
            systemctl stop configflow-agent 2>/dev/null || true
            systemctl disable configflow-agent 2>/dev/null || true
            rm -f /etc/systemd/system/configflow-agent.service
            systemctl daemon-reload 2>/dev/null || true
        fi

        # 杀掉所有进程
        printf "%b\\n" "${{YELLOW}}清理进程...${{NC}}"
        pkill -9 -f "agent.sh" 2>/dev/null || true
        pkill -9 -f "nc -l" 2>/dev/null || true
        pkill -9 -f "configflow-agent" 2>/dev/null || true

        # 删除文件
        printf "%b\\n" "${{YELLOW}}删除程序文件和配置...${{NC}}"
        rm -rf /opt/configflow-agent
        rm -f /var/log/configflow-agent.log
        rm -f /run/configflow-agent.pid

        # 清理锁文件和临时文件
        printf "%b\\n" "${{YELLOW}}清理锁文件和临时文件...${{NC}}"
        rm -rf /tmp/configflow-agent-main.lock
        rm -rf /tmp/configflow-agent-heartbeat.lock
        rm -f /tmp/agent_fifo_* 2>/dev/null || true

        printf "\\n"
        printf "%b\\n" "${{GREEN}}================================${{NC}}"
        printf "%b\\n" "${{GREEN}}Agent 卸载完成！${{NC}}"
        printf "%b\\n" "${{GREEN}}================================${{NC}}"
        exit 0
        ;;
    3|*)
        printf "%b\\n" "${{YELLOW}}操作已取消${{NC}}"
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

printf "%b\\n" "${{YELLOW}}检测到系统: $OS_NAME${{NC}}"
printf "%b\\n" "${{YELLOW}}系统类型: $OS_TYPE, 包管理器: $PKG_MANAGER, Init系统: $INIT_SYSTEM${{NC}}"

# 检查必要的工具
printf "%b\\n" "${{YELLOW}}检查必要工具...${{NC}}"

# 安装 curl
if ! command -v curl >/dev/null 2>&1; then
    printf "%b\\n" "${{RED}}curl 未安装，正在安装...${{NC}}"
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
            printf "%b\\n" "${{RED}}无法自动安装 curl，请手动安装${{NC}}"
            exit 1
            ;;
    esac
fi

# 安装 netcat
if ! command -v nc >/dev/null 2>&1; then
    printf "%b\\n" "${{YELLOW}}netcat 未安装，尝试安装...${{NC}}"
    case "$PKG_MANAGER" in
        apk)
            # Alpine 的 BusyBox 通常已包含 nc
            printf "%b\\n" "${{GREEN}}BusyBox nc 可用${{NC}}"
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
    printf "%b\\n" "${{YELLOW}}socat 未安装，尝试安装...${{NC}}"
    case "$PKG_MANAGER" in
        apk)
            apk add --no-cache socat || printf "%b\\n" "${{YELLOW}}socat 安装失败，将使用 netcat (BusyBox nc)${{NC}}"
            ;;
        apt)
            apt-get install -y socat || printf "%b\\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        yum)
            yum install -y socat || printf "%b\\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        dnf)
            dnf install -y socat || printf "%b\\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        pacman)
            pacman -Sy --noconfirm socat || printf "%b\\n" "${{YELLOW}}socat 安装失败，将使用 netcat fallback${{NC}}"
            ;;
        *)
            printf "%b\\n" "${{YELLOW}}未知包管理器，跳过 socat 安装，将使用 netcat${{NC}}"
            ;;
    esac
else
    printf "%b\\n" "${{GREEN}}socat 已安装${{NC}}"
fi

# 创建 Agent 目录
AGENT_DIR="/opt/configflow-agent"
printf "%b\\n" "${{YELLOW}}创建 Agent 目录: $AGENT_DIR${{NC}}"
mkdir -p $AGENT_DIR
cd $AGENT_DIR

# 创建 Agent 主程序文件
printf "%b\\n" "${{YELLOW}}创建 Agent 程序...${{NC}}"
cat > agent.sh << 'AGENT_SHELL_EOF'
{agent_shell_content}
AGENT_SHELL_EOF

chmod +x agent.sh

# 创建配置文件
printf "%b\\n" "${{YELLOW}}创建 Agent 配置文件...${{NC}}"
cat > config.json << EOF
{{
  "server_url": "{server_url}",
  "agent_name": "{agent_name}",
  "agent_host": "{agent_host}",
  "agent_port": {agent_port},
  "agent_ip": "{agent_ip}",
  "service_type": "{service_type}",
  "deployment_method": "shell",
  "service_name": "{service_name}",
  "config_path": "{config_path}",
  "restart_command": "{restart_command}",
  "heartbeat_interval": 30
}}
EOF

# 根据 Init 系统创建服务
if [ "$INIT_SYSTEM" = "openrc" ]; then
    # Alpine Linux - 使用 OpenRC
    printf "%b\\n" "${{YELLOW}}创建 OpenRC 服务...${{NC}}"
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
    printf "%b\\n" "${{YELLOW}}清理旧的服务状态...${{NC}}"
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
    printf "%b\\n" "${{YELLOW}}启动 Agent 服务...${{NC}}"
    rc-update add configflow-agent default
    sleep 1
    rc-service configflow-agent start

    # 等待服务启动
    sleep 2

    # 检查服务状态
    if rc-service configflow-agent status | grep -q "started"; then
        printf "%b\\n" "${{GREEN}}================================${{NC}}"
        printf "%b\\n" "${{GREEN}}Agent 安装成功！${{NC}}"
        printf "%b\\n" "${{GREEN}}================================${{NC}}"
        printf "%b\\n" "${{YELLOW}}服务状态: ${{NC}}"
        rc-service configflow-agent status
        printf "%b\\n" ""
        printf "%b\\n" "${{YELLOW}}查看日志: ${{NC}}tail -f /var/log/configflow-agent.log"
        printf "%b\\n" "${{YELLOW}}停止服务: ${{NC}}rc-service configflow-agent stop"
        printf "%b\\n" "${{YELLOW}}重启服务: ${{NC}}rc-service configflow-agent restart"
    else
        printf "%b\\n" "${{RED}}================================${{NC}}"
        printf "%b\\n" "${{RED}}Agent 启动失败！${{NC}}"
        printf "%b\\n" "${{RED}}================================${{NC}}"
        printf "%b\\n" "${{YELLOW}}查看错误日志: ${{NC}}tail -n 50 /var/log/configflow-agent.log"
        exit 1
    fi

elif [ "$INIT_SYSTEM" = "systemd" ]; then
    # Debian/Ubuntu/CentOS/RHEL 等 - 使用 systemd
    printf "%b\\n" "${{YELLOW}}创建 systemd 服务...${{NC}}"
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
    printf "%b\\n" "${{YELLOW}}重载 systemd...${{NC}}"
    systemctl daemon-reload

    # 启动服务前清理旧的锁文件和临时文件
    printf "%b\\n" "${{YELLOW}}清理旧的锁文件和临时文件...${{NC}}"
    systemctl stop configflow-agent 2>/dev/null || true
    pkill -9 -f "agent.sh" 2>/dev/null || true
    pkill -9 -f "nc -l" 2>/dev/null || true
    rm -rf /tmp/configflow-agent-main.lock
    rm -rf /tmp/configflow-agent-heartbeat.lock
    rm -f /tmp/agent_fifo_* 2>/dev/null || true
    sleep 1

    # 启动服务
    printf "%b\\n" "${{YELLOW}}启动 Agent 服务...${{NC}}"
    systemctl enable configflow-agent
    systemctl start configflow-agent

    # 等待服务启动
    sleep 2

    # 检查服务状态
    if systemctl is-active --quiet configflow-agent; then
        printf "%b\\n" "${{GREEN}}================================${{NC}}"
        printf "%b\\n" "${{GREEN}}Agent 安装成功！${{NC}}"
        printf "%b\\n" "${{GREEN}}================================${{NC}}"
        printf "%b\\n" "${{YELLOW}}服务状态: ${{NC}}"
        systemctl status configflow-agent --no-pager -l
        printf "%b\\n" ""
        printf "%b\\n" "${{YELLOW}}查看日志: ${{NC}}journalctl -u configflow-agent -f"
        printf "%b\\n" "${{YELLOW}}停止服务: ${{NC}}systemctl stop configflow-agent"
        printf "%b\\n" "${{YELLOW}}重启服务: ${{NC}}systemctl restart configflow-agent"
    else
        printf "%b\\n" "${{RED}}================================${{NC}}"
        printf "%b\\n" "${{RED}}Agent 启动失败！${{NC}}"
        printf "%b\\n" "${{RED}}================================${{NC}}"
        printf "%b\\n" "${{YELLOW}}查看错误日志: ${{NC}}journalctl -u configflow-agent -n 50"
        exit 1
    fi
else
    printf "%b\\n" "${{RED}}不支持的 Init 系统: $INIT_SYSTEM${{NC}}"
    printf "%b\\n" "${{YELLOW}}Agent 程序已安装到 $AGENT_DIR，但无法创建系统服务${{NC}}"
    printf "%b\\n" "${{YELLOW}}请手动配置服务启动${{NC}}"
    exit 1
fi
"""


def generate_lightweight_install_script(
    server_url: str,
    agent_name: str,
    service_type: str,
    agent_port: int = 8080,
    agent_ip: str = "",
    config_path: str = None,
    restart_command: str = None
) -> str:
    """
    生成轻量级 Shell Agent 安装脚本（无 Python 依赖）
    适用于资源受限的环境（如 Alpine Linux）

    Args:
        agent_ip: 可选的 Agent IP 地址，如果指定则脚本不会自动获取 IP
    """
    # 根据服务类型确定服务名称
    if service_type == 'mihomo':
        service_name = "mihomo"
    elif service_type == 'mosdns':
        service_name = "mosdns"
    else:
        service_name = service_type

    # 设置配置文件路径
    if config_path is None:
        config_path = f"/etc/{service_type}/config.yaml"

    # 设置默认的重启命令
    if restart_command is None:
        restart_command = f"systemctl restart {service_name}"

    # 使用内嵌模板
    agent_shell_content = AGENT_SHELL_TEMPLATE
    script_template = INSTALL_SHELL_TEMPLATE

    # 替换模板中的变量
    script = script_template.format(
        service_type=service_type,
        agent_name=agent_name,
        server_url=server_url,
        agent_host="0.0.0.0",
        agent_port=agent_port,
        agent_ip=agent_ip,
        service_name=service_name,
        config_path=config_path,
        restart_command=restart_command,
        agent_shell_content=agent_shell_content
    )

    return script


def generate_docker_mihomo_compose(
    server_url: str,
    agent_token: str,
    agent_name: str = "mihomo-agent",
    data_dir: str = "./mihomo_data",
    network_mode: str = "host"
) -> str:
    """
    生成 Mihomo Docker Compose 配置

    Args:
        server_url: 服务器 URL
        agent_token: Agent 令牌
        agent_name: Agent 名称
        data_dir: 数据目录路径
        network_mode: 网络模式 (host/bridge)

    Returns:
        Docker Compose YAML 配置
    """
    # 根据网络模式决定是否添加端口映射
    if network_mode == "bridge":
        ports_section = """    ports:
      - "8080:8080"
      - "53:53/udp"
      - "53:53/tcp"
      - "1053:1053"
      - "7890:7890"
      - "7891:7891"
      - "9090:9090"
"""
    else:
        ports_section = ""

    compose_template = """version: '3.8'

services:
  mihomo:
    image: thsrite/config-flow-agent:latest
    container_name: {agent_name}
    restart: unless-stopped
    network_mode: {network_mode}
{ports_section}    environment:
      - SERVER_URL={server_url}
      - AGENT_TOKEN={agent_token}
      - AGENT_NAME={agent_name}
      - SERVICE_TYPE=mihomo
      - DEPLOYMENT_METHOD=docker
      - CONFIG_PATH=/root/.config/mihomo/config.yaml
      - RESTART_COMMAND=supervisorctl restart mihomo
    volumes:
      - {data_dir}:/root/.config/mihomo
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
"""

    return compose_template.format(
        server_url=server_url,
        agent_token=agent_token,
        agent_name=agent_name,
        data_dir=data_dir,
        network_mode=network_mode,
        ports_section=ports_section
    )


def generate_docker_mihomo_run(
    server_url: str,
    agent_token: str,
    agent_name: str = "mihomo-agent",
    data_dir: str = "./mihomo_data",
    network_mode: str = "host"
) -> str:
    """
    生成 Mihomo Docker Run 命令

    Args:
        server_url: 服务器 URL
        agent_token: Agent 令牌
        agent_name: Agent 名称
        data_dir: 数据目录路径
        network_mode: 网络模式 (host/bridge)

    Returns:
        Docker run 命令脚本
    """
    # 根据网络模式决定是否添加端口映射
    if network_mode == "bridge":
        ports_mapping = """  -p 8080:8080 \\
  -p 53:53/udp \\
  -p 53:53/tcp \\
  -p 1053:1053 \\
  -p 7890:7890 \\
  -p 7891:7891 \\
  -p 9090:9090 \\
"""
    else:
        ports_mapping = ""

    run_command = """#!/bin/bash

# 创建数据目录
mkdir -p {data_dir}

# 运行 Mihomo 容器
docker run -d \\
  --name {agent_name} \\
  --restart unless-stopped \\
  --network {network_mode} \\
{ports_mapping}  -e SERVER_URL="{server_url}" \\
  -e AGENT_TOKEN="{agent_token}" \\
  -e AGENT_NAME="{agent_name}" \\
  -e SERVICE_TYPE="mihomo" \\
  -e DEPLOYMENT_METHOD="docker" \\
  -e CONFIG_PATH="/root/.config/mihomo/config.yaml" \\
  -e RESTART_COMMAND="supervisorctl restart mihomo" \\
  -v {data_dir}:/root/.config/mihomo \\
  --log-opt max-size=10m \\
  --log-opt max-file=3 \\
  thsrite/config-flow-agent:latest

echo "Mihomo Agent 已启动"
echo "容器名称: {agent_name}"
echo "查看日志: docker logs -f {agent_name}"
"""

    return run_command.format(
        server_url=server_url,
        agent_token=agent_token,
        agent_name=agent_name,
        data_dir=data_dir,
        network_mode=network_mode,
        ports_mapping=ports_mapping
    )


def generate_docker_mosdns_compose(
    server_url: str,
    agent_token: str,
    agent_name: str = "mosdns-agent",
    data_dir: str = "./mosdns_data",
    network_mode: str = "host"
) -> str:
    """
    生成 MosDNS Docker Compose 配置

    Args:
        server_url: 服务器 URL
        agent_token: Agent 令牌
        agent_name: Agent 名称
        data_dir: 数据目录路径
        network_mode: 网络模式 (host/bridge)

    Returns:
        Docker Compose YAML 配置
    """
    # 根据网络模式决定是否添加端口映射
    if network_mode == "bridge":
        ports_section = """    ports:
      - "8081:8081"
      - "53:53/udp"
      - "53:53/tcp"
"""
    else:
        ports_section = ""

    compose_template = """version: '3.8'

services:
  mosdns:
    image: thsrite/config-flow-agent:latest
    container_name: {agent_name}
    restart: unless-stopped
    network_mode: {network_mode}
{ports_section}    environment:
      - SERVER_URL={server_url}
      - AGENT_TOKEN={agent_token}
      - AGENT_NAME={agent_name}
      - SERVICE_TYPE=mosdns
      - DEPLOYMENT_METHOD=docker
      - CONFIG_PATH=/etc/mosdns/config.yaml
      - RESTART_COMMAND=supervisorctl restart mosdns
    volumes:
      - {data_dir}:/etc/mosdns
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
"""

    return compose_template.format(
        server_url=server_url,
        agent_token=agent_token,
        agent_name=agent_name,
        data_dir=data_dir,
        network_mode=network_mode,
        ports_section=ports_section
    )


def generate_docker_mosdns_run(
    server_url: str,
    agent_token: str,
    agent_name: str = "mosdns-agent",
    data_dir: str = "./mosdns_data",
    network_mode: str = "host"
) -> str:
    """
    生成 MosDNS Docker Run 命令

    Args:
        server_url: 服务器 URL
        agent_token: Agent 令牌
        agent_name: Agent 名称
        data_dir: 数据目录路径
        network_mode: 网络模式 (host/bridge)

    Returns:
        Docker run 命令脚本
    """
    # 根据网络模式决定是否添加端口映射
    if network_mode == "bridge":
        ports_mapping = """  -p 8081:8081 \\
  -p 53:53/udp \\
  -p 53:53/tcp \\
"""
    else:
        ports_mapping = ""

    run_command = """#!/bin/bash

# 创建数据目录
mkdir -p {data_dir}

# 运行 MosDNS 容器
docker run -d \\
  --name {agent_name} \\
  --restart unless-stopped \\
  --network {network_mode} \\
{ports_mapping}  -e SERVER_URL="{server_url}" \\
  -e AGENT_TOKEN="{agent_token}" \\
  -e AGENT_NAME="{agent_name}" \\
  -e SERVICE_TYPE="mosdns" \\
  -e DEPLOYMENT_METHOD="docker" \\
  -e CONFIG_PATH="/etc/mosdns/config.yaml" \\
  -e RESTART_COMMAND="supervisorctl restart mosdns" \\
  -v {data_dir}:/etc/mosdns \\
  --log-opt max-size=10m \\
  --log-opt max-file=3 \\
  thsrite/config-flow-agent:latest

echo "MosDNS Agent 已启动"
echo "容器名称: {agent_name}"
echo "查看日志: docker logs -f {agent_name}"
"""

    return run_command.format(
        server_url=server_url,
        agent_token=agent_token,
        agent_name=agent_name,
        data_dir=data_dir,
        network_mode=network_mode,
        ports_mapping=ports_mapping
    )


def generate_docker_aio_compose(
    server_url: str,
    agent_token: str,
    agent_name: str = "aio-agent",
    data_dir: str = "./aio_data",
    network_mode: str = "host"
) -> str:
    """
    生成 All-in-One Docker Compose 配置（使用统一镜像 + 环境变量控制）

    符合作者新架构：单个镜像 thsrite/config-flow-agent:latest
    通过 ENABLE_MIHOMO 和 ENABLE_MOSDNS 环境变量控制服务启动

    Args:
        server_url: 服务器 URL
        agent_token: Agent 令牌
        agent_name: Agent 名称
        data_dir: 数据目录路径
        network_mode: 网络模式 (host/bridge)

    Returns:
        Docker Compose YAML 配置
    """
    # 根据网络模式决定是否添加端口映射
    if network_mode == "bridge":
        ports_section = """    ports:
      - "8080:8080"
      - "8081:8081"
      - "53:53/udp"
      - "53:53/tcp"
      - "1053:1053"
      - "7890:7890"
      - "7891:7891"
      - "9090:9090"
"""
    else:
        ports_section = ""

    compose_template = """version: '3.8'

services:
  aio-agent:
    # 使用统一镜像，通过环境变量控制 Mihomo 和 MosDNS 的启动
    image: thsrite/config-flow-agent:latest
    container_name: {agent_name}
    restart: unless-stopped
    network_mode: {network_mode}
{ports_section}    environment:
      # 基础配置
      - SERVER_URL={server_url}
      - AGENT_TOKEN={agent_token}
      - TZ=Asia/Shanghai
      # AIO 模式：同时启用 Mihomo 和 MosDNS
      - ENABLE_MIHOMO=true
      - ENABLE_MOSDNS=true
      # Mihomo Agent 配置
      - AGENT_MIHOMO_NAME={agent_name}-mihomo
      - AGENT_MIHOMO_PORT=8080
      # MosDNS Agent 配置
      - AGENT_MOSDNS_NAME={agent_name}-mosdns
      - AGENT_MOSDNS_PORT=8081
    volumes:
      - {data_dir}/mihomo:/root/.config/mihomo
      - {data_dir}/mosdns:/etc/mosdns
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
"""

    return compose_template.format(
        server_url=server_url,
        agent_token=agent_token,
        agent_name=agent_name,
        data_dir=data_dir,
        network_mode=network_mode,
        ports_section=ports_section
    )


def generate_docker_aio_run(
    server_url: str,
    agent_token: str,
    agent_name: str = "aio-agent",
    data_dir: str = "./aio_data",
    network_mode: str = "host"
) -> str:
    """
    生成 All-in-One Docker Run 命令（使用统一镜像 + 环境变量控制）

    符合作者新架构：单个镜像 thsrite/config-flow-agent:latest
    通过 ENABLE_MIHOMO 和 ENABLE_MOSDNS 环境变量控制服务启动

    Args:
        server_url: 服务器 URL
        agent_token: Agent 令牌
        agent_name: Agent 名称
        data_dir: 数据目录路径
        network_mode: 网络模式 (host/bridge)

    Returns:
        Docker run 命令脚本
    """
    # 根据网络模式决定是否添加端口映射
    if network_mode == "bridge":
        ports_mapping = """  -p 8080:8080 \\
  -p 8081:8081 \\
  -p 53:53/udp \\
  -p 53:53/tcp \\
  -p 1053:1053 \\
  -p 7890:7890 \\
  -p 7891:7891 \\
  -p 9090:9090 \\
"""
    else:
        ports_mapping = ""

    run_command = """#!/bin/bash

# 创建数据目录
mkdir -p {data_dir}/mihomo
mkdir -p {data_dir}/mosdns

# 运行 All-in-One 容器（使用统一镜像，通过环境变量控制服务启动）
docker run -d \\
  --name {agent_name} \\
  --restart unless-stopped \\
  --network {network_mode} \\
{ports_mapping}  -e SERVER_URL="{server_url}" \\
  -e AGENT_TOKEN="{agent_token}" \\
  -e TZ=Asia/Shanghai \\
  # AIO 模式：同时启用 Mihomo 和 MosDNS
  -e ENABLE_MIHOMO="true" \\
  -e ENABLE_MOSDNS="true" \\
  # Mihomo Agent 配置
  -e AGENT_MIHOMO_NAME="{agent_name}-mihomo" \\
  -e AGENT_MIHOMO_PORT="8080" \\
  # MosDNS Agent 配置
  -e AGENT_MOSDNS_NAME="{agent_name}-mosdns" \\
  -e AGENT_MOSDNS_PORT="8081" \\
  -v {data_dir}/mihomo:/root/.config/mihomo \\
  -v {data_dir}/mosdns:/etc/mosdns \\
  --log-opt max-size=10m \\
  --log-opt max-file=3 \\
  thsrite/config-flow-agent:latest

echo "All-in-One Agent 已启动"
echo "容器名称: {agent_name}"
echo "服务: Mihomo (端口 8080) + MosDNS (端口 8081)"
echo "查看日志: docker logs -f {agent_name}"
"""

    return run_command.format(
        server_url=server_url,
        agent_token=agent_token,
        agent_name=agent_name,
        data_dir=data_dir,
        network_mode=network_mode,
        ports_mapping=ports_mapping
    )
