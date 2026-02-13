"""Agent 安装脚本生成器"""
import os
import re
import yaml
from typing import Dict, Any

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# 获取当前文件所在目录
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(CURRENT_DIR, "scripts")


def validate_agent_name(name: str) -> None:
    """验证 Agent 名称安全性"""
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Invalid agent name: only alphanumeric characters, hyphens, and underscores are allowed.")


def generate_lightweight_install_script(
    server_url: str,
    agent_name: str,
    service_type: str,
    agent_port: int = 8080,
    agent_ip: str = "",
    config_path: str = None,
    restart_command: str = None
) -> str:
    """生成轻量级 Shell Agent 安装脚本"""
    # 验证名称
    validate_agent_name(agent_name)

    # 读取脚本模板
    install_script_path = os.path.join(SCRIPTS_DIR, "install.sh")
    agent_script_path = os.path.join(SCRIPTS_DIR, "agent.sh")

    try:
        with open(install_script_path, "r", encoding="utf-8") as f:
            install_template = f.read()

        with open(agent_script_path, "r", encoding="utf-8") as f:
            agent_content = f.read()
    except Exception as e:
        logger.error(f"Error reading template files: {e}")
        return f"#!/bin/sh\n# Error reading template files: {str(e)}"

    # 处理默认值
    if not config_path:
        if service_type == "mihomo":
            config_path = "/etc/mihomo/config.yaml"
        elif service_type == "mosdns":
            config_path = "/etc/mosdns/config.yaml"
        else:
            config_path = "/etc/config.yaml"

    if not restart_command:
        if service_type == "mihomo":
            restart_command = "systemctl restart mihomo"
        elif service_type == "mosdns":
            restart_command = "systemctl restart mosdns"
        else:
            restart_command = "echo 'No restart command configured'"

    # 设置服务名称
    service_name = service_type

    # 替换变量
    # 1. 注入 agent.sh 内容
    script = install_template.replace("{agent_shell_content}", agent_content)

    # 2. 替换配置变量
    replacements = {
        "{server_url}": server_url,
        "{agent_name}": agent_name,
        "{agent_host}": agent_ip, # 暂时使用 agent_ip 作为 host
        "{agent_port}": str(agent_port),
        "{agent_ip}": agent_ip,
        "{service_type}": service_type,
        "{service_name}": service_name,
        "{config_path}": config_path,
        "{restart_command}": restart_command
    }

    for key, value in replacements.items():
        script = script.replace(key, str(value))

    return script


def generate_docker_agent_compose(
    server_url: str,
    agent_name: str = "agent",
    agent_ip: str = "",
    data_dir: str = "./agent_data",
    network_mode: str = "host",
    enable_mihomo: bool = True,
    enable_mosdns: bool = False,
    mihomo_port: int = 8080,
    mosdns_port: int = 8081
) -> str:
    """生成统一的 Docker Compose 配置"""
    # 验证名称
    validate_agent_name(agent_name)

    services_enabled = []
    if enable_mihomo:
        services_enabled.append("mihomo")
    if enable_mosdns:
        services_enabled.append("mosdns")

    service_suffix = "-".join(services_enabled) if services_enabled else "agent"
    container_name = f"{agent_name}-{service_suffix}"

    # 环境变量列表
    environment = [
        f"SERVER_URL={server_url}",
        "TZ=Asia/Shanghai",
        f"ENABLE_MIHOMO={'true' if enable_mihomo else 'false'}",
        f"ENABLE_MOSDNS={'true' if enable_mosdns else 'false'}"
    ]

    if agent_ip:
        environment.append(f"AGENT_IP={agent_ip}")

    if enable_mihomo:
        environment.extend([
            f"AGENT_MIHOMO_NAME={agent_name}-mihomo",
            f"AGENT_MIHOMO_PORT={mihomo_port}"
        ])

    if enable_mosdns:
        environment.extend([
            f"AGENT_MOSDNS_NAME={agent_name}-mosdns",
            f"AGENT_MOSDNS_PORT={mosdns_port}"
        ])

    # 卷映射
    volumes = []
    if enable_mihomo:
        volumes.append(f"{data_dir}/mihomo:/root/.config/mihomo")
    if enable_mosdns:
        volumes.append(f"{data_dir}/mosdns:/etc/mosdns")

    # 构建服务配置
    service_config = {
        'image': 'thsrite/config-flow-agent:latest',
        'container_name': container_name,
        'restart': 'unless-stopped',
        'network_mode': network_mode,
        'environment': environment,
        'volumes': volumes,
        'logging': {
            'driver': 'json-file',
            'options': {
                'max-size': '10m',
                'max-file': '3'
            }
        }
    }

    # 端口映射
    if network_mode == "bridge":
        port_mappings = []
        if enable_mihomo:
            port_mappings.extend([
                f"{mihomo_port}:{mihomo_port}",
                "53:53/udp",
                "7890:7890",
                "9090:9090"
            ])
        if enable_mosdns:
            port_mappings.append(f"{mosdns_port}:{mosdns_port}")
            # 避免重复添加 53 端口
            if "53:53/udp" not in port_mappings:
                port_mappings.append("53:53/udp")
        
        if port_mappings:
            service_config['ports'] = port_mappings

    # 构建完整的 Compose 配置
    compose_config = {
        'version': '3.8',
        'services': {
            'agent': service_config
        }
    }

    return yaml.dump(compose_config, sort_keys=False, allow_unicode=True)


def generate_docker_agent_run(
    server_url: str,
    agent_name: str = "agent",
    agent_ip: str = "",
    data_dir: str = "./agent_data",
    network_mode: str = "host",
    enable_mihomo: bool = True,
    enable_mosdns: bool = False,
    mihomo_port: int = 8080,
    mosdns_port: int = 8081
) -> str:
    """生成统一的 Docker Run 命令"""
    # 验证名称
    validate_agent_name(agent_name)

    services = []
    if enable_mihomo:
        services.append("mihomo")
    if enable_mosdns:
        services.append("mosdns")

    service_suffix = "-".join(services) if services else "agent"
    container_name = f"{agent_name}-{service_suffix}"

    # 服务描述
    if enable_mihomo and enable_mosdns:
        service_desc = "Mihomo + MosDNS"
    elif enable_mihomo:
        service_desc = "Mihomo"
    elif enable_mosdns:
        service_desc = "MosDNS"
    else:
        service_desc = "Agent"

    # 构建端口映射
    ports_args = ""
    if network_mode == "bridge":
        ports = []
        if enable_mihomo:
            ports.extend([
                f"-p {mihomo_port}:{mihomo_port}",
                "-p 7890:7890",
                "-p 9090:9090",
                "-p 53:53/udp"
            ])
        
        if enable_mosdns:
            ports.append(f"-p {mosdns_port}:{mosdns_port}")
            # 避免重复添加 53 端口
            if not enable_mihomo:
                ports.append("-p 53:53/udp")
                
        if ports:
            ports_args = " ".join(ports) + " \\"

    # 构建卷映射
    volumes_args = ""
    volumes = []
    if enable_mihomo:
        volumes.append(f"-v {data_dir}/mihomo:/root/.config/mihomo")
    if enable_mosdns:
        volumes.append(f"-v {data_dir}/mosdns:/etc/mosdns")
        
    if volumes:
        volumes_args = " ".join(volumes) + " \\"

    # 构建命令
    cmd = f"""#!/bin/bash
# 运行 Agent + {service_desc}
docker run -d \\
  --name {container_name} \\
  --restart unless-stopped \\
  --network {network_mode} \\"""

    if ports_args:
        cmd += f"\n  {ports_args}"

    cmd += f"""
  -e SERVER_URL="{server_url}" \\
  -e ENABLE_MIHOMO="{'true' if enable_mihomo else 'false'}" \\
  -e ENABLE_MOSDNS="{'true' if enable_mosdns else 'false'}" \\"""

    if agent_ip:
        cmd += f"\n  -e AGENT_IP={agent_ip} \\"

    if enable_mihomo:
        cmd += f"""
  -e AGENT_MIHOMO_NAME={agent_name}-mihomo \\
  -e AGENT_MIHOMO_PORT={mihomo_port} \\"""

    if enable_mosdns:
        cmd += f"""
  -e AGENT_MOSDNS_NAME={agent_name}-mosdns \\
  -e AGENT_MOSDNS_PORT={mosdns_port} \\"""

    if volumes_args:
        cmd += f"\n  {volumes_args}"
    cmd += """
  thsrite/config-flow-agent:latest
"""
    return cmd
