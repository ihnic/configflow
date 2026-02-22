"""Surge 配置生成器"""
import re
import os
from typing import Dict, Any, List
from backend.utils.subscription_parser import parse_uri_list
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def get_aggregation_nodes(agg_id: str, config_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """从聚合 provider 文件中获取节点"""
    from backend.routes.aggregations import generate_aggregation_provider
    import yaml

    # 查找聚合
    aggregations = config_data.get('subscription_aggregations', [])
    aggregation = next((a for a in aggregations if a['id'] == agg_id), None)

    if not aggregation or not aggregation.get('enabled', True):
        return []

    try:
        # 生成 provider 文件（会自动重新解析订阅）
        result = generate_aggregation_provider(aggregation)
        file_path = result['file_path']

        # 读取生成的 YAML 文件
        with open(file_path, 'r', encoding='utf-8') as f:
            provider_data = yaml.safe_load(f)

        proxies = provider_data.get('proxies', [])
        logger.info(f"从聚合 '{aggregation['name']}' 获取了 {len(proxies)} 个节点")

        # 将 mihomo 格式的 proxy 转换为节点格式
        nodes = []
        for proxy in proxies:
            node = {'name': proxy.get('name'), **proxy}
            nodes.append(node)

        return nodes
    except Exception as e:
        logger.error(f"获取聚合节点失败: {e}")
        return []


def split_rules_and_rulesets(config_data: Dict[str, Any]) -> tuple:
    """从 rule_configs 中分离规则和规则集"""
    all_rules = config_data.get('rule_configs', [])
    rules = []
    rule_sets = []

    for item in all_rules:
        item_type = item.get('itemType', '')
        if item_type == 'rule':
            rules.append(item)
        elif item_type == 'ruleset':
            rule_sets.append(item)

    # 兼容旧格式
    if not all_rules:
        rules = config_data.get('rules', [])
        rule_sets = config_data.get('rule_sets', [])

    return rules, rule_sets


def generate_surge_config(config_data: Dict[str, Any], base_url: str = '') -> str:
    """
    生成 Surge 配置文件

    Args:
        config_data: 包含节点、策略组、规则等的配置字典
        base_url: 前端页面的 base URL（协议 + 主机 + 端口），用于构建完整的规则 URL

    Returns:
        str: Surge 格式的配置字符串
    """

    # 从合并数组中分离规则和规则集
    rules_list, rule_sets_list = split_rules_and_rulesets(config_data)

    # 获取 server_domain（优先使用配置的域名）
    server_domain = config_data.get('system_config', {}).get('server_domain', '').strip()
    # 如果没有配置 server_domain，则使用 base_url
    effective_base_url = server_domain or base_url

    sections = []
    wireguard_sections = []  # 存储WireGuard配置section

    # 检查是否有自定义配置（从嵌套结构中读取）
    surge_config_data = config_data.get('surge', {})
    custom_surge_config = surge_config_data.get('custom_config', '')

    # 读取 smart_groups 配置，构建 group_id → policy_priority 的映射
    smart_groups_config = surge_config_data.get('smart_groups', [])
    smart_group_map = {sg['group_id']: sg.get('policy_priority', '') for sg in smart_groups_config}

    # 解析自定义配置的所有 section
    custom_sections = {}  # section_name -> full_text (含 [SectionName] 行)
    if custom_surge_config and custom_surge_config.strip():
        current_section = None
        current_lines = []
        for line in custom_surge_config.strip().split('\n'):
            if line.strip().startswith('[') and ']' in line.strip():
                # 保存前一个 section
                if current_section:
                    custom_sections[current_section] = '\n'.join(current_lines)
                current_section = line.strip().split(']')[0].split('[')[1]
                current_lines = [line]
            else:
                if current_section:
                    current_lines.append(line)
        if current_section:
            custom_sections[current_section] = '\n'.join(current_lines)

    # 提取 [General]（沿用现有逻辑）
    general_section = custom_sections.get('General', None)

    # 如果没有自定义 General 部分，使用默认配置
    if not general_section:
        general = [
            '[General]',
            'loglevel = notify',
            'internet-test-url = http://www.gstatic.com/generate_204',
            'proxy-test-url = http://www.gstatic.com/generate_204',
            'test-timeout = 3',
            'skip-proxy = localhost, *.local, injections.adguard.org, local.adguard.org, captive.apple.com, guzzoni.apple.com, 0.0.0.0/8, 10.0.0.0/8, 17.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 192.88.99.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32',
            'dns-server = 223.5.5.5, 119.29.29.29, system',
            'ipv6 = true',
            'allow-wifi-access = true',
            'wifi-access-http-port = 6152',
            'wifi-access-socks5-port = 6153',
            'http-listen = 0.0.0.0:6152',
            'socks5-listen = 0.0.0.0:6153',
            'exclude-simple-hostnames = true'
        ]
        general_section = '\n'.join(general)

    sections.append(general_section)

    # 收集被策略组使用的节点ID、订阅ID和聚合ID
    used_node_ids = set()
    used_subscription_ids = set()
    used_aggregation_ids = set()

    logger.debug("开始收集被策略组使用的节点、订阅和聚合...")

    for group in config_data.get('proxy_groups', []):
        # 跳过禁用的策略组
        if not group.get('enabled', True):
            continue

        # 处理跟随模式
        follow_group_id = group.get('follow_group')
        if follow_group_id:
            # 查找被跟随的策略组
            followed_group = next((g for g in config_data.get('proxy_groups', []) if g.get('id') == follow_group_id), None)
            if followed_group:
                # 使用被跟随策略组的设置
                manual_nodes = followed_group.get('manual_nodes', [])
                aggregation_ids = followed_group.get('aggregations', [])
                subscriptions = followed_group.get('subscriptions', [])
            else:
                continue
        else:
            # 使用自己的设置
            manual_nodes = group.get('manual_nodes', [])
            aggregation_ids = group.get('aggregations', [])
            subscriptions = group.get('subscriptions', [])

        # 收集手动节点
        for node_id in manual_nodes:
            if node_id not in ['DIRECT', 'REJECT']:
                used_node_ids.add(node_id)

        # 收集直接引用的订阅
        for sub_id in subscriptions:
            used_subscription_ids.add(sub_id)

        # 收集聚合 ID（Surge 需要从聚合 provider 获取节点）
        if aggregation_ids:
            for agg_id in aggregation_ids:
                used_aggregation_ids.add(agg_id)

        # 收集 proxies_order 中的节点（精确排序中的节点）
        proxies_order = group.get('proxies_order', [])
        if proxies_order:
            for item in proxies_order:
                if item.get('type') == 'node':
                    node_id = item.get('id')
                    if node_id not in ['DIRECT', 'REJECT']:
                        used_node_ids.add(node_id)

    # 收集被策略组直接选择的节点ID（通过 manual_nodes 或 proxies_order）
    directly_selected_node_ids = set()
    for group in config_data.get('proxy_groups', []):
        if not group.get('enabled', True):
            continue

        # 处理跟随模式
        follow_group_id = group.get('follow_group')
        if follow_group_id:
            followed_group = next((g for g in config_data.get('proxy_groups', []) if g.get('id') == follow_group_id), None)
            if followed_group:
                manual_nodes = followed_group.get('manual_nodes', [])
                proxies_order = followed_group.get('proxies_order', [])
            else:
                continue
        else:
            manual_nodes = group.get('manual_nodes', [])
            proxies_order = group.get('proxies_order', [])

        # 收集直接选择的节点
        for node_id in manual_nodes:
            if node_id not in ['DIRECT', 'REJECT']:
                directly_selected_node_ids.add(node_id)

        # 收集 proxies_order 中的节点
        if proxies_order:
            for item in proxies_order:
                if item.get('type') == 'node':
                    node_id = item.get('id')
                    if node_id not in ['DIRECT', 'REJECT']:
                        directly_selected_node_ids.add(node_id)

    logger.debug(f"策略组直接选择的节点ID: {directly_selected_node_ids}")

    # 收集所有聚合中的节点ID，但排除被直接选择的节点
    nodes_only_in_aggregations = set()
    for agg in config_data.get('subscription_aggregations', []):
        if agg.get('enabled', True) and agg.get('id') in used_aggregation_ids:
            agg_nodes = agg.get('nodes', [])
            # 只添加没有被直接选择的节点
            for node_id in agg_nodes:
                if node_id not in directly_selected_node_ids:
                    nodes_only_in_aggregations.add(node_id)
            logger.debug(f"聚合 '{agg.get('name')}' 包含节点: {agg_nodes}")

    logger.debug(f"仅通过聚合使用的节点ID（将被排除）: {nodes_only_in_aggregations}")

    # [Proxy] 部分（只添加被策略组直接使用且启用的节点，排除聚合中的节点）
    proxies = ['[Proxy]']

    logger.debug(f"收集到的被使用节点ID: {used_node_ids}")
    logger.debug(f"开始生成 Surge proxies，总节点数: {len(config_data.get('nodes', []))}")

    # 添加手动节点
    for node in config_data.get('nodes', []):
        # 跳过禁用的节点或未被使用的节点
        if not node.get('enabled', True):
            logger.debug(f"跳过禁用节点: {node.get('name')}")
            continue
        if node.get('id') not in used_node_ids:
            logger.debug(f"跳过未被策略组使用的节点: {node.get('name')} (id: {node.get('id')})")
            continue
        # 跳过仅通过聚合使用的节点
        if node.get('id') in nodes_only_in_aggregations:
            logger.debug(f"跳过仅通过聚合使用的节点: {node.get('name')} (id: {node.get('id')})")
            continue
        proxy_line, wg_section = convert_node_to_surge(node)
        if proxy_line:
            proxies.append(proxy_line)
            logger.debug(f"添加节点到 Surge proxies: {node.get('name')}")
        # 如果有WireGuard section，添加到列表
        if wg_section:
            wireguard_sections.append(wg_section)

    logger.debug(f"最终生成的 Surge proxies 数量: {len(proxies) - 1}")

    sections.append('\n'.join(proxies))

    # [Proxy Group] 部分
    proxy_groups = ['[Proxy Group]']

    for group in config_data.get('proxy_groups', []):
        if not group.get('enabled', True):
            continue
        group_line = convert_proxy_group_to_surge(group, config_data, base_url, smart_group_map)
        if group_line:
            proxy_groups.append(group_line)

    if len(proxy_groups) == 1:
        all_proxy_names = [node['name'] for node in config_data.get('nodes', []) if node.get('enabled', True)]
        if all_proxy_names:
            proxy_groups.append(f"Proxy = select, {', '.join(all_proxy_names)}")
            proxy_groups.append(f"Auto = url-test, {', '.join(all_proxy_names)}, url = http://www.gstatic.com/generate_204, interval = 300")

    sections.append('\n'.join(proxy_groups))

    # [Rule] 部分
    rules = ['[Rule]']

    ruleset_behaviors = {}
    ruleset_urls = {}

    rule_library = config_data.get('rule_library', [])
    for lib_rule in rule_library:
        if lib_rule.get('enabled', True):
            ruleset_name = lib_rule.get('name', '')
            ruleset_behaviors[ruleset_name] = lib_rule.get('behavior', '')
            ruleset_urls[ruleset_name] = lib_rule.get('url', '')

    surge_rule_type_map = {
        'SRC-IP-CIDR': 'SRC-IP',
        'DST-PORT': 'DEST-PORT',
    }

    for item in config_data.get('rule_configs', []):
        if not item.get('enabled', True):
            continue

        item_type = item.get('itemType', '')

        if item_type == 'rule':
            rule_type = item['rule_type']
            value = item.get('value', '')
            policy = item['policy']

            if rule_type == 'MATCH':
                rules.append(f"FINAL,{policy}")
            elif rule_type == 'RULE-SET':
                rules.append(f"RULE-SET,{value},{policy}")
            elif rule_type in ['AND', 'OR', 'NOT']:
                surge_value = value.replace('),(', '), (')
                for mihomo_type, surge_type in surge_rule_type_map.items():
                    surge_value = surge_value.replace(mihomo_type, surge_type)
                rules.append(f"{rule_type},{surge_value},{policy}")
            else:
                surge_rule_type = surge_rule_type_map.get(rule_type, rule_type)
                no_resolve = item.get('no_resolve', False)
                if no_resolve:
                    rules.append(f"{surge_rule_type},{value},{policy},no-resolve")
                else:
                    rules.append(f"{surge_rule_type},{value},{policy}")

        elif item_type == 'ruleset':
            policy = item.get('policy', 'Proxy')
            url = item.get('url', '')
            ruleset_name = item.get('name', '')

            original_url = ruleset_urls.get(ruleset_name, url)

            if url and url.startswith('/') and effective_base_url:
                url = f"{effective_base_url}{url}"

            if not url and ruleset_name in ruleset_urls:
                url = ruleset_urls[ruleset_name]
                if url and url.startswith('/') and effective_base_url:
                    url = f"{effective_base_url}{url}"

            rule_options = []
            no_resolve = item.get('no_resolve', False)
            if no_resolve:
                rule_options.append('no-resolve')

            if original_url and (original_url.endswith('.yaml') or original_url.endswith('.yml')):
                rule_options.append('rule-set-format=yaml')

            if rule_options:
                rules.append(f"RULE-SET,{url},{policy},{','.join(rule_options)}")
            else:
                rules.append(f"RULE-SET,{url},{policy}")

    sections.append('\n'.join(rules))

    if wireguard_sections:
        sections.extend(wireguard_sections)

    auto_sections = {'General', 'Proxy', 'Proxy Group', 'Rule'}
    for section_name, section_content in custom_sections.items():
        if section_name not in auto_sections:
            sections.append(section_content)

    config_output = '\n\n'.join(sections)

    config_token = config_data.get('system_config', {}).get('config_token', '')
    surge_url = f"{effective_base_url}/api/config/surge"
    if config_token:
        surge_url += f"?token={config_token}"
    managed_line = f"#!MANAGED-CONFIG {surge_url} interval=86400 strict=true"

    return f"{managed_line}\n\n{config_output}"


def convert_proxies_to_surge_text(proxies: List[Dict[str, Any]]) -> str:
    """将 mihomo 格式 proxies 列表转换为 Surge 纯文本格式"""
    from backend.utils.sub_store_client import proxies_to_nodes

    nodes = proxies_to_nodes(proxies)
    lines = []
    for node in nodes:
        try:
            proxy_line, wireguard_section = convert_node_to_surge(node)
            if wireguard_section:
                continue
            if proxy_line:
                lines.append(proxy_line)
        except Exception as e:
            logger.warning(f"转换节点到 Surge 格式失败: {node.get('name', '?')}, 错误: {e}")
            continue
    return '\n'.join(lines)


def convert_node_to_surge(node: Dict[str, Any]) -> tuple:
    """
    将通用节点格式转换为 Surge 配置行
    """
    outer_name = node.get('name', '')

    is_raw_object = False
    if 'proxy_string' in node:
        try:
            parsed_nodes = parse_uri_list(node['proxy_string'])
            if not parsed_nodes:
                return None, None
            parsed_node = parsed_nodes[0]

            if parsed_node.get('_raw_object'):
                is_raw_object = True
                parsed_node = {k: v for k, v in parsed_node.items() if k != '_raw_object'}
                parsed_node['name'] = outer_name
            else:
                parsed_node['name'] = outer_name

            node = parsed_node
        except:
            return None, None

    node_type = node.get('type', '').lower()
    if not node_type:
        return None, None

    name = node['name']
    server = node.get('server', '')
    port = node.get('port', 0)

    if is_raw_object:
        params = node
    else:
        params = node.get('params', {})

    if node_type == 'ss':
        cipher = params.get('cipher', 'aes-256-gcm')
        password = params.get('password', '')
        parts = [f"{name} = ss", server, str(port), f"encrypt-method={cipher}", f"password={password}"]
        if params.get('udp') or params.get('udp-relay'):
            parts.append("udp-relay=true")
        if params.get('test-url'):
            parts.append(f"test-url={params['test-url']}")
        return ', '.join(parts), None

    elif node_type == 'vmess':
        uuid = params.get('uuid', '')
        tls = 'tls=true' if params.get('tls', False) else ''
        network = params.get('network', 'tcp')
        parts = [f"{name} = vmess", server, str(port), f"username={uuid}"]
        if tls:
            parts.append(tls)
        if network == 'ws':
            ws_opts = params.get('ws-opts', {})
            path = ws_opts.get('path', '/')
            host = ws_opts.get('headers', {}).get('Host', '')
            parts.append('ws=true')
            parts.append(f'ws-path={path}')
            if host:
                parts.append(f'ws-headers=Host:{host}')
        if params.get('udp') or params.get('udp-relay'):
            parts.append('udp-relay=true')
        return ', '.join(parts), None

    elif node_type == 'trojan':
        password = params.get('password', '')
        sni = params.get('sni', '')
        skip_cert = params.get('skip-cert-verify', False)
        parts = [f"{name} = trojan", server, str(port), f"password={password}"]
        if sni:
            parts.append(f"sni={sni}")
        if skip_cert:
            parts.append("skip-cert-verify=true")
        if params.get('udp') or params.get('udp-relay'):
            parts.append('udp-relay=true')
        return ', '.join(parts), None

    elif node_type == 'hysteria2':
        password = params.get('password', '')
        sni = params.get('sni', '')
        skip_cert = params.get('skip-cert-verify', False)
        parts = [f"{name} = hysteria2", server, str(port), f"password={password}"]
        if sni:
            parts.append(f"sni={sni}")
        if skip_cert:
            parts.append("skip-cert-verify=true")
        if params.get('udp') or params.get('udp-relay'):
            parts.append('udp-relay=true')
        return ', '.join(parts), None

    # --- 增加 SOCKS5 / SOCKS5-TLS 处理 ---
    elif node_type == 'socks5':
        username = params.get('username', '')
        password = params.get('password', '')
        tls = params.get('tls', False)
        
        # Surge 对应类型：socks5 或 socks5-tls
        final_type = 'socks5-tls' if tls else 'socks5'
        parts = [f"{name} = {final_type}", server, str(port)]
        
        if username and password:
            parts.append(username)
            parts.append(password)
        
        if tls:
            sni = params.get('sni', '')
            if sni:
                parts.append(f"sni={sni}")
            if params.get('skip-cert-verify', False):
                parts.append("skip-cert-verify=true")

        if params.get('udp') or params.get('udp-relay'):
            parts.append('udp-relay=true')
        return ', '.join(parts), None

    elif node_type == 'http' or node_type == 'https':
        username = params.get('username', '')
        password = params.get('password', '')
        if username and password:
            return f"{name} = {node_type}, {server}, {port}, {username}, {password}", None
        else:
            return f"{name} = {node_type}, {server}, {port}", None

    elif node_type == 'snell':
        psk = params.get('psk', '') or params.get('password', '')
        version = params.get('version', 4)
        parts = [f"{name} = snell", server, str(port), f"psk={psk}"]
        if version:
            parts.append(f"version={version}")
        if params.get('reuse'):
            parts.append("reuse=true")
        if params.get('udp-relay') or params.get('udp'):
            parts.append("udp-relay=true")
        obfs = params.get('obfs', '')
        if obfs:
            parts.append(f"obfs={obfs}")
            obfs_host = params.get('obfs-host', '')
            if obfs_host:
                parts.append(f"obfs-host={obfs_host}")
        return ', '.join(parts), None

    elif node_type == 'tuic' or node_type == 'tuic-v5':
        uuid = params.get('uuid', '')
        password = params.get('password', '')
        token = params.get('token', '')
        parts = [f"{name} = tuic-v5", server, str(port)]
        if uuid:
            parts.append(f"uuid={uuid}")
        if password:
            parts.append(f"password={password}")
        elif token:
            parts.append(f"token={token}")
        alpn = params.get('alpn', 'h3')
        if alpn:
            parts.append(f"alpn={alpn}")
        sni = params.get('sni', '')
        if sni:
            parts.append(f"sni={sni}")
        if params.get('skip-cert-verify', False):
            parts.append("skip-cert-verify=true")
        if params.get('udp-relay') or params.get('udp'):
            parts.append("udp-relay=true")
        return ', '.join(parts), None

    elif node_type == 'vless':
        uuid = params.get('uuid', '')
        tls = params.get('tls', False) or params.get('security', '') == 'tls'
        network = params.get('network', 'tcp')
        parts = [f"{name} = vmess", server, str(port), f"username={uuid}"]
        if tls:
            parts.append('tls=true')
            sni = params.get('sni', '') or params.get('servername', '')
            if sni:
                parts.append(f'sni={sni}')
        if network == 'ws':
            ws_opts = params.get('ws-opts', {}) or params.get('ws-config', {})
            path = ws_opts.get('path', '/') or params.get('path', '/')
            host = ws_opts.get('headers', {}).get('Host', '') or params.get('host', '')
            parts.append('ws=true')
            parts.append(f'ws-path={path}')
            if host:
                parts.append(f'ws-headers=Host:{host}')
        elif network == 'grpc':
            grpc_service = params.get('grpc-opts', {}).get('grpc-service-name', '') or params.get('serviceName', '')
            if grpc_service:
                parts.append(f'grpc-service-name={grpc_service}')
        if params.get('skip-cert-verify', False):
            parts.append("skip-cert-verify=true")
        if params.get('udp') or params.get('udp-relay'):
            parts.append('udp-relay=true')
        return ', '.join(parts), None

    elif node_type == 'wireguard' or node_type == 'wg':
        section_name = params.get('section-name', name.replace(' ', '-').replace('_', '-'))
        proxy_line_parts = [f"{name} = wireguard", f"section-name = {section_name}"]
        mtu = params.get('mtu')
        if mtu:
            proxy_line_parts.append(f"mtu={mtu}")
        proxy_line = ', '.join(proxy_line_parts)

        wg_section_lines = [f"[WireGuard {section_name}]"]
        private_key = params.get('private-key', '') or params.get('privateKey', '')
        if private_key:
            wg_section_lines.append(f"private-key = {private_key}")
        self_ip = params.get('self-ip', '') or params.get('ip', '') or params.get('address', '')
        if self_ip:
            wg_section_lines.append(f"self-ip = {self_ip}")
        dns = params.get('dns', '') or params.get('dns-server', '')
        if dns:
            if isinstance(dns, list):
                dns = ', '.join(dns)
            wg_section_lines.append(f"dns-server = {dns}")
        if mtu:
            wg_section_lines.append(f"mtu = {mtu}")
        peer_public_key = params.get('public-key', '') or params.get('publicKey', '') or params.get('peer-public-key', '')
        endpoint = params.get('endpoint', '') or f"{server}:{port}"
        allowed_ips = params.get('allowed-ips', '') or params.get('allowed_ips', '0.0.0.0/0, ::/0')
        if peer_public_key:
            peer_parts = [f"public-key = {peer_public_key}"]
            peer_parts.append(f"endpoint = {endpoint}")
            if isinstance(allowed_ips, list):
                allowed_ips = ', '.join(allowed_ips)
            peer_parts.append(f'allowed-ips = "{allowed_ips}"')
            keepalive = params.get('keepalive', '') or params.get('persistent-keepalive', '')
            if keepalive:
                peer_parts.append(f"keepalive = {keepalive}")
            preshared_key = params.get('preshared-key', '') or params.get('presharedKey', '')
            if preshared_key:
                peer_parts.append(f"preshared-key = {preshared_key}")
            client_id = params.get('client-id', '') or params.get('reserved', '')
            if client_id:
                peer_parts.append(f"client-id = {client_id}")
            wg_section_lines.append(f"peer = ({', '.join(peer_parts)})")
        wg_section = '\n'.join(wg_section_lines)
        return proxy_line, wg_section

    return None, None


def convert_proxy_group_to_surge(group: Dict[str, Any], config_data: Dict[str, Any], base_url: str = '', smart_group_map: Dict[str, str] = None) -> str:
    """将策略组转换为 Surge 格式"""
    server_domain = config_data.get('system_config', {}).get('server_domain', '').strip()
    effective_base_url = server_domain or base_url

    name = group['name']
    group_type = group['type']

    policy_priority = None
    if smart_group_map and group.get('id') in smart_group_map:
        policy_priority = smart_group_map[group['id']]
        group_type = 'smart'

    follow_group_id = group.get('follow_group')
    if follow_group_id:
        followed_group = next((g for g in config_data.get('proxy_groups', []) if g.get('id') == follow_group_id), None)
        if followed_group:
            manual_nodes = followed_group.get('manual_nodes', [])
            aggregation_ids = followed_group.get('aggregations', [])
            include_groups = followed_group.get('include_groups', [])
            subscriptions = followed_group.get('subscriptions', [])
            group = {
                **group,
                'type': followed_group['type'],
                'manual_nodes': manual_nodes,
                'aggregations': aggregation_ids,
                'include_groups': include_groups,
                'subscriptions': subscriptions,
                'regex': followed_group.get('regex', ''),
                'proxies_order': followed_group.get('proxies_order', []),
                'proxy_order': followed_group.get('proxy_order', 'nodes_first'),
                'url': followed_group.get('url'),
                'interval': followed_group.get('interval')
            }
            if group_type != 'smart':
                group_type = followed_group['type']
        else:
            return None
    else:
        manual_nodes = group.get('manual_nodes', [])
        aggregation_ids = group.get('aggregations', [])
        include_groups = group.get('include_groups', [])
        subscriptions = group.get('subscriptions', [])

    all_proxies = []
    proxies_order = group.get('proxies_order', [])

    if proxies_order:
        for item in proxies_order:
            if item.get('type') == 'node':
                node_id = item.get('id')
                if node_id in ['DIRECT', 'REJECT']:
                    all_proxies.append(node_id)
                else:
                    node = next((n for n in config_data.get('nodes', []) if n.get('id') == node_id), None)
                    if node:
                        all_proxies.append(node['name'])
            elif item.get('type') == 'strategy':
                group_id = item.get('id')
                ref_group = next((g for g in config_data.get('proxy_groups', []) if g.get('id') == group_id), None)
                if ref_group:
                    all_proxies.append(ref_group['name'])

        order_node_ids = {item.get('id') for item in proxies_order if item.get('type') == 'node'}
        for node_id in manual_nodes:
            if node_id not in order_node_ids:
                if node_id in ['DIRECT', 'REJECT']:
                    all_proxies.append(node_id)
                else:
                    node = next((n for n in config_data.get('nodes', []) if n.get('id') == node_id), None)
                    if node:
                        all_proxies.append(node['name'])
    else:
        nodes_list = []
        strategies_list = []
        if manual_nodes:
            for node_id in manual_nodes:
                if node_id in ['DIRECT', 'REJECT']:
                    nodes_list.append(node_id)
                else:
                    node = next((n for n in config_data.get('nodes', []) if n.get('id') == node_id), None)
                    if node:
                        nodes_list.append(node['name'])
        if include_groups:
            for group_id in include_groups:
                ref_group = next((g for g in config_data.get('proxy_groups', []) if g.get('id') == group_id), None)
                if ref_group:
                    strategies_list.append(ref_group['name'])

        proxy_order = group.get('proxy_order', 'nodes_first')
        if proxy_order == 'strategies_first':
            all_proxies.extend(strategies_list)
            all_proxies.extend(nodes_list)
        else:
            all_proxies.extend(nodes_list)
            all_proxies.extend(strategies_list)

    policy_paths = []
    config_token = config_data.get('system_config', {}).get('config_token', '')

    if subscriptions:
        all_subs = config_data.get('subscriptions', [])
        for sub_id in subscriptions:
            sub = next((s for s in all_subs if s['id'] == sub_id and s.get('enabled', True)), None)
            if sub:
                sub_url = f"{effective_base_url}/api/subscriptions/{sub_id}/proxies"
                if config_token:
                    sub_url += f"?token={config_token}&format=surge"
                else:
                    sub_url += f"?format=surge"
                policy_paths.append(sub_url)

    if aggregation_ids:
        aggregations = config_data.get('subscription_aggregations', [])
        for agg_id in aggregation_ids:
            agg = next((a for a in aggregations if a['id'] == agg_id and a.get('enabled', True)), None)
            if agg:
                agg_url = f"{effective_base_url}/api/aggregations/{agg_id}/provider"
                if config_token:
                    agg_url += f"?token={config_token}&format=surge"
                else:
                    agg_url += f"?format=surge"
                policy_paths.append(agg_url)

    if not all_proxies and not policy_paths:
        return None

    proxy_list = ', '.join(all_proxies) if all_proxies else ''

    if group_type == 'select':
        group_line = f"{name} = select"
        if proxy_list:
            group_line += f", {proxy_list}"
    elif group_type == 'url-test':
        url = group.get('url', 'http://www.gstatic.com/generate_204')
        interval = group.get('interval', 300)
        group_line = f"{name} = url-test"
        if proxy_list:
            group_line += f", {proxy_list}"
        group_line += f", url = {url}, interval = {interval}"
    elif group_type == 'fallback':
        url = group.get('url', 'http://www.gstatic.com/generate_204')
        interval = group.get('interval', 300)
        group_line = f"{name} = fallback"
        if proxy_list:
            group_line += f", {proxy_list}"
        group_line += f", url = {url}, interval = {interval}"
    elif group_type == 'load-balance':
        url = group.get('url', 'http://www.gstatic.com/generate_204')
        interval = group.get('interval', 300)
        group_line = f"{name} = load-balance"
        if proxy_list:
            group_line += f", {proxy_list}"
        group_line += f", url = {url}, interval = {interval}"
    elif group_type == 'smart':
        url = group.get('url', 'http://www.gstatic.com/generate_204')
        interval = group.get('interval', 300)
        group_line = f"{name} = smart"
        if proxy_list:
            group_line += f", {proxy_list}"
        if policy_priority:
            group_line += f", policy-priority={policy_priority}"
        group_line += f", url = {url}, interval = {interval}"
    else:
        return None

    if policy_paths:
        for policy_path in policy_paths:
            group_line += f", policy-path = {policy_path}, update-interval = 86400"

    return group_line


def get_proxy_group_nodes(group: Dict[str, Any], config_data: Dict[str, Any]) -> List[str]:
    """获取策略组的节点列表"""
    result_nodes = []
    all_nodes = config_data.get('nodes', [])

    subscriptions = group.get('subscriptions', [])
    if subscriptions:
        subscription_nodes = [
            node for node in all_nodes
            if node.get('subscription_id') in subscriptions and node.get('enabled', True)
        ]

        regex_pattern = group.get('regex', '')
        if regex_pattern:
            try:
                regex = re.compile(regex_pattern)
                subscription_nodes = [
                    node for node in subscription_nodes
                    if regex.search(node['name'])
                ]
            except re.error:
                pass

        result_nodes.extend([node['name'] for node in subscription_nodes])

    manual_proxies = group.get('proxies', [])
    if manual_proxies:
        for proxy_name in manual_proxies:
            if proxy_name not in result_nodes:
                result_nodes.append(proxy_name)

    seen = set()
    unique_nodes = []
    for node in result_nodes:
        if node not in seen:
            seen.add(node)
            unique_nodes.append(node)

    return unique_nodes
