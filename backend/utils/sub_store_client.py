"""Sub-Store API 客户端

通过 Sub-Store 的 API 获取订阅的 proxies YAML，替代内置的订阅解析和节点转换。

Sub-Store API 参考:
  - GET  /api/subs              — 获取所有订阅
  - POST /api/subs              — 创建订阅 {name, url, ...}
  - GET  /api/sub/:name         — 获取单个订阅
  - GET  /download/:name        — 下载订阅 (query: target, url, ua, noCache 等)
  - GET  /download/:name/:target — 下载订阅 (target 放在路径中)
"""
import os
from urllib.parse import quote

import requests
import yaml

from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _get_base_url():
    """获取 sub-store API 基础 URL（含 backend path 前缀）

    优先级：配置文件 > 环境变量 > 默认值
    例如 http://sub-store:3001 或 http://10.0.0.2:6031/index
    """
    # 优先从配置文件读取（用户在 UI 中设置的值）
    try:
        from backend.common.config import get_config
        config_data = get_config()
        config_url = config_data.get('system_config', {}).get('sub_store_url', '')
        if config_url and config_url.strip():
            return config_url.strip().rstrip('/')
    except Exception:
        pass

    return os.environ.get('SUB_STORE_URL', 'http://127.0.0.1:3001').rstrip('/')


def _is_yaml_response(text):
    """检查响应文本是否像有效的 YAML（而非 HTML 页面）"""
    stripped = text.strip()
    # HTML 页面特征
    if stripped.startswith('<!') or stripped.startswith('<html') or '<head>' in stripped[:500]:
        return False
    # 有效的 proxies YAML 应该包含 proxies 键
    if 'proxies:' in stripped[:200] or stripped.startswith('proxies:'):
        return True
    # 尝试 YAML 解析，如果结果是 dict 且包含 proxies，则有效
    try:
        data = yaml.safe_load(stripped)
        if isinstance(data, dict) and 'proxies' in data:
            return True
    except Exception:
        pass
    return False


def _create_subscription(base, sub_id, url):
    """在 sub-store 中创建临时订阅。

    Returns:
        True 如果创建成功
    """
    try:
        logger.info(f"Sub-Store 创建临时订阅 '{sub_id}'")
        create_resp = requests.post(
            f'{base}/api/subs',
            json={'name': sub_id, 'url': url},
            timeout=10
        )
        if create_resp.status_code in (200, 201):
            return True
        logger.warning(f"Sub-Store 创建订阅 '{sub_id}' 返回状态码: {create_resp.status_code}")
        return False
    except Exception as e:
        logger.warning(f"Sub-Store 创建订阅 '{sub_id}' 失败: {e}")
        return False


def _delete_subscription(base, sub_id):
    """从 sub-store 中删除订阅（用完即删）。"""
    try:
        resp = requests.delete(f'{base}/api/sub/{quote(sub_id, safe="")}', timeout=10)
        if resp.status_code in (200, 204):
            logger.info(f"Sub-Store 已删除临时订阅 '{sub_id}'")
        else:
            logger.debug(f"Sub-Store 删除订阅 '{sub_id}' 返回状态码: {resp.status_code}")
    except Exception as e:
        logger.debug(f"Sub-Store 删除订阅 '{sub_id}' 失败（可忽略）: {e}")


def get_subscription_proxies_yaml(sub_id, url, target='ClashMeta'):
    """调用 sub-store 获取订阅的 proxies YAML。

    自动创建 sub-store 中的订阅（如果不存在）。

    Args:
        sub_id: 订阅 ID，用作 sub-store 中的订阅 name
        url: 原始订阅 URL
        target: 目标格式，默认 ClashMeta

    Returns:
        str: 目标格式的文本（ClashMeta 返回 YAML）

    Raises:
        Exception: 获取失败或返回的不是有效 YAML
    """
    base = _get_base_url()
    logger.info(f"Sub-Store base URL: {base}")

    # 使用带前缀的临时名称，避免和 Sub-Store 中已有订阅冲突
    temp_name = f"_cf_tmp_{sub_id}"
    # 创建临时订阅
    _create_subscription(base, temp_name, url)

    try:
        # 下载订阅（target 放在路径中，这是 Sub-Store 推荐的方式）
        download_url = f'{base}/download/{quote(temp_name, safe="")}/{target}'
        logger.info(f"Sub-Store 下载: {download_url}")

        resp = requests.get(download_url, timeout=30)
        resp.raise_for_status()

        text = resp.text

        # 验证响应是有效的 YAML 而非 HTML 页面
        if not _is_yaml_response(text):
            preview = text[:200].replace('\n', '\\n')
            raise Exception(
                f"Sub-Store 返回了非 YAML 内容（可能是 HTML 页面），"
                f"请检查 Sub-Store URL 配置是否正确。响应预览: {preview}"
            )

        return text
    finally:
        # 用完即删，不在 Sub-Store 中残留订阅数据
        _delete_subscription(base, temp_name)


_TEMP_NODE_SUB_NAME = '_cf_tmp_node_convert'


def convert_proxy_string(proxy_string, target='ClashMeta'):
    """通过 Sub-Store 将单个节点字符串（URI / YAML）转换为 mihomo 格式的 proxy dict。

    Args:
        proxy_string: 节点字符串，如 vless://...、ss://... 或 YAML 对象
        target: 目标格式，默认 ClashMeta

    Returns:
        dict 或 None: 转换后的 mihomo proxy dict，失败返回 None
    """
    base = _get_base_url()
    logger.info(f"节点转换: proxy_string={proxy_string[:80]}...")

    # 创建临时订阅（需要一个名字才能调用 download）
    _create_subscription(base, _TEMP_NODE_SUB_NAME, 'https://example.com')

    try:
        # 通过 content 参数直接传入节点内容，覆盖订阅 URL
        download_url = f'{base}/download/{quote(_TEMP_NODE_SUB_NAME, safe="")}/{target}'
        logger.info(f"节点转换下载: {download_url}")
        resp = requests.get(
            download_url,
            params={'content': proxy_string},
            timeout=15
        )
        logger.info(f"节点转换响应: status={resp.status_code}, content-type={resp.headers.get('content-type', '')}")
        resp.raise_for_status()

        text = resp.text
        logger.info(f"节点转换响应内容(前200字符): {text[:200]}")

        if not _is_yaml_response(text):
            logger.warning(f"Sub-Store 节点转换返回非 YAML 内容: {text[:200]}")
            return None

        proxies = parse_proxies_from_yaml(text)
        logger.info(f"节点转换解析结果: {len(proxies)} 个 proxy")
        if proxies:
            logger.info(f"节点转换成功: {proxies[0].get('name', '')} ({proxies[0].get('type', '')})")
            return proxies[0]
        logger.warning("节点转换: YAML 解析成功但 proxies 列表为空")
        return None
    except Exception as e:
        logger.warning(f"Sub-Store 节点转换失败: {e}")
        return None
    finally:
        _delete_subscription(base, _TEMP_NODE_SUB_NAME)


def _fix_proxy_fields(proxy):
    """补全代理节点的必需字段（如 VLESS 的 encryption: none）"""
    if isinstance(proxy, dict) and proxy.get('type') == 'vless' and proxy.get('encryption', '') in ('', 'zero', None):
        proxy['encryption'] = 'none'
    return proxy


def parse_proxies_from_yaml(yaml_text):
    """从 sub-store 返回的 YAML 文本中解析 proxies 列表。

    Args:
        yaml_text: sub-store 返回的 YAML 文本

    Returns:
        list[dict]: proxies 列表（mihomo 格式的 dict）
    """
    data = yaml.safe_load(yaml_text)
    if isinstance(data, dict):
        proxies = data.get('proxies', [])
        for proxy in proxies:
            _fix_proxy_fields(proxy)
        return proxies
    return []


def proxies_to_nodes(proxies):
    """将 mihomo 格式的 proxies 列表转换为内部 node 格式（用于缓存和 UI 展示）。

    Args:
        proxies: mihomo 格式的 proxy dict 列表

    Returns:
        list[dict]: 内部 node 格式列表
    """
    nodes = []
    for proxy in proxies:
        node = {
            'name': proxy.get('name', 'Unnamed'),
            'type': proxy.get('type', '').lower(),
            'server': proxy.get('server', ''),
            'port': proxy.get('port', 0),
            'params': {k: v for k, v in proxy.items() if k not in ('name', 'type', 'server', 'port')}
        }
        nodes.append(node)
    return nodes
