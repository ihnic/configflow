"""公共工具函数模块"""
import os
import secrets
import string
from functools import wraps
from flask import jsonify


def get_local_ip():
    """获取本地 IP 地址"""
    try:
        import socket
        # 创建 UDP socket 连接到外部地址（不会实际发送数据）
        # 使用 Google DNS 作为目标，只是为了获取本地网络接口的 IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception:
        # 如果获取失败，返回 localhost
        return '127.0.0.1'


def generate_random_token(length: int = 32) -> str:
    """生成随机令牌"""
    # 使用字母和数字
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def str_to_bool(s) -> bool:
    """将字符串转换为布尔值"""
    return str(s).lower() == 'true'
