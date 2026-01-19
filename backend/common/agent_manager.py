"""Agent Manager 单例模块"""
from backend.agents.manager import AgentManager
from backend.common.config import config_data

# 全局 agent_manager 实例
_agent_manager = None


def get_agent_manager() -> AgentManager:
    """获取全局 AgentManager 实例"""
    global _agent_manager
    if _agent_manager is None:
        _agent_manager = AgentManager(config_data)
    return _agent_manager


def init_agent_manager():
    """初始化 AgentManager（在应用启动时调用）"""
    global _agent_manager
    _agent_manager = AgentManager(config_data)
    return _agent_manager
