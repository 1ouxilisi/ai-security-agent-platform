# saas 模块包



"""
__init__模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

# 第10轮升级：SaaS 化基础模块单例导出
try:
    from saas.auth_manager import AuthManager, auth_manager
    from saas.mfa_manager import MFAManager, mfa_manager
    from saas.user_manager import UserManager, user_manager
    from saas.invitation_manager import InvitationManager, invitation_manager
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger(__name__).warning(f"SaaS 模块部分加载失败: {_e}")

__all__ = [
    "AuthManager", "auth_manager",
    "MFAManager", "mfa_manager",
    "UserManager", "user_manager",
    "InvitationManager", "invitation_manager",
]
