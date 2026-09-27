# -*- coding: utf-8 -*-
"""
audit 审计日志深化模块。

模块功能：
    - 操作审计日志（带哈希链防篡改）
    - 登录日志与会话管理
    - API 调用日志（脱敏、性能监控、异常检测）
    - 数据访问日志（敏感数据访问与泄露检测）
    - 日志管理器（归档、清理、跨表搜索、完整性校验）

设计要点：
    - 所有表使用 CREATE TABLE IF NOT EXISTS 自建，依赖全局 db 实例（WAL 模式）
    - 写入采用批量 executemany，避免大量日志阻塞主流程
    - 操作日志基于 SHA256 哈希链，可校验是否被篡改

注意事项：
    - 本模块仅用于授权的安全测试与审计
    - 请勿用于非法用途
"""

from __future__ import annotations

# 暴露便捷的单例访问器，业务代码可直接 from audit import get_operation_logger
try:  # pragma: no cover - 导入失败不影响其他模块
    from audit.operation_log import OperationLogger, get_operation_logger  # noqa: F401
    from audit.login_log import LoginLogger, get_login_logger  # noqa: F401
    from audit.api_log import ApiCallLogger, get_api_logger  # noqa: F401
    from audit.data_access_log import DataAccessLogger, get_data_access_logger  # noqa: F401
    from audit.log_manager import LogManager, get_log_manager  # noqa: F401
except Exception as _e:  # pragma: no cover
    # 自测环境可能尚未建表，延迟到首次调用时再初始化
    import logging
    logging.getLogger(__name__).warning(f"audit 模块部分组件延迟加载: {_e}")

__all__ = [
    "OperationLogger",
    "get_operation_logger",
    "LoginLogger",
    "get_login_logger",
    "ApiCallLogger",
    "get_api_logger",
    "DataAccessLogger",
    "get_data_access_logger",
    "LogManager",
    "get_log_manager",
]

__version__ = "1.0.0"
