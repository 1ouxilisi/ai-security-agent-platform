# -*- coding: utf-8 -*-
"""
backup 数据备份恢复模块（第10轮升级，第六优先级）。

模块功能：
    - BackupManager：完整/增量/差异备份，在线备份，压缩(gzip)、加密(XOR+base64)、
      校验(SHA256)、定时计划、自动清理、备份元数据管理。
    - RestoreManager：完整/指定表/指定数据恢复，恢复前预览、恢复前自动备份、
      失败自动回滚、恢复报告。
    - MigrationManager：版本升级迁移 / SQLite->MySQL/PostgreSQL 兼容 SQL 生成 /
      租户数据迁移，迁移预览、执行、回滚、报告。
    - ExportManager：JSON/CSV/XML/SQL/HTML 五种格式导出，压缩、加密、统计。

设计要点：
    - 仅依赖 Python 标准库（sqlite3 / zlib / gzip / zipfile / hashlib / base64 / json）。
    - 元数据存放在 data/ai_hacking_agent.db，表名前缀 backup_。
    - 备份文件落盘到 data/backups/。
    - 所有管理器均为单例，模块级实例可直接 import 使用。

注意事项：
    - 本模块仅用于授权的安全测试与运维场景。
    - 请勿用于非法用途。
"""

from __future__ import annotations

# 延迟导入，避免自测环境缺表时直接炸掉；真正使用时再实例化
try:  # pragma: no cover
    from backup.backup_manager import BackupManager, backup_manager  # noqa: F401
    from backup.restore_manager import RestoreManager, restore_manager  # noqa: F401
    from backup.migration_manager import MigrationManager, migration_manager  # noqa: F401
    from backup.export_manager import ExportManager, export_manager  # noqa: F401
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger(__name__).warning("backup 模块部分组件延迟加载: %s", _e)

__all__ = [
    "BackupManager",
    "backup_manager",
    "RestoreManager",
    "restore_manager",
    "MigrationManager",
    "migration_manager",
    "ExportManager",
    "export_manager",
]

__version__ = "10.0.0"
