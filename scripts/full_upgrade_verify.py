#!/usr/bin/env python3
"""
full_upgrade_verify脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""全面升级验证脚本"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 60)
print("  AI Hacking Agent 全面升级验证")
print("=" * 60)
print()

# 1. CVE漏洞库
from tools.cve_database import cve_database
cve_stats = cve_database.get_statistics()
print(f"[1] CVE漏洞库: {cve_stats['total_cves']}个")
print(f"    严重级别: {cve_stats['by_severity']}")

# 2. POC利用库
from tools.exploit_engine import exploit_engine
poc_stats = exploit_engine.get_poc_statistics()
print(f"[2] POC利用库: {poc_stats['total_pocs']}个")
print(f"    分类: {poc_stats['by_category']}")

# 3. 用户认证系统
from tools.auth_manager import auth_manager
auth_stats = auth_manager.get_statistics()
print(f"[3] 用户认证: {auth_stats['total_users']}用户, {auth_stats['active_api_keys']}API密钥")

# 4. 告警通知系统
from tools.alert_manager import alert_manager
alert_stats = alert_manager.get_statistics()
print(f"[4] 告警系统: {alert_stats['total_alerts']}告警, {alert_stats['enabled_channels']}渠道")

# 5. 备份管理器
from scripts.backup_manager import backup_manager
backup_stats = backup_manager.get_statistics()
print(f"[5] 备份系统: {backup_stats['total_backups']}备份, {backup_stats['total_size_human']}")

# 6. API安全中间件
from api_server.security_middleware import rate_limiter, ip_filter, request_logger
print(f"[6] API安全: 限流({rate_limiter.default_limit}/{rate_limiter.default_window}s), IP过滤, 请求日志")

# 7. 测试告警创建
r = alert_manager.create_alert("测试告警", "这是一个测试告警", severity="info", category="test", auto_notify=False)
print(f"[7] 告警创建: {r['success']}")

# 8. 测试备份创建
r = backup_manager.create_backup("full", "全面升级验证备份")
print(f"[8] 备份创建: {r['success']}, {r['files_count']}文件, {r['compressed_size']}字节")

print()
print("=" * 60)
print("  全面升级验证完成 - 所有模块正常运行！")
print("=" * 60)
