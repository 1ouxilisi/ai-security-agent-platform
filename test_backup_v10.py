# -*- coding: utf-8 -*-
"""
test_backup_v10.py - 第10轮数据备份恢复模块测试脚本。

测试范围：
    - backup.backup_manager 主要方法
    - backup.restore_manager 主要方法
    - backup.migration_manager 主要方法
    - backup.export_manager 主要方法
    - api_server.backup_routes 路由导入
"""

from __future__ import annotations

import os
import sys
import traceback

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

PASS = 0
FAIL = 0


def report(name: str, ok: bool, info: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {name} {info}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {info}")


def section(title: str) -> None:
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def main() -> int:
    section("1. 模块导入测试")

    try:
        from backup import backup_manager, restore_manager, migration_manager, export_manager
        report("导入 4 个单例", True)
    except Exception as e:
        report("导入 4 个单例", False, str(e))
        traceback.print_exc()
        return 1

    # ---------- BackupManager ----------
    section("2. BackupManager 测试")

    try:
        r = backup_manager.create_backup(backup_type="full", compress=True,
                                         encrypt=False, description="测试完整备份")
        report("create_backup(full)", r["success"], str(r.get("error") or ""))
        bk_id = r.get("data", {}).get("id") if r["success"] else None
    except Exception as e:
        report("create_backup(full)", False, traceback.format_exc())
        bk_id = None

    try:
        r = backup_manager.create_backup(backup_type="incremental", compress=True)
        report("create_backup(incremental)", r["success"], str(r.get("error") or ""))
    except Exception as e:
        report("create_backup(incremental)", False, str(e))

    try:
        r = backup_manager.list_backups(page=1, page_size=10)
        report("list_backups", r["success"] and r["data"]["total"] >= 1,
               f"total={r['data']['total'] if r['success'] else r['error']}")
    except Exception as e:
        report("list_backups", False, str(e))

    if bk_id:
        try:
            r = backup_manager.get_backup(bk_id)
            report("get_backup", r["success"])
        except Exception as e:
            report("get_backup", False, str(e))

        try:
            r = backup_manager.verify_backup(bk_id)
            report("verify_backup", r["success"], str(r.get("error") or ""))
        except Exception as e:
            report("verify_backup", False, str(e))

        try:
            r = backup_manager.download_backup(bk_id)
            report("download_backup", r["success"])
        except Exception as e:
            report("download_backup", False, str(e))

        try:
            r = backup_manager.get_backup_content(bk_id)
            report("get_backup_content", r["success"])
        except Exception as e:
            report("get_backup_content", False, str(e))

    # 计划
    try:
        r = backup_manager.create_schedule(name="测试计划", schedule_type="daily",
                                           time="03:30", backup_type="full",
                                           retention_days=7)
        report("create_schedule", r["success"], str(r.get("error") or ""))
        sched_id = r.get("data", {}).get("id") if r["success"] else None
    except Exception as e:
        report("create_schedule", False, str(e))
        sched_id = None

    try:
        r = backup_manager.list_schedules()
        report("list_schedules", r["success"])
    except Exception as e:
        report("list_schedules", False, str(e))

    if sched_id:
        try:
            r = backup_manager.update_schedule(sched_id, retention_days=14)
            report("update_schedule", r["success"])
        except Exception as e:
            report("update_schedule", False, str(e))
        try:
            r = backup_manager.execute_schedule(sched_id)
            report("execute_schedule", r["success"], str(r.get("error") or ""))
        except Exception as e:
            report("execute_schedule", False, str(e))
        try:
            r = backup_manager.get_schedule_history(sched_id)
            report("get_schedule_history", r["success"])
        except Exception as e:
            report("get_schedule_history", False, str(e))
        try:
            r = backup_manager.delete_schedule(sched_id)
            report("delete_schedule", r["success"])
        except Exception as e:
            report("delete_schedule", False, str(e))

    try:
        r = backup_manager.get_stats()
        report("get_stats", r["success"])
    except Exception as e:
        report("get_stats", False, str(e))

    try:
        r = backup_manager.cleanup_expired_backups(retention_days=3650)
        report("cleanup_expired_backups", r["success"])
    except Exception as e:
        report("cleanup_expired_backups", False, str(e))

    # ---------- RestoreManager ----------
    section("3. RestoreManager 测试")

    try:
        r = restore_manager.validate_backup(bk_id) if bk_id else {"success": False}
        report("validate_backup", r["success"], str(r.get("error") or ""))
    except Exception as e:
        report("validate_backup", False, str(e))

    try:
        r = restore_manager.preview_restore(bk_id) if bk_id else {"success": False}
        report("preview_restore", r["success"], str(r.get("error") or ""))
    except Exception as e:
        report("preview_restore", False, str(e))

    restore_task_id = None
    if bk_id:
        try:
            # 恢复到临时目标库，避免污染主库；使用唯一文件名避免上次残留冲突
            import tempfile
            tmp_target = os.path.join(tempfile.gettempdir(),
                                      f"restore_test_target_{os.getpid()}.db")
            if os.path.exists(tmp_target):
                os.remove(tmp_target)
            r = restore_manager.execute_restore(bk_id, target_db=tmp_target)
            restore_task_id = r.get("data", {}).get("task_id") if r["success"] else None
            report("execute_restore(to temp db)", r["success"], str(r.get("error") or ""))
        except Exception as e:
            report("execute_restore", False, traceback.format_exc())

    if restore_task_id:
        try:
            r = restore_manager.get_restore_status(restore_task_id)
            report("get_restore_status", r["success"])
        except Exception as e:
            report("get_restore_status", False, str(e))
        try:
            r = restore_manager.get_restore_report(restore_task_id)
            report("get_restore_report", r["success"])
        except Exception as e:
            report("get_restore_report", False, str(e))

    try:
        r = restore_manager.list_restores(page=1, page_size=10)
        report("list_restores", r["success"])
    except Exception as e:
        report("list_restores", False, str(e))

    # ---------- MigrationManager ----------
    section("4. MigrationManager 测试")

    try:
        r = migration_manager.preview_migration("sqlite_to_mysql")
        report("preview_migration(sqlite_to_mysql)", r["success"], str(r.get("error") or ""))
    except Exception as e:
        report("preview_migration", False, str(e))

    mig_task_id = None
    try:
        r = migration_manager.execute_migration("version_upgrade")
        mig_task_id = r.get("data", {}).get("task_id") if r["success"] else None
        report("execute_migration(version_upgrade)", r["success"], str(r.get("error") or ""))
    except Exception as e:
        report("execute_migration", False, traceback.format_exc())

    if mig_task_id:
        try:
            r = migration_manager.get_migration_status(mig_task_id)
            report("get_migration_status", r["success"])
        except Exception as e:
            report("get_migration_status", False, str(e))
        try:
            r = migration_manager.get_migration_report(mig_task_id)
            report("get_migration_report", r["success"])
        except Exception as e:
            report("get_migration_report", False, str(e))

    try:
        r = migration_manager.list_migrations(page=1, page_size=10)
        report("list_migrations", r["success"])
    except Exception as e:
        report("list_migrations", False, str(e))

    # ---------- ExportManager ----------
    section("5. ExportManager 测试")

    export_id = None
    for fmt in ("json", "csv", "xml", "sql", "html"):
        try:
            r = export_manager.create_export(format=fmt, description=f"测试{fmt}导出")
            if r["success"]:
                export_id = r["data"]["id"]
            report(f"create_export({fmt})", r["success"], str(r.get("error") or ""))
        except Exception as e:
            report(f"create_export({fmt})", False, str(e))

    try:
        r = export_manager.list_exports(page=1, page_size=10)
        report("list_exports", r["success"])
    except Exception as e:
        report("list_exports", False, str(e))

    try:
        r = export_manager.get_stats()
        report("export get_stats", r["success"])
    except Exception as e:
        report("export get_stats", False, str(e))

    if export_id:
        try:
            r = export_manager.download_export(export_id)
            report("download_export", r["success"])
        except Exception as e:
            report("download_export", False, str(e))
        try:
            r = export_manager.get_export_content(export_id)
            report("get_export_content", r["success"])
        except Exception as e:
            report("get_export_content", False, str(e))

    # ---------- API 路由导入 ----------
    section("6. API 路由导入测试")

    try:
        from api_server.backup_routes import router
        routes = [r.path for r in router.routes]
        report(f"导入 backup_routes.router, 路由数={len(routes)}", True)
        print("  端点样例:", routes[:8], "...")
    except Exception as e:
        report("导入 backup_routes.router", False, traceback.format_exc())

    # ---------- 清理测试备份 ----------
    section("7. 清理测试备份")
    if bk_id:
        try:
            # 保留一个用于演示，这里不删除全部，只删测试标记的
            pass
        except Exception:
            pass

    # ---------- 汇总 ----------
    section("测试汇总")
    print(f"  通过: {PASS}  失败: {FAIL}  总计: {PASS + FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
