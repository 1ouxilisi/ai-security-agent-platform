#!/usr/bin/env python3
"""
backup_manager脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import sys
import json
import time
import shutil
import sqlite3
import zipfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from utils.logger import log


class BackupManager:
    """备份管理器"""

    def __init__(self, project_root: str = None):
        """初始化BackupManager实例。

        Args:
            self: 类实例。
        """
        if project_root is None:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.project_root = project_root
        self.backup_dir = os.path.join(project_root, "data", "backups")
        os.makedirs(self.backup_dir, exist_ok=True)

        # 需要备份的目录和文件
        self.backup_targets = [
            "data/cve_database.db",
            "data/enterprise.db",
            "data/auth.db",
            "data/alerts.db",
            "data/hacking_agent.db",
            "data/reports",
            "data/scans",
            "data/logs",
            ".env",
            "config/settings.yaml",
        ]

    def create_backup(self, backup_type: str = "full",
                      description: str = "") -> Dict[str, Any]:
        """创建备份"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{backup_type}_{timestamp}"
        backup_path = os.path.join(self.backup_dir, backup_name)
        os.makedirs(backup_path, exist_ok=True)

        log.info(f"开始创建{backup_type}备份: {backup_name}")

        backed_up_files = []
        total_size = 0

        for target in self.backup_targets:
            source_path = os.path.join(self.project_root, target)
            if not os.path.exists(source_path):
                continue

            dest_path = os.path.join(backup_path, target)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            try:
                if os.path.isdir(source_path):
                    shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(source_path, dest_path)

                file_size = os.path.getsize(dest_path) if os.path.isfile(dest_path) else sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, dirnames, filenames in os.walk(dest_path)
                    for filename in filenames
                )
                total_size += file_size
                backed_up_files.append(target)
                log.debug(f"已备份: {target} ({file_size} bytes)")
            except Exception as e:
                log.error(f"备份失败 {target}: {e}")

        # 创建备份元数据
        metadata = {
            "backup_name": backup_name,
            "backup_type": backup_type,
            "description": description,
            "created_at": datetime.now().isoformat(),
            "project_root": self.project_root,
            "files_count": len(backed_up_files),
            "total_size": total_size,
            "files": backed_up_files,
            "version": "1.0",
        }

        metadata_path = os.path.join(backup_path, "backup_metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

        # 压缩备份
        zip_path = backup_path + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(backup_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, backup_path)
                    zipf.write(file_path, arcname)

        # 删除未压缩的目录
        shutil.rmtree(backup_path, ignore_errors=True)

        zip_size = os.path.getsize(zip_path)

        log.info(f"备份完成: {backup_name}.zip ({zip_size} bytes, {len(backed_up_files)}个文件)")

        # 清理旧备份（保留最近10个）
        self._cleanup_old_backups(keep=10)

        return {
            "success": True,
            "backup_name": backup_name,
            "backup_path": zip_path,
            "backup_type": backup_type,
            "files_count": len(backed_up_files),
            "original_size": total_size,
            "compressed_size": zip_size,
            "compression_ratio": round(zip_size / total_size * 100, 1) if total_size > 0 else 0,
            "created_at": metadata["created_at"],
        }

    def restore_backup(self, backup_name: str,
                        restore_path: str = None) -> Dict[str, Any]:
        """恢复备份"""
        if restore_path is None:
            restore_path = self.project_root

        # 查找备份文件
        backup_zip = os.path.join(self.backup_dir, f"{backup_name}.zip")
        if not os.path.exists(backup_zip):
            return {"success": False, "error": f"备份文件不存在: {backup_name}"}

        log.info(f"开始恢复备份: {backup_name}")

        # 先备份当前数据（安全起见）
        safety_backup = self.create_backup(backup_type="safety_before_restore",
                                            description=f"恢复{backup_name}前的安全备份")

        # 解压备份
        temp_dir = os.path.join(self.backup_dir, f"restore_{int(time.time())}")
        os.makedirs(temp_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(backup_zip, "r") as zipf:
                zipf.extractall(temp_dir)

            # 读取元数据
            metadata_path = os.path.join(temp_dir, "backup_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                files_to_restore = metadata.get("files", [])
            else:
                files_to_restore = []
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file != "backup_metadata.json":
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, temp_dir)
                            files_to_restore.append(rel_path)

            # 恢复文件
            restored_files = []
            for file_rel in files_to_restore:
                source = os.path.join(temp_dir, file_rel)
                dest = os.path.join(restore_path, file_rel)

                if not os.path.exists(source):
                    continue

                os.makedirs(os.path.dirname(dest), exist_ok=True)

                try:
                    if os.path.isdir(source):
                        shutil.copytree(source, dest, dirs_exist_ok=True)
                    else:
                        shutil.copy2(source, dest)
                    restored_files.append(file_rel)
                except Exception as e:
                    log.error(f"恢复失败 {file_rel}: {e}")

            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)

            log.info(f"恢复完成: {backup_name} ({len(restored_files)}个文件)")

            return {
                "success": True,
                "backup_name": backup_name,
                "restored_files": len(restored_files),
                "safety_backup": safety_backup.get("backup_name"),
                "restored_at": datetime.now().isoformat(),
            }
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {"success": False, "error": str(e)}

    def list_backups(self) -> List[Dict[str, Any]]:
        """列出所有备份"""
        backups = []
        for file in os.listdir(self.backup_dir):
            if file.endswith(".zip") and file.startswith("backup_"):
                backup_path = os.path.join(self.backup_dir, file)
                backup_name = file.replace(".zip", "")
                size = os.path.getsize(backup_path)
                created = datetime.fromtimestamp(os.path.getmtime(backup_path))

                # 尝试读取元数据
                metadata = {}
                try:
                    with zipfile.ZipFile(backup_path, "r") as zipf:
                        if "backup_metadata.json" in zipf.namelist():
                            with zipf.open("backup_metadata.json") as f:
                                metadata = json.loads(f.read().decode("utf-8"))
                except Exception:
                    pass

                backups.append({
                    "backup_name": backup_name,
                    "backup_type": metadata.get("backup_type", "unknown"),
                    "description": metadata.get("description", ""),
                    "size": size,
                    "size_human": self._human_size(size),
                    "files_count": metadata.get("files_count", 0),
                    "created_at": created.isoformat(),
                })

        backups.sort(key=lambda x: x["created_at"], reverse=True)
        return backups

    def delete_backup(self, backup_name: str) -> Dict[str, Any]:
        """删除备份"""
        backup_zip = os.path.join(self.backup_dir, f"{backup_name}.zip")
        if not os.path.exists(backup_zip):
            return {"success": False, "error": f"备份文件不存在: {backup_name}"}

        os.remove(backup_zip)
        log.info(f"已删除备份: {backup_name}")
        return {"success": True, "backup_name": backup_name}

    def _cleanup_old_backups(self, keep: int = 10):
        """清理旧备份"""
        backups = self.list_backups()
        if len(backups) > keep:
            for old_backup in backups[keep:]:
                self.delete_backup(old_backup["backup_name"])

    def _human_size(self, size: int) -> str:
        """人类可读的文件大小"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    def get_statistics(self) -> Dict[str, Any]:
        """获取备份统计"""
        backups = self.list_backups()
        total_size = sum(b["size"] for b in backups)

        return {
            "total_backups": len(backups),
            "total_size": total_size,
            "total_size_human": self._human_size(total_size),
            "backup_dir": self.backup_dir,
            "latest_backup": backups[0] if backups else None,
            "oldest_backup": backups[-1] if backups else None,
        }


# 全局备份管理器实例
backup_manager = BackupManager()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="数据备份恢复工具")
    parser.add_argument("action", choices=["backup", "restore", "list", "delete", "stats"],
                       help="操作类型")
    parser.add_argument("--name", help="备份名称（restore/delete时使用）")
    parser.add_argument("--type", default="full", choices=["full", "incremental"],
                       help="备份类型")
    parser.add_argument("--description", default="", help="备份描述")

    args = parser.parse_args()

    if args.action == "backup":
        result = backup_manager.create_backup(args.type, args.description)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.action == "restore":
        if not args.name:
            print("错误: 恢复备份需要指定--name参数")
            sys.exit(1)
        result = backup_manager.restore_backup(args.name)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.action == "list":
        backups = backup_manager.list_backups()
        print(json.dumps(backups, indent=2, ensure_ascii=False))
    elif args.action == "delete":
        if not args.name:
            print("错误: 删除备份需要指定--name参数")
            sys.exit(1)
        result = backup_manager.delete_backup(args.name)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.action == "stats":
        stats = backup_manager.get_statistics()
        print(json.dumps(stats, indent=2, ensure_ascii=False))
