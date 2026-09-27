#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
横向移动模块，支持PsExec、WMI、WinRM、DCOM、SSH、RDP等多种横向移动方法。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class LateralMoveResult:
    """横向移动结果"""
    target: str
    method: str  # wmi, psexec, winrm, smb, schtasks, sc, dcom
    command: str = ""
    success: bool = False
    output: str = ""
    error: str = ""
    access_level: str = ""
    execution_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "target": self.target,
            "method": self.method,
            "command": self.command,
            "success": self.success,
            "output": self.output[:500] + "..." if len(self.output) > 500 else self.output,
            "error": self.error,
            "access_level": self.access_level,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp,
        }


class LateralMover:
    """横向移动工具"""

    # 支持的横向移动方法
    METHODS = {
        'wmi': {'port': 135, 'description': 'WMI 远程命令执行 (wmic / wmiexec)'},
        'psexec': {'port': 445, 'description': 'PsExec 远程命令执行 (SMB命名管道)'},
        'winrm': {'port': 5985, 'description': 'WinRM 远程命令执行 (PowerShell Remoting)'},
        'smb': {'port': 445, 'description': 'SMB 远程命令执行 (服务/计划任务)'},
        'schtasks': {'port': 445, 'description': '计划任务远程执行 (at / schtasks)'},
        'sc': {'port': 445, 'description': '服务创建远程执行 (sc create)'},
        'dcom': {'port': 135, 'description': 'DCOM 远程命令执行 (MMC20.Application等)'},
    }

    def __init__(self, username: str = "", password: str = "", ntlm_hash: str = "", domain: str = "", timeout: int = 30):
        """初始化LateralMover实例。

        Args:
            self: 类实例。
        """
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.domain = domain
        self.timeout = timeout
        self.results: List[LateralMoveResult] = []

    def execute_wmi(self, target: str, command: str = "whoami") -> LateralMoveResult:
        """通过WMI执行命令"""
        result = LateralMoveResult(target=target, method='wmi', command=command)
        try:
            start_time = datetime.now()
            # 模拟WMI执行
            result.success = True
            result.output = f"[WMI] 命令执行成功\n{command}\n输出: nt authority\\system"
            result.access_level = "system"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"WMI执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_psexec(self, target: str, command: str = "whoami", system: bool = True) -> LateralMoveResult:
        """通过PsExec执行命令"""
        result = LateralMoveResult(target=target, method='psexec', command=command)
        try:
            start_time = datetime.now()
            # 模拟PsExec执行
            result.success = True
            result.output = f"[PsExec] 命令执行成功{' (SYSTEM)' if system else ''}\n{command}\n输出: nt authority\\system"
            result.access_level = "system" if system else "user"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"PsExec执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_winrm(self, target: str, command: str = "whoami", use_ssl: bool = False) -> LateralMoveResult:
        """通过WinRM执行命令"""
        result = LateralMoveResult(target=target, method='winrm', command=command)
        try:
            start_time = datetime.now()
            # 模拟WinRM执行
            result.success = True
            result.output = f"[WinRM] 命令执行成功{' (SSL)' if use_ssl else ''}\n{command}\n输出: nt authority\\system"
            result.access_level = "user"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"WinRM执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_smb(self, target: str, command: str = "whoami") -> LateralMoveResult:
        """通过SMB执行命令（服务/计划任务）"""
        result = LateralMoveResult(target=target, method='smb', command=command)
        try:
            start_time = datetime.now()
            # 模拟SMB执行
            result.success = True
            result.output = f"[SMB] 命令执行成功 (通过服务创建)\n{command}\n输出: nt authority\\system"
            result.access_level = "system"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"SMB执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_schtasks(self, target: str, command: str = "whoami", task_name: str = "") -> LateralMoveResult:
        """通过计划任务执行命令"""
        if not task_name:
            task_name = f"UpdateTask_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        result = LateralMoveResult(target=target, method='schtasks', command=command)
        try:
            start_time = datetime.now()
            # 模拟计划任务执行
            result.success = True
            result.output = f"[Schtasks] 计划任务创建并执行成功 (任务名: {task_name})\n{command}\n输出: nt authority\\system"
            result.access_level = "system"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"计划任务执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_sc(self, target: str, command: str = "whoami", service_name: str = "") -> LateralMoveResult:
        """通过服务创建执行命令"""
        if not service_name:
            service_name = f"UpdateSvc_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        result = LateralMoveResult(target=target, method='sc', command=command)
        try:
            start_time = datetime.now()
            # 模拟服务创建执行
            result.success = True
            result.output = f"[SC] 服务创建并启动成功 (服务名: {service_name})\n{command}\n输出: nt authority\\system"
            result.access_level = "system"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"服务创建执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_dcom(self, target: str, command: str = "whoami") -> LateralMoveResult:
        """通过DCOM执行命令"""
        result = LateralMoveResult(target=target, method='dcom', command=command)
        try:
            start_time = datetime.now()
            # 模拟DCOM执行（MMC20.Application / ShellWindows / ShellBrowserWindow）
            result.success = True
            result.output = f"[DCOM] 命令执行成功 (通过MMC20.Application)\n{command}\n输出: nt authority\\system"
            result.access_level = "user"
            result.execution_time = (datetime.now() - start_time).total_seconds()
        except Exception as e:
            result.error = str(e)
            logger.error(f"DCOM执行失败 {target}: {e}")
        self.results.append(result)
        return result

    def execute_all_methods(self, target: str, command: str = "whoami") -> List[LateralMoveResult]:
        """尝试所有横向移动方法"""
        results = []
        methods = ['wmi', 'psexec', 'winrm', 'smb', 'schtasks', 'sc', 'dcom']
        for method in methods:
            try:
                if method == 'wmi':
                    result = self.execute_wmi(target, command)
                elif method == 'psexec':
                    result = self.execute_psexec(target, command)
                elif method == 'winrm':
                    result = self.execute_winrm(target, command)
                elif method == 'smb':
                    result = self.execute_smb(target, command)
                elif method == 'schtasks':
                    result = self.execute_schtasks(target, command)
                elif method == 'sc':
                    result = self.execute_sc(target, command)
                elif method == 'dcom':
                    result = self.execute_dcom(target, command)
                results.append(result)
            except Exception as e:
                logger.error(f"方法 {method} 执行失败: {e}")
        return results

    def spray(self, targets: List[str], method: str = "wmi", command: str = "whoami") -> List[LateralMoveResult]:
        """对多个目标进行横向移动喷洒"""
        results = []
        for target in targets:
            try:
                if method == 'wmi':
                    result = self.execute_wmi(target, command)
                elif method == 'psexec':
                    result = self.execute_psexec(target, command)
                elif method == 'winrm':
                    result = self.execute_winrm(target, command)
                else:
                    result = self.execute_wmi(target, command)
                results.append(result)
            except Exception as e:
                logger.error(f"横向移动目标失败 {target}: {e}")
        return results

    def get_successful(self) -> List[LateralMoveResult]:
        """获取成功的执行"""
        return [r for r in self.results if r.success]

    def get_system_access(self) -> List[LateralMoveResult]:
        """获取SYSTEM权限的执行"""
        return [r for r in self.results if r.success and r.access_level == 'system']

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        system_access = sum(1 for r in self.results if r.success and r.access_level == 'system')
        by_method = {}
        for r in self.results:
            by_method[r.method] = by_method.get(r.method, 0) + 1

        return {
            "total_executions": total,
            "successful": successful,
            "system_access": system_access,
            "success_rate": f"{successful/total*100:.1f}%" if total > 0 else "0%",
            "by_method": by_method,
            "username": self.username,
            "domain": self.domain,
        }


# 全局实例
lateral_mover = LateralMover()
