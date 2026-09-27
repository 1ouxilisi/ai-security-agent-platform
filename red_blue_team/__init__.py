# -*- coding: utf-8 -*-
"""
red_blue_team — 自动化红蓝对抗与攻击模拟平台（第24轮升级方向1）。

模块划分：
    - attack_simulator   攻击模拟引擎：ATT&CK 战术映射 / 技术库 / 场景库 / 攻击链构建 / 执行 / 评估
    - defense_validator  防御检测验证：规则库 / 覆盖率分析 / 告警验证 / 紫队协作 / 改进建议
    - exercise_manager   红蓝对抗管理：项目 / 红队 / 蓝队 / 过程记录 / 评分 / 复盘
    - attack_visualization 攻击路径可视化：拓扑 / 时间线 / 攻击树 / 杀伤链 / 热力图 / 3D 地图
    - attack_tools       攻击工具集成：Metasploit / Cobalt Strike / Nmap / SQLMap / 自定义 / 编排
    - exercise_dashboard 红蓝对抗控制台：总览 / 管理 / 攻击 / 防御 / 可视化 / 设置

所有数据均为内存字典模拟，不落地数据库。第三方库缺失时自动回退模拟。
"""

from __future__ import annotations

__version__ = "25.0.0"
__all__ = [
    "attack_simulator",
    "defense_validator",
    "exercise_manager",
    "attack_visualization",
    "attack_tools",
    "exercise_dashboard",
    # v25.0 新增
    "AttackMapper",
    "ATTCTechnique",
    "AttackMapping",
    "AttackChainSimulator",
    "AttackChain",
    "AttackStep",
    "DetectionRuleLibrary",
    "DetectionRule",
    "DetectionResult",
]


def _import_safe(name: str):
    """安全导入子模块，失败返回 None 而不阻断包加载。"""
    try:
        return __import__(f"{__name__}.{name}", fromlist=[name])
    except Exception as exc:  # pragma: no cover - 容错导入
        import logging
        logging.getLogger("red_blue_team").warning("子模块 %s 导入失败: %s", name, exc)
        return None


attack_simulator = _import_safe("attack_simulator")
defense_validator = _import_safe("defense_validator")
exercise_manager = _import_safe("exercise_manager")
attack_visualization = _import_safe("attack_visualization")
attack_tools = _import_safe("attack_tools")
exercise_dashboard = _import_safe("exercise_dashboard")

# v25.0 新增模块直接导入
try:
    from .attack_mapper import AttackMapper, ATTCTechnique, AttackMapping
except Exception:
    AttackMapper = ATTCTechnique = AttackMapping = None

try:
    from .attack_chain import AttackChainSimulator, AttackChain, AttackStep
except Exception:
    AttackChainSimulator = AttackChain = AttackStep = None

try:
    from .detection_rules import DetectionRuleLibrary, DetectionRule, DetectionResult
except Exception:
    DetectionRuleLibrary = DetectionRule = DetectionResult = None
