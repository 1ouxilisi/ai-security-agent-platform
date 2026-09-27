# -*- coding: utf-8 -*-
"""
task_panel.py — 统一任务执行面板后端。

提供：
  - 场景模板库
  - 任务提交 / 状态查询 / 结果查看 / 操作（重试/取消/删除/导出/分享）
  - 任务历史（分页 + 筛选 + 搜索 + 排序）
全部为内存字典模拟，数据真实有意义。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .common import _clean, now_str, new_id, paginate, apply_filters, search_in


# --------------------------------------------------------------------------- #
# 场景模板
# --------------------------------------------------------------------------- #
SCENARIOS: List[Dict[str, Any]] = [
    {
        "code": "web_vuln_scan",
        "name": "Web 应用漏洞扫描",
        "icon": "🌐",
        "category": "web",
        "description": "对授权目标 Web 应用进行 OWASP Top10 检测，覆盖注入、XSS、反序列化等。",
        "default_target_hint": "https://example.com",
        "params": [
            {"key": "depth", "label": "爬取深度", "type": "int", "default": 3, "min": 1, "max": 8},
            {"key": "threads", "label": "并发线程", "type": "int", "default": 10, "min": 1, "max": 50},
            {"key": "check_owasp", "label": "OWASP Top10", "type": "bool", "default": True},
            {"key": "check_auth", "label": "认证与会话测试", "type": "bool", "default": True},
        ],
        "estimated_minutes": 25,
    },
    {
        "code": "api_security",
        "name": "API 安全评估",
        "icon": "🔌",
        "category": "api",
        "description": "对 OpenAPI/Swagger 接口做鉴权、越权、参数污染与敏感数据泄露检测。",
        "default_target_hint": "https://api.example.com/openapi.json",
        "params": [
            {"key": "schema_url", "label": "OpenAPI 文档地址", "type": "str", "default": ""},
            {"key": "test_idor", "label": "越权(IDOR)测试", "type": "bool", "default": True},
            {"key": "test_rate_limit", "label": "限流测试", "type": "bool", "default": False},
        ],
        "estimated_minutes": 18,
    },
    {
        "code": "asset_discovery",
        "name": "资产测绘与发现",
        "icon": "🗺️",
        "category": "recon",
        "description": "对子域名、端口、服务、目录指纹进行被动+主动发现。",
        "default_target_hint": "example.com",
        "params": [
            {"key": "port_scope", "label": "端口范围", "type": "str", "default": "1-10000"},
            {"key": "subdomain", "label": "子域名枚举", "type": "bool", "default": True},
            {"key": "fingerprint", "label": "服务指纹识别", "type": "bool", "default": True},
        ],
        "estimated_minutes": 40,
    },
    {
        "code": "config_audit",
        "name": "安全配置基线审计",
        "icon": "🛡️",
        "category": "audit",
        "description": "按 CIS 基线对服务器/中间件/数据库配置进行合规性检查。",
        "default_target_hint": "asset group: prod-web",
        "params": [
            {"key": "baseline", "label": "基线标准", "type": "str", "default": "CIS v2.0"},
            {"key": "strict", "label": "严格模式", "type": "bool", "default": True},
        ],
        "estimated_minutes": 15,
    },
    {
        "code": "darkweb_monitor",
        "name": "暗网与泄露监控",
        "icon": "🕶️",
        "category": "threat",
        "description": "监控域名/邮箱/凭证在泄露库与暗网论坛的暴露情况。",
        "default_target_hint": "corp.example.com",
        "params": [
            {"key": "include_breach", "label": "泄露库匹配", "type": "bool", "default": True},
            {"key": "include_forum", "label": "论坛情报", "type": "bool", "default": False},
        ],
        "estimated_minutes": 30,
    },
    {
        "code": "supply_chain",
        "name": "供应链安全扫描",
        "icon": "⛓️",
        "category": "supply",
        "description": "对依赖清单(requirements/package.json)做已知漏洞与许可证风险检测。",
        "default_target_hint": "pip freeze output",
        "params": [
            {"key": "lockfile", "label": "锁定文件路径", "type": "str", "default": ""},
            {"key": "license_check", "label": "许可证检查", "type": "bool", "default": True},
        ],
        "estimated_minutes": 12,
    },
]


# --------------------------------------------------------------------------- #
# 任务存储
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _seed_tasks() -> None:
    if TASKS:
        return
    samples = [
        ("web_vuln_scan", "https://shop.example.com", "done", 92, 17, "high"),
        ("api_security", "https://api.example.com/v2", "done", 74, 9, "medium"),
        ("asset_discovery", "example.com", "done", 100, 43, "info"),
        ("config_audit", "prod-web-01", "done", 61, 5, "high"),
        ("darkweb_monitor", "corp.example.com", "done", 88, 3, "critical"),
        ("supply_chain", "backend/requirements.txt", "running", 45, 4, "medium"),
        ("web_vuln_scan", "https://blog.example.com", "pending", 0, 0, "info"),
        ("api_security", "https://admin.example.com/api", "failed", 67, 2, "high"),
    ]
    risk_map = {"critical": 90, "high": 72, "medium": 55, "info": 20}
    for i, (sc, tgt, status, prog, found, sev) in enumerate(samples):
        sid = f"task_seed_{1000 + i}"
        sc_obj = next(s for s in SCENARIOS if s["code"] == sc)
        steps = _build_steps(sc, status, prog)
        TASKS[sid] = {
            "task_id": sid,
            "scenario": sc,
            "scenario_name": sc_obj["name"],
            "target": tgt,
            "status": status,
            "progress": prog,
            "created_at": now_str(),
            "updated_at": now_str(),
            "finished_at": now_str() if status in ("done", "failed") else None,
            "params": {"depth": 3, "threads": 10},
            "steps": steps,
            "logs": _build_logs(sc, prog),
            "result": {
                "risk_score": risk_map.get(sev, 50),
                "risk_level": sev,
                "findings_count": found,
                "severity_breakdown": {"critical": found // 4, "high": found // 3,
                                       "medium": found // 2, "low": found // 1 or 1},
                "report_id": f"rep_{sid}",
                "summary": f"针对 {tgt} 的{sc_obj['name']}已完成，共发现 {found} 项发现。"
                if status == "done" else None,
            },
            "error": "目标连接超时（30s 无响应），已在第 4 步终止。" if status == "failed" else None,
        }


def _build_steps(scenario: str, status: str, progress: int) -> List[Dict[str, Any]]:
    base = [
        "初始化扫描引擎",
        "目标连通性预检",
        "资产枚举与指纹识别",
        "PoC 载荷投递",
        "结果降噪与误报过滤",
        "报告生成",
    ]
    out = []
    done_count = int(progress / 100 * len(base))
    for i, s in enumerate(base):
        if i < done_count or status == "done":
            st = "done"
        elif i == done_count and status == "running":
            st = "running"
        else:
            st = "pending"
        out.append({"index": i + 1, "name": s, "status": st,
                     "duration_ms": 1200 + i * 850})
    return out


def _build_logs(scenario: str, progress: int) -> List[str]:
    lines = [
        f"[{now_str()}] 引擎初始化完成，加载 {len(SCENARIOS)} 个场景模板",
        "[INFO] 开始解析目标地址与端口",
        "[INFO] 预检通过，启动扫描 worker",
        "[INFO] 已投递第一批探测载荷",
        "[INFO] 命中 1 个疑似注入点，进入验证阶段",
    ]
    keep = max(1, int(progress / 100 * len(lines)))
    return lines[:keep]


_seed_tasks()


# --------------------------------------------------------------------------- #
# 业务函数
# --------------------------------------------------------------------------- #
def list_scenarios() -> List[Dict[str, Any]]:
    return list(SCENARIOS)


def get_scenario(code: str) -> Optional[Dict[str, Any]]:
    return next((s for s in SCENARIOS if s["code"] == code), None)


def submit_task(scenario: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    sc_obj = get_scenario(scenario)
    if not sc_obj:
        raise ValueError(f"未知场景模板: {scenario}")
    if not target or not str(target).strip():
        raise ValueError("目标不能为空")
    tid = new_id("task")
    TASKS[tid] = {
        "task_id": tid,
        "scenario": scenario,
        "scenario_name": sc_obj["name"],
        "target": target.strip(),
        "status": "running",
        "progress": 5,
        "created_at": now_str(),
        "updated_at": now_str(),
        "finished_at": None,
        "params": params or {},
        "steps": _build_steps(scenario, "running", 5),
        "logs": [f"[{now_str()}] 任务已提交，场景={scenario}，目标={target}"],
        "result": None,
        "error": None,
    }
    return get_task(tid)


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return TASKS.get(task_id)


def list_tasks(page: int = 1, page_size: int = 20, status: str = "",
               scenario: str = "", q: str = "",
               sort_by: str = "created_at", sort_dir: str = "desc") -> Dict[str, Any]:
    items = list(TASKS.values())
    items = apply_filters(items, {"status": status, "scenario": scenario})
    items = search_in(items, q, ["task_id", "target", "scenario_name"])
    return paginate(items, page, page_size, sort_by, sort_dir)


def retry_task(task_id: str) -> Optional[Dict[str, Any]]:
    t = TASKS.get(task_id)
    if not t:
        return None
    t["status"] = "running"
    t["progress"] = 5
    t["error"] = None
    t["finished_at"] = None
    t["steps"] = _build_steps(t["scenario"], "running", 5)
    t["logs"] = t["logs"] + [f"[{now_str()}] 手动重试任务"]
    t["updated_at"] = now_str()
    return t


def cancel_task(task_id: str) -> Optional[Dict[str, Any]]:
    t = TASKS.get(task_id)
    if not t:
        return None
    if t["status"] in ("done", "failed", "cancelled"):
        return t
    t["status"] = "cancelled"
    t["finished_at"] = now_str()
    t["updated_at"] = now_str()
    t["logs"] = t["logs"] + [f"[{now_str()}] 用户取消任务"]
    return t


def delete_task(task_id: str) -> bool:
    return TASKS.pop(task_id, None) is not None


def export_task_report(task_id: str, fmt: str = "json") -> Optional[Dict[str, Any]]:
    t = TASKS.get(task_id)
    if not t:
        return None
    content = (
        f"# 任务报告\n\n任务ID: {t['task_id']}\n场景: {t['scenario_name']}\n"
        f"目标: {t['target']}\n状态: {t['status']}\n\n"
        f"## 结果\n\n{t['result']}\n"
    )
    return {"task_id": task_id, "format": fmt,
            "filename": f"{task_id}_report.{fmt}",
            "content": content, "size_bytes": len(content.encode("utf-8"))}


def share_task_report(task_id: str) -> Optional[Dict[str, Any]]:
    t = TASKS.get(task_id)
    if not t:
        return None
    token = new_id("share")
    return {"task_id": task_id, "share_token": token,
            "share_url": f"/shared/report/{token}", "expires_in_hours": 72}


def task_summary(task_id: str) -> Optional[Dict[str, Any]]:
    t = TASKS.get(task_id)
    if not t:
        return None
    return {"task_id": task_id, "status": t["status"], "progress": t["progress"],
            "steps": t["steps"], "result": t["result"], "logs": t["logs"][-50:]}
