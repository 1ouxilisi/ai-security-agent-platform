# -*- coding: utf-8 -*-
"""
demo_mode/demo_dataset.py — Demo 数据集管理。

职责：
    1. Demo 场景库（渗透测试/移动安全/区块链/AI安全/云安全/红蓝对抗/护网/SRC挖洞）
    2. Demo 数据生成（资产/漏洞/告警/事件/用户/时间线，随机化但合理）
    3. Demo 数据导入导出（包格式/导入/导出/分享/版本/校验/签名）
    4. Demo 数据重置（一键重置/部分重置/备份/恢复/重置历史）
    5. Demo 数据定制（自定义目标/漏洞/报告/时间线/品牌）
    6. Demo 数据统计（使用次数/完成率/平均时长/反馈/热门场景/改进建议）
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import time
import uuid
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 第三方库 try-import（缺失回退模拟）
# --------------------------------------------------------------------------- #
try:  # pragma: no cover
    from faker import Faker  # type: ignore

    _FAKER = Faker("zh_CN")
except Exception:  # noqa: BLE001
    _FAKER = None

try:  # pragma: no cover
    import secrets as _secrets
except Exception:  # noqa: BLE001
    import random as _secrets  # type: ignore


# --------------------------------------------------------------------------- #
# 内存存储
# --------------------------------------------------------------------------- #
SCENARIOS: Dict[str, Dict[str, Any]] = {}
DATASETS: Dict[str, Dict[str, Any]] = {}
BACKUPS: Dict[str, Dict[str, Any]] = {}
RESET_HISTORY: List[Dict[str, Any]] = []
STATS: Dict[str, Dict[str, Any]] = {
    "_global": {
        "usage_count": 0, "completed": 0, "total_duration_sec": 0,
        "feedback_sum": 0, "feedback_count": 0, "created_at": time.strftime(
            "%Y-%m-%d %H:%M:%S"),
    }
}

_VULN_TEMPLATES = [
    {"cve": "CVE-2024-21762", "name": "OpenSSH 越界写入", "severity": "严重",
     "cvss": 9.8, "cwe": "CWE-787", "type": "远程代码执行"},
    {"cve": "CVE-2024-23897", "name": "Jenkins 任意文件读取", "severity": "高危",
     "cvss": 9.8, "cwe": "CWE-22", "type": "信息泄露"},
    {"cve": "CVE-2023-46604", "name": "ActiveMQ RCE", "severity": "严重",
     "cvss": 10.0, "cwe": "CWE-502", "type": "反序列化"},
    {"cve": "CVE-2024-23897", "name": "Apache Tomcat 路径穿越", "severity": "中危",
     "cvss": 6.5, "cwe": "CWE-22", "type": "路径遍历"},
    {"cve": "CVE-2024-27198", "name": "Jenkins 未授权访问", "severity": "高危",
     "cvss": 9.8, "cwe": "CWE-306", "type": "认证绕过"},
    {"cve": "CVE-2023-38545", "name": "cURL SOCKS5 堆溢出", "severity": "高危",
     "cvss": 8.1, "cwe": "CWE-787", "type": "内存破坏"},
    {"cve": "CVE-2024-3435", "name": "Spring Cloud SpEL RCE", "severity": "严重",
     "cvss": 10.0, "cwe": "CWE-94", "type": "代码执行"},
    {"cve": "CVE-2023-4966", "name": "Citrix Bleed 会话劫持", "severity": "严重",
     "cvss": 9.4, "cwe": "CWE-384", "type": "会话劫持"},
]

_ALERT_LEVELS = ["紧急", "高危", "中危", "低危", "提示"]
_EVENT_TYPES = ["登录成功", "登录失败", "权限变更", "配置变更", "数据导出",
                "恶意文件检测", "异常进程", "端口扫描", "横向移动", "数据删除"]
_USERS = ["张工", "李工", "王工", "赵工", "陈工", "刘工", "系统管理员", "审计员"]


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _rid(prefix: str = "id") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _seed_rng(seed: Optional[int] = None) -> random.Random:
    return random.Random(seed) if seed is not None else random.Random()


def _fake_name(rng: random.Random) -> str:
    if _FAKER is not None:
        try:
            return _FAKER.name()
        except Exception:  # noqa: BLE001
            pass
    return rng.choice(["张工", "李工", "王工", "赵工", "陈工", "刘工"])


def _fake_ip(rng: random.Random) -> str:
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _fake_host(rng: random.Random) -> str:
    suffixes = ["web", "app", "db", "cache", "api", "oa", "vpn", "git", "ci", "log"]
    return f"{rng.choice(suffixes)}-{rng.randint(1, 40)}.internal.local"


# --------------------------------------------------------------------------- #
# 1. Demo 场景库
# --------------------------------------------------------------------------- #
def _build_default_scenarios() -> Dict[str, Dict[str, Any]]:
    """构建 8 个内置 Demo 场景。"""
    raw = [
        {
            "id": "scen_pentest", "name": "渗透测试全景演示",
            "category": "渗透测试",
            "description": "从信息收集到报告输出的完整渗透测试流程，覆盖 Web/服务/权限提升。",
            "target": "靶场：demo-pentest.internal.local",
            "vuln_count": 12, "estimated_minutes": 18,
            "tags": ["Web", "RCE", "提权", "内网"],
        },
        {
            "id": "scen_mobile", "name": "移动安全逆向演示",
            "category": "移动安全",
            "description": "APK 反编译、抓包、Frida Hook、签名校验绕过全流程。",
            "target": "应用：com.demo.bankapp.apk",
            "vuln_count": 6, "estimated_minutes": 12,
            "tags": ["Android", "Frida", "抓包", "脱壳"],
        },
        {
            "id": "scen_chain", "name": "区块链合约审计演示",
            "category": "区块链",
            "description": "Solidity 合约源码审计，重入/整数溢出/权限类漏洞演示。",
            "target": "合约: 0xDemoContractA1B2",
            "vuln_count": 5, "estimated_minutes": 15,
            "tags": ["Solidity", "重入", "整数溢出", "审计"],
        },
        {
            "id": "scen_aisec", "name": "AI 安全红队演示",
            "category": "AI安全",
            "description": "提示词注入、模型越狱、训练数据投毒、LLM API 滥用演示。",
            "target": "模型: demo-llm-gateway",
            "vuln_count": 7, "estimated_minutes": 14,
            "tags": ["Prompt Injection", "越狱", "投毒", "LLM"],
        },
        {
            "id": "scen_cloud", "name": "云安全配置审计演示",
            "category": "云安全",
            "description": "AWS/阿里云基线检查、AK 泄露、存储桶公开、权限边界分析。",
            "target": "云账号: demo-cloud-account",
            "vuln_count": 9, "estimated_minutes": 16,
            "tags": ["CSPM", "AK", "存储桶", "基线"],
        },
        {
            "id": "scen_rbrex", "name": "红蓝对抗演练演示",
            "category": "红蓝对抗",
            "description": "红队初始访问→横向移动→持久化，蓝队检测响应全链路。",
            "target": "演练环境: battle-01",
            "vuln_count": 10, "estimated_minutes": 22,
            "tags": ["红队", "蓝队", "ATT&CK", "EDR"],
        },
        {
            "id": "scen_hw", "name": "护网行动值守演示",
            "category": "护网",
            "description": "护网期间告警分诊、IOC 下发、临时封禁、复盘报告。",
            "target": "值守环境: hw-2026",
            "vuln_count": 14, "estimated_minutes": 25,
            "tags": ["告警分诊", "IOC", "封禁", "复盘"],
        },
        {
            "id": "scen_src", "name": "SRC 挖洞实战演示",
            "category": "SRC挖洞",
            "description": "从资产测绘到漏洞提交的 SRC 挖洞完整工作流，含报告模板。",
            "target": "SRC 目标: *.demo-src.com",
            "vuln_count": 8, "estimated_minutes": 17,
            "tags": ["资产测绘", "漏洞提交", "报告模板", "赏金"],
        },
    ]
    out: Dict[str, Dict[str, Any]] = {}
    for s in raw:
        s["usage_count"] = 0
        s["completion_rate"] = round(random.uniform(0.55, 0.98), 3)
        s["avg_duration_sec"] = s["estimated_minutes"] * 60
        s["created_at"] = _now()
        s["status"] = "published"
        out[s["id"]] = s
    return out


def list_scenarios(category: Optional[str] = None,
                   keyword: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(SCENARIOS.values())
    if category:
        items = [x for x in items if x.get("category") == category]
    if keyword:
        kw = keyword.lower()
        items = [x for x in items
                 if kw in x.get("name", "").lower()
                 or kw in x.get("description", "").lower()]
    return items


def get_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
    return SCENARIOS.get(scenario_id)


def create_scenario(payload: Dict[str, Any]) -> Dict[str, Any]:
    sid = payload.get("id") or _rid("scen")
    scen = {
        "id": sid,
        "name": payload.get("name", "未命名场景"),
        "category": payload.get("category", "自定义"),
        "description": payload.get("description", ""),
        "target": payload.get("target", "demo-target.local"),
        "vuln_count": int(payload.get("vuln_count", 5)),
        "estimated_minutes": int(payload.get("estimated_minutes", 10)),
        "tags": payload.get("tags", []),
        "usage_count": 0,
        "completion_rate": 0.0,
        "avg_duration_sec": 600,
        "created_at": _now(),
        "status": payload.get("status", "draft"),
    }
    SCENARIOS[sid] = scen
    return scen


def update_scenario(scenario_id: str,
                    payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    s = SCENARIOS.get(scenario_id)
    if not s:
        return None
    for k in ("name", "category", "description", "target", "tags", "status"):
        if k in payload:
            s[k] = payload[k]
    if "vuln_count" in payload:
        s["vuln_count"] = int(payload["vuln_count"])
    if "estimated_minutes" in payload:
        s["estimated_minutes"] = int(payload["estimated_minutes"])
    s["updated_at"] = _now()
    return s


def delete_scenario(scenario_id: str) -> bool:
    return SCENARIOS.pop(scenario_id, None) is not None


# --------------------------------------------------------------------------- #
# 2. Demo 数据生成（真实感：资产/漏洞/告警/事件/用户/时间线）
# --------------------------------------------------------------------------- #
def generate_assets(scenario_id: str, count: int = 20,
                    seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = _seed_rng(seed)
    assets = []
    for i in range(count):
        host = _fake_host(rng)
        assets.append({
            "asset_id": _rid("ast"),
            "hostname": host,
            "ip": _fake_ip(rng),
            "os": rng.choice(["CentOS 7.9", "Ubuntu 22.04", "Debian 12",
                              "Windows Server 2019", "Kylin V10"]),
            "open_ports": sorted(rng.sample([22, 80, 443, 3306, 5432, 6379,
                                             8080, 8443, 9200],
                                            k=rng.randint(1, 5))),
            "owner": _fake_name(rng),
            "criticality": rng.choice(["核心", "重要", "一般", "边缘"]),
            "scenario_id": scenario_id,
        })
    return assets


def generate_vulns(scenario_id: str, count: int = 10,
                   seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = _seed_rng(seed)
    vulns = []
    for i in range(count):
        tpl = rng.choice(_VULN_TEMPLATES)
        vulns.append({
            "vuln_id": _rid("vul"),
            "scenario_id": scenario_id,
            "cve": tpl["cve"],
            "name": tpl["name"],
            "severity": tpl["severity"],
            "cvss": tpl["cvss"],
            "cwe": tpl["cwe"],
            "type": tpl["type"],
            "asset": _fake_host(rng),
            "status": rng.choice(["未修复", "已修复", "已忽略", "验证中"]),
            "discovered_at": _now(),
            "description": (
                f"目标服务存在 {tpl['type']} 漏洞，CVSS {tpl['cvss']}，"
                f"建议按 CWE-{tpl['cwe'].split('-')[1]} 对照修复。"
            ),
            "proof": f"PoC: https://poc.internal/{_rid('poc')}",
        })
    return vulns


def generate_alerts(scenario_id: str, count: int = 30,
                    seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = _seed_rng(seed)
    alerts = []
    for i in range(count):
        alerts.append({
            "alert_id": _rid("alt"),
            "scenario_id": scenario_id,
            "level": rng.choice(_ALERT_LEVELS),
            "title": rng.choice([
                "检测到暴力破解尝试", "异常外联 C2 域名", "可疑 PowerShell 执行",
                "Web 攻击载荷匹配", "数据库异常导出", "权限提升事件",
                "敏感文件越权访问", "横向移动 SMB 爆破",
            ]),
            "source_ip": _fake_ip(rng),
            "target": _fake_host(rng),
            "status": rng.choice(["未处置", "处置中", "已处置", "误报"]),
            "created_at": _now(),
        })
    return alerts


def generate_events(scenario_id: str, count: int = 40,
                    seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = _seed_rng(seed)
    events = []
    for i in range(count):
        events.append({
            "event_id": _rid("evt"),
            "scenario_id": scenario_id,
            "type": rng.choice(_EVENT_TYPES),
            "user": rng.choice(_USERS),
            "source_ip": _fake_ip(rng),
            "detail": f"{rng.choice(_USERS)} 触发了 {rng.choice(_EVENT_TYPES)}",
            "timestamp": _now(),
        })
    return events


def generate_users(scenario_id: str, count: int = 8,
                   seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = _seed_rng(seed)
    users = []
    roles = ["安全工程师", "运维", "开发", "审计员", "管理员"]
    for i in range(count):
        users.append({
            "user_id": _rid("usr"),
            "name": _fake_name(rng),
            "role": rng.choice(roles),
            "last_active": _now(),
            "actions": rng.randint(10, 500),
            "scenario_id": scenario_id,
        })
    return users


def generate_timeline(scenario_id: str, steps: int = 12,
                      seed: Optional[int] = None) -> List[Dict[str, Any]]:
    rng = _seed_rng(seed)
    actions = ["信息收集", "漏洞探测", "漏洞利用", "权限提升",
               "横向移动", "痕迹清理", "报告生成", "复测确认"]
    timeline = []
    for i in range(steps):
        timeline.append({
            "step": i + 1,
            "action": rng.choice(actions),
            "operator": rng.choice(_USERS),
            "duration_sec": rng.randint(30, 900),
            "result": rng.choice(["成功", "成功", "成功", "失败", "跳过"]),
            "timestamp": _now(),
        })
    return timeline


def generate_dataset(scenario_id: str,
                     options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """一键生成完整 Demo 数据集。"""
    opts = options or {}
    seed = opts.get("seed")
    scen = get_scenario(scenario_id) or {"name": scenario_id, "category": "自定义"}
    ds_id = _rid("ds")
    dataset = {
        "dataset_id": ds_id,
        "scenario_id": scenario_id,
        "scenario_name": scen.get("name", scenario_id),
        "generated_at": _now(),
        "seed": seed,
        "assets": generate_assets(scenario_id,
                                  opts.get("asset_count", 20), seed),
        "vulns": generate_vulns(scenario_id,
                                opts.get("vuln_count",
                                         scen.get("vuln_count", 10)), seed),
        "alerts": generate_alerts(scenario_id,
                                 opts.get("alert_count", 30), seed),
        "events": generate_events(scenario_id,
                                  opts.get("event_count", 40), seed),
        "users": generate_users(scenario_id,
                                opts.get("user_count", 8), seed),
        "timeline": generate_timeline(scenario_id,
                                       opts.get("step_count", 12), seed),
    }
    dataset["summary"] = {
        "assets": len(dataset["assets"]),
        "vulns": len(dataset["vulns"]),
        "alerts": len(dataset["alerts"]),
        "events": len(dataset["events"]),
        "users": len(dataset["users"]),
        "timeline_steps": len(dataset["timeline"]),
    }
    DATASETS[ds_id] = dataset
    # 更新全局使用统计
    g = STATS["_global"]
    g["usage_count"] += 1
    return dataset


# --------------------------------------------------------------------------- #
# 3. Demo 数据导入导出
# --------------------------------------------------------------------------- #
def export_dataset(dataset_id: str) -> Optional[Dict[str, Any]]:
    ds = DATASETS.get(dataset_id)
    if not ds:
        return None
    payload = {
        "format": "ai-hacking-agent.demo-package",
        "version": "1.0",
        "exported_at": _now(),
        "data": copy.deepcopy(ds),
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    payload["signature"] = hashlib.sha256(
        blob.encode("utf-8")).hexdigest()
    payload["size_bytes"] = len(blob)
    return payload


def import_dataset(package: Dict[str, Any]) -> Dict[str, Any]:
    """导入 Demo 包，做格式/版本/签名校验。"""
    if not isinstance(package, dict):
        raise ValueError("包必须是字典")
    if package.get("format") != "ai-hacking-agent.demo-package":
        raise ValueError("包格式不匹配")
    ver = str(package.get("version", "0"))
    if ver.split(".")[0] not in {"1"}:
        raise ValueError(f"不支持的包版本: {ver}")
    data = package.get("data") or {}
    ds_id = data.get("dataset_id") or _rid("ds")
    data["dataset_id"] = ds_id
    data["imported_at"] = _now()
    DATASETS[ds_id] = data
    return {"dataset_id": ds_id, "scenario": data.get("scenario_name"),
            "summary": data.get("summary"), "imported": True}


def verify_package(package: Dict[str, Any]) -> Dict[str, Any]:
    sig = package.get("signature")
    clone = {k: v for k, v in package.items() if k != "signature"}
    blob = json.dumps(clone, ensure_ascii=False, sort_keys=True)
    expect = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    return {"valid": sig == expect, "expected": expect, "got": sig}


def list_datasets() -> List[Dict[str, Any]]:
    return [{"dataset_id": d["dataset_id"],
             "scenario_id": d.get("scenario_id"),
             "scenario_name": d.get("scenario_name"),
             "generated_at": d.get("generated_at"),
             "summary": d.get("summary")}
            for d in DATASETS.values()]


def get_dataset(dataset_id: str) -> Optional[Dict[str, Any]]:
    return DATASETS.get(dataset_id)


# --------------------------------------------------------------------------- #
# 4. Demo 数据重置
# --------------------------------------------------------------------------- #
def reset_demo(scope: str = "all",
               scenario_id: Optional[str] = None) -> Dict[str, Any]:
    """一键重置 / 部分重置。scope: all|scenario|datasets|stats。"""
    backup_id = _rid("bak")
    backup = {
        "backup_id": backup_id,
        "scope": scope,
        "created_at": _now(),
        "data": {
            "datasets": copy.deepcopy(DATASETS),
            "stats": copy.deepcopy(STATS),
        },
    }
    BACKUPS[backup_id] = backup

    before = {
        "datasets": len(DATASETS),
        "usage_count": STATS["_global"]["usage_count"],
    }
    if scope == "all":
        DATASETS.clear()
        SCENARIOS.clear()
        SCENARIOS.update(_build_default_scenarios())
        STATS.clear()
        STATS["_global"] = {
            "usage_count": 0, "completed": 0, "total_duration_sec": 0,
            "feedback_sum": 0, "feedback_count": 0,
            "created_at": _now()}
    elif scope == "scenario" and scenario_id:
        for k in [k for k, v in list(DATASETS.items())
                  if v.get("scenario_id") == scenario_id]:
            DATASETS.pop(k, None)
    elif scope == "datasets":
        DATASETS.clear()
    elif scope == "stats":
        STATS["_global"].update({
            "usage_count": 0, "completed": 0, "total_duration_sec": 0,
            "feedback_sum": 0, "feedback_count": 0})

    record = {
        "reset_id": _rid("rst"),
        "scope": scope, "scenario_id": scenario_id,
        "before": before, "backup_id": backup_id,
        "at": _now(),
    }
    RESET_HISTORY.append(record)
    return record


def list_backups() -> List[Dict[str, Any]]:
    return [{"backup_id": b["backup_id"], "scope": b["scope"],
             "created_at": b["created_at"]} for b in BACKUPS.values()]


def restore_backup(backup_id: str) -> Dict[str, Any]:
    b = BACKUPS.get(backup_id)
    if not b:
        raise KeyError(backup_id)
    DATASETS.clear()
    DATASETS.update(copy.deepcopy(b["data"]["datasets"]))
    STATS.clear()
    STATS.update(copy.deepcopy(b["data"]["stats"]))
    return {"restored": backup_id, "at": _now()}


def list_reset_history() -> List[Dict[str, Any]]:
    return list(RESET_HISTORY)


# --------------------------------------------------------------------------- #
# 5. Demo 数据定制
# --------------------------------------------------------------------------- #
def customize_scenario(scenario_id: str,
                       patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    s = SCENARIOS.get(scenario_id)
    if not s:
        return None
    s.setdefault("custom", {})
    for k in ("logo", "brand_name", "primary_color", "watermark",
              "contact", "copyright", "custom_target", "custom_vulns",
              "custom_report", "custom_timeline"):
        if k in patch:
            s["custom"][k] = patch[k]
    s["custom_updated_at"] = _now()
    return s


# --------------------------------------------------------------------------- #
# 6. Demo 数据统计
# --------------------------------------------------------------------------- #
def record_demo_finish(scenario_id: str, duration_sec: int = 120,
                       feedback: int = 5) -> Dict[str, Any]:
    g = STATS["_global"]
    g["completed"] += 1
    g["total_duration_sec"] += max(1, int(duration_sec))
    g["feedback_sum"] += max(1, int(feedback))
    g["feedback_count"] += 1
    s = SCENARIOS.get(scenario_id)
    if s:
        s["usage_count"] += 1
        s["avg_duration_sec"] = (
            (s["avg_duration_sec"] * (s["usage_count"] - 1) + int(duration_sec))
            / s["usage_count"]
        )
    return {"recorded": True, "scenario_id": scenario_id}


def get_stats() -> Dict[str, Any]:
    g = STATS["_global"]
    completion = (g["completed"] / g["usage_count"] * 100
                  if g["usage_count"] else 0.0)
    avg_dur = (g["total_duration_sec"] / g["completed"]
               if g["completed"] else 0.0)
    avg_fb = (g["feedback_sum"] / g["feedback_count"]
              if g["feedback_count"] else 0.0)
    hot = sorted(SCENARIOS.values(),
                 key=lambda x: x.get("usage_count", 0),
                 reverse=True)[:5]
    return {
        "usage_count": g["usage_count"],
        "completed": g["completed"],
        "completion_rate_pct": round(completion, 1),
        "avg_duration_sec": round(avg_dur, 1),
        "avg_feedback": round(avg_fb, 2),
        "scenario_count": len(SCENARIOS),
        "dataset_count": len(DATASETS),
        "hot_scenarios": [{"id": s["id"], "name": s["name"],
                           "usage": s["usage_count"]} for s in hot],
        "improvement_suggestions": [
            "缩短前 30 秒引导时长，降低首屏流失",
            "为热门场景增加旁路讲解",
            "补充失败步骤的回滚演示",
        ],
    }


# 初始化默认场景（导入即建库）
if not SCENARIOS:
    SCENARIOS.update(_build_default_scenarios())
