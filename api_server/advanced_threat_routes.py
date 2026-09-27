# -*- coding: utf-8 -*-
"""
advanced_threat_routes.py — 高级威胁检测与响应 REST API（第25轮升级方向1）。

路由前缀：/api/v1/advanced-threat
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500 错误。
任务/会话用内存字典模拟异步。
本模块仅用于授权的安全评估与运营场景。
"""
from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from advanced_threat.ueba_engine import ueba_engine
    from advanced_threat.ml_anomaly import ml_anomaly
    from advanced_threat.apt_detection import apt_detector
    from advanced_threat.attack_chain import attack_chain_analyzer
    from advanced_threat.threat_hunt import threat_hunt_platform
    from advanced_threat.advanced_threat_dashboard import advanced_threat_dashboard
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("advanced_threat_routes").warning("模块导入失败: %s", _e)
    ueba_engine = None  # type: ignore
    ml_anomaly = None  # type: ignore
    apt_detector = None  # type: ignore
    attack_chain_analyzer = None  # type: ignore
    threat_hunt_platform = None  # type: ignore
    advanced_threat_dashboard = None  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/advanced-threat", tags=["高级威胁检测与响应"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符，避免 JSON 序列化异常"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


def _check() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("advanced_threat 模块未正确加载")
    return None


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    return tid


# ==================== 请求模型 ====================

class DeviationReq(BaseModel):
    user_id: str
    login_hour: int = 10
    location: str = ""
    device: str = ""
    login_count_today: int = 1
    data_access_mb: float = 0
    weekday: str = "Monday"


class EntityDetectReq(BaseModel):
    entity_id: str
    metrics: Dict[str, float] = Field(default_factory=dict)


class TTPMatchReq(BaseModel):
    ttps: List[str] = Field(default_factory=list)


class ChainDetectReq(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


class C2DetectReq(BaseModel):
    domain: str
    ip: str


class ExfilDetectReq(BaseModel):
    source_user: str
    volume_mb: float
    protocol: str = "HTTPS"
    destination: str = ""


class HuntReq(BaseModel):
    hunt_type: str = "hypothesis"
    query: str = ""
    time_range_h: int = 24


class WorkflowReq(BaseModel):
    hypothesis: str
    template_id: Optional[str] = None
    time_range_h: int = 48


class TemplateReq(BaseModel):
    name: str
    description: str = ""
    query: str
    query_type: str = "sql"
    industry: str = "通用"


class InferReq(BaseModel):
    model_id: str
    features: List[float] = Field(default_factory=lambda: [1.0] * 8)


class TrainReq(BaseModel):
    algorithm_id: str
    custom_params: Dict[str, Any] = Field(default_factory=dict)
    n_samples: int = 500


class ABTestReq(BaseModel):
    model_a: str
    model_b: str


class IOCReq(BaseModel):
    iocs: List[str] = Field(default_factory=list)


class SettingsUpdateReq(BaseModel):
    updates: Dict[str, Any] = Field(default_factory=dict)


class AlertRespondReq(BaseModel):
    action: str = "closed"
    assignee: Optional[str] = None


# ============================================================
# 1. UEBA 端点 (11)
# ============================================================

@router.get("/ueba/overview")
def ueba_overview():
    """UEBA 总览"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.overview())
    except Exception as e:
        return _fail(e)


@router.get("/ueba/users")
def ueba_users(department: Optional[str] = Query(None), risk_level: Optional[str] = Query(None)):
    """用户列表"""
    r = _check()
    if r:
        return r
    try:
        users = ueba_engine.users
        if department:
            users = [u for u in users if u["department"] == department]
        if risk_level:
            users = [u for u in users if u["risk_level"] == risk_level]
        return _ok(users)
    except Exception as e:
        return _fail(e)


@router.get("/ueba/users/{user_id}")
def ueba_user_detail(user_id: str):
    """用户详情"""
    r = _check()
    if r:
        return r
    try:
        u = next((x for x in ueba_engine.users if x["user_id"] == user_id), None)
        if not u:
            return _fail(f"用户 {user_id} 不存在")
        return _ok(u)
    except Exception as e:
        return _fail(e)


@router.get("/ueba/users/{user_id}/risk")
def ueba_user_risk(user_id: str):
    """用户风险评分"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.compute_user_risk(user_id))
    except Exception as e:
        return _fail(e)


@router.post("/ueba/detect-deviation")
def ueba_detect_deviation(req: DeviationReq):
    """行为偏离检测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.detect_deviation(req.user_id, req.model_dump(exclude_unset=True)))
    except Exception as e:
        return _fail(e)


@router.get("/ueba/entities")
def ueba_entities(entity_type: Optional[str] = Query(None)):
    """实体列表"""
    r = _check()
    if r:
        return r
    try:
        entities = ueba_engine.entities
        if entity_type:
            entities = [e for e in entities if e["type"] == entity_type]
        return _ok(entities)
    except Exception as e:
        return _fail(e)


@router.post("/ueba/entities/{entity_id}/detect")
def ueba_entity_detect(entity_id: str, req: EntityDetectReq):
    """实体行为偏离检测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.detect_entity_deviation(entity_id, req.metrics))
    except Exception as e:
        return _fail(e)


@router.get("/ueba/peer-groups")
def ueba_peer_groups(department: Optional[str] = Query(None), role: Optional[str] = Query(None)):
    """同行群体分析"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.peer_group_analysis(department, role))
    except Exception as e:
        return _fail(e)


@router.get("/ueba/alerts")
def ueba_alerts(severity: Optional[str] = Query(None), status: Optional[str] = Query(None)):
    """UEBA 告警列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.list_alerts(severity, status))
    except Exception as e:
        return _fail(e)


@router.post("/ueba/alerts/{alert_id}/respond")
def ueba_respond_alert(alert_id: str, req: AlertRespondReq):
    """响应 UEBA 告警"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ueba_engine.respond_alert(alert_id, req.action, req.assignee))
    except Exception as e:
        return _fail(e)


@router.post("/ueba/ml-detect")
def ueba_ml_detect(user_id: str = Query(...), features: str = Query("1.0,2.0,3.0,4.0,5.0")):
    """UEBA ML 异常检测"""
    r = _check()
    if r:
        return r
    try:
        feat_list = [float(x) for x in features.split(",")]
        return _ok(ueba_engine.ml_detect(user_id, feat_list))
    except Exception as e:
        return _fail(e)


# ============================================================
# 2. ML 异常检测端点 (11)
# ============================================================

@router.get("/ml/overview")
def ml_overview():
    """ML 异常检测总览"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.overview())
    except Exception as e:
        return _fail(e)


@router.get("/ml/algorithms")
def ml_algorithms():
    """可用算法列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.algorithms)
    except Exception as e:
        return _fail(e)


@router.get("/ml/models")
def ml_models():
    """模型列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(list(ml_anomaly.models.values()))
    except Exception as e:
        return _fail(e)


@router.get("/ml/models/{model_id}")
def ml_model_detail(model_id: str):
    """模型详情"""
    r = _check()
    if r:
        return r
    try:
        m = ml_anomaly.models.get(model_id)
        if not m:
            return _fail(f"模型 {model_id} 不存在")
        return _ok(m)
    except Exception as e:
        return _fail(e)


@router.post("/ml/train")
def ml_train(req: TrainReq):
    """训练新模型"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.train_model(req.algorithm_id, req.custom_params, req.n_samples))
    except Exception as e:
        return _fail(e)


@router.post("/ml/infer")
def ml_infer(req: InferReq):
    """实时推理"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.infer(req.model_id, req.features))
    except Exception as e:
        return _fail(e)


@router.post("/ml/infer-batch")
def ml_infer_batch(model_id: str = Query(...), batch_size: int = Query(10)):
    """批量推理"""
    r = _check()
    if r:
        return r
    try:
        import random
        batch = [[random.gauss(0, 1) for _ in range(8)] for _ in range(batch_size)]
        return _ok(ml_anomaly.infer_batch(model_id, batch))
    except Exception as e:
        return _fail(e)


@router.get("/ml/anomalies")
def ml_anomalies_list(anomaly_type: Optional[str] = Query(None), limit: int = 50):
    """异常事件列表"""
    r = _check()
    if r:
        return r
    try:
        result = ml_anomaly.anomalies
        if anomaly_type:
            result = [a for a in result if a["type"] == anomaly_type]
        return _ok(list(reversed(result))[:limit])
    except Exception as e:
        return _fail(e)


@router.get("/ml/anomalies/{anomaly_id}/explain")
def ml_explain_anomaly(anomaly_id: str):
    """异常解释"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.explain_anomaly(anomaly_id))
    except Exception as e:
        return _fail(e)


@router.get("/ml/drift/{model_id}")
def ml_check_drift(model_id: str):
    """模型漂移检测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.check_drift(model_id))
    except Exception as e:
        return _fail(e)


@router.post("/ml/ab-test")
def ml_ab_test(req: ABTestReq):
    """模型 A/B 测试"""
    r = _check()
    if r:
        return r
    try:
        return _ok(ml_anomaly.model_ab_test(req.model_a, req.model_b))
    except Exception as e:
        return _fail(e)


# ============================================================
# 3. APT 检测端点 (12)
# ============================================================

@router.get("/apt/overview")
def apt_overview():
    """APT 检测总览"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.overview())
    except Exception as e:
        return _fail(e)


@router.get("/apt/tactics")
def apt_tactics():
    """ATT&CK 战术列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.tactics)
    except Exception as e:
        return _fail(e)


@router.get("/apt/tactics/{tactic_id}/detect")
def apt_detect_tactic(tactic_id: str):
    """战术检测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.detect_tactic(tactic_id))
    except Exception as e:
        return _fail(e)


@router.get("/apt/techniques")
def apt_techniques(tactic_id: Optional[str] = Query(None)):
    """ATT&CK 技术列表"""
    r = _check()
    if r:
        return r
    try:
        techs = apt_detector.techniques
        if tactic_id:
            techs = [t for t in techs if t["tactic_id"] == tactic_id]
        return _ok(techs)
    except Exception as e:
        return _fail(e)


@router.get("/apt/techniques/{technique_id}")
def apt_technique_detail(technique_id: str):
    """技术详情"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.detect_technique(technique_id))
    except Exception as e:
        return _fail(e)


@router.post("/apt/match-ttp")
def apt_match_ttp(req: TTPMatchReq):
    """TTP 画像匹配"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.match_ttp_profile(req.ttps))
    except Exception as e:
        return _fail(e)


@router.post("/apt/analyze-chain")
def apt_analyze_chain(req: ChainDetectReq):
    """行为链分析"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.analyze_behavior_chain(req.events))
    except Exception as e:
        return _fail(e)


@router.post("/apt/detect-c2")
def apt_detect_c2(req: C2DetectReq):
    """C2 基础设施检测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.detect_c2(req.domain, req.ip))
    except Exception as e:
        return _fail(e)


@router.post("/apt/detect-exfiltration")
def apt_detect_exfiltration(req: ExfilDetectReq):
    """数据渗出检测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.detect_exfiltration(req.source_user, req.volume_mb, req.protocol, req.destination))
    except Exception as e:
        return _fail(e)


@router.post("/apt/run-hunt")
def apt_run_hunt(req: HuntReq):
    """APT 威胁狩猎"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.run_hunt(req.hunt_type, req.query, req.time_range_h))
    except Exception as e:
        return _fail(e)


@router.get("/apt/c2-infrastructure")
def apt_c2_list():
    """C2 基础设施列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.c2_infrastructure)
    except Exception as e:
        return _fail(e)


@router.get("/apt/exfiltration-events")
def apt_exfil_list():
    """数据渗出事件列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(apt_detector.exfiltration_events)
    except Exception as e:
        return _fail(e)


# ============================================================
# 4. 攻击链端点 (9)
# ============================================================

@router.get("/chain/overview")
def chain_overview():
    """攻击链总览"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.overview())
    except Exception as e:
        return _fail(e)


@router.get("/chain/list")
def chain_list(severity: Optional[str] = Query(None), status: Optional[str] = Query(None)):
    """攻击链列表"""
    r = _check()
    if r:
        return r
    try:
        chains = attack_chain_analyzer.detected_chains
        if severity:
            chains = [c for c in chains if c.get("severity") == severity]
        if status:
            chains = [c for c in chains if c.get("status") == status]
        return _ok(chains)
    except Exception as e:
        return _fail(e)


@router.get("/chain/{chain_id}")
def chain_detail(chain_id: str):
    """攻击链详情"""
    r = _check()
    if r:
        return r
    try:
        c = next((x for x in attack_chain_analyzer.detected_chains if x["chain_id"] == chain_id), None)
        if not c:
            return _fail(f"攻击链 {chain_id} 不存在")
        return _ok(c)
    except Exception as e:
        return _fail(e)


@router.get("/chain/{chain_id}/reconstruct")
def chain_reconstruct(chain_id: str):
    """攻击链重建"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.reconstruct(chain_id))
    except Exception as e:
        return _fail(e)


@router.get("/chain/{chain_id}/analyze")
def chain_analyze(chain_id: str):
    """攻击链分析"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.analyze_chain(chain_id))
    except Exception as e:
        return _fail(e)


@router.get("/chain/{chain_id}/predict")
def chain_predict(chain_id: str):
    """攻击链预测"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.predict_next(chain_id))
    except Exception as e:
        return _fail(e)


@router.get("/chain/{chain_id}/visualize")
def chain_visualize(chain_id: str):
    """攻击链可视化数据"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.visualization_data(chain_id))
    except Exception as e:
        return _fail(e)


@router.get("/chain/knowledge-base")
def chain_knowledge_base():
    """攻击链知识库"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.get_knowledge_base())
    except Exception as e:
        return _fail(e)


@router.post("/chain/detect")
def chain_detect(req: ChainDetectReq):
    """从事件检测攻击链"""
    r = _check()
    if r:
        return r
    try:
        return _ok(attack_chain_analyzer.detect_chain(req.events))
    except Exception as e:
        return _fail(e)


# ============================================================
# 5. 威胁狩猎端点 (9)
# ============================================================

@router.get("/hunt/overview")
def hunt_overview():
    """威胁狩猎总览"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.overview())
    except Exception as e:
        return _fail(e)


@router.post("/hunt/query")
def hunt_query(query: str = Query(...), query_type: str = Query("sql"),
               time_range_h: int = Query(24), limit: int = Query(100)):
    """执行狩猎查询"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.execute_query(query, query_type, time_range_h, limit))
    except Exception as e:
        return _fail(e)


@router.get("/hunt/templates")
def hunt_templates(industry: Optional[str] = Query(None), tactic: Optional[str] = Query(None)):
    """狩猎模板列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.list_templates(industry, tactic))
    except Exception as e:
        return _fail(e)


@router.post("/hunt/templates")
def hunt_create_template(req: TemplateReq):
    """创建狩猎模板"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.create_template(req.name, req.description, req.query, req.query_type, req.industry))
    except Exception as e:
        return _fail(e)


@router.post("/hunt/workflow")
def hunt_workflow(req: WorkflowReq):
    """执行狩猎工作流"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.run_hunt_workflow(req.hypothesis, req.template_id, req.time_range_h))
    except Exception as e:
        return _fail(e)


@router.get("/hunt/sessions")
def hunt_sessions(limit: int = 20):
    """狩猎会话列表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(list(reversed(threat_hunt_platform.hunt_sessions))[:limit])
    except Exception as e:
        return _fail(e)


@router.get("/hunt/metrics")
def hunt_metrics():
    """狩猎度量"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.get_metrics())
    except Exception as e:
        return _fail(e)


@router.get("/hunt/knowledge-base")
def hunt_knowledge_base():
    """狩猎知识库"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.knowledge_base)
    except Exception as e:
        return _fail(e)


@router.post("/hunt/ioc-match")
def hunt_ioc_match(req: IOCReq):
    """IOC 匹配"""
    r = _check()
    if r:
        return r
    try:
        return _ok(threat_hunt_platform.ioc_match(req.iocs))
    except Exception as e:
        return _fail(e)


# ============================================================
# 6. 控制台与系统设置端点 (10)
# ============================================================

@router.get("/dashboard/overview")
def dash_overview():
    """控制台威胁总览"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.threat_overview())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/ueba")
def dash_ueba():
    """UEBA 管理面板"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.ueba_view())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/ml")
def dash_ml():
    """ML 管理面板"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.ml_view())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/apt")
def dash_apt():
    """APT 检测面板"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.apt_view())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/chain")
def dash_chain():
    """攻击链管理面板"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.chain_view())
    except Exception as e:
        return _fail(e)


@router.get("/dashboard/hunt")
def dash_hunt():
    """狩猎管理面板"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.hunt_view())
    except Exception as e:
        return _fail(e)


@router.get("/settings")
def get_settings():
    """获取系统设置"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.get_settings())
    except Exception as e:
        return _fail(e)


@router.put("/settings/{section}")
def update_settings(section: str, req: SettingsUpdateReq):
    """更新系统设置"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.update_settings(section, req.updates))
    except Exception as e:
        return _fail(e)


@router.get("/audit-logs")
def audit_logs(limit: int = 50):
    """审计日志"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.list_audit_logs(limit))
    except Exception as e:
        return _fail(e)


@router.get("/report")
def generate_report():
    """生成综合报表"""
    r = _check()
    if r:
        return r
    try:
        return _ok(advanced_threat_dashboard.generate_report())
    except Exception as e:
        return _fail(e)
