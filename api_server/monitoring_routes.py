"""监控 API 路由。

提供定时任务、分布式节点、告警、代理池的 REST 接口。
调度器与告警引擎在模块级别以单例初始化，路由函数直接复用。
"""
from typing import Optional, List, Any, Dict

from fastapi import APIRouter, Query
from pydantic import BaseModel

from utils.logger import log
from monitoring.scheduler import get_scheduler
from monitoring.alert_engine import get_alert_engine

router = APIRouter(prefix="/api/monitoring", tags=["监控"])

# 模块级单例
scheduler = get_scheduler()
alert_engine = get_alert_engine()


# --------------------------------------------------------------------------
# 请求模型
# --------------------------------------------------------------------------
class ScheduledTaskCreate(BaseModel):
    name: str
    target: str
    scan_type: str = "port_scan"
    schedule_type: str = "interval"           # cron / interval
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    options: Optional[Dict[str, Any]] = None


class ScheduledTaskUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None
    schedule_type: Optional[str] = None
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    options: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class AckRequest(BaseModel):
    user: str = "system"


def _ok(data: Any = None, message: str = "ok") -> Dict[str, Any]:
    return {"success": True, "message": message, "data": data}


def _err(message: str) -> Dict[str, Any]:
    return {"success": False, "message": message, "data": None}


# --------------------------------------------------------------------------
# 定时任务
# --------------------------------------------------------------------------
@router.get("/scheduled-tasks", summary="列出所有定时任务")
def list_scheduled_tasks(enabled_only: bool = Query(False)):
    try:
        return _ok(scheduler.list_tasks(enabled_only=enabled_only))
    except Exception as e:
        log.error(f"列出定时任务失败: {e}")
        return _err(f"列出定时任务失败: {e}")


@router.post("/scheduled-tasks", summary="创建定时任务")
def create_scheduled_task(req: ScheduledTaskCreate):
    try:
        t = scheduler.add_task(
            name=req.name, target=req.target, scan_type=req.scan_type,
            schedule_type=req.schedule_type,
            cron_expression=req.cron_expression,
            interval_seconds=req.interval_seconds,
            options=req.options,
        )
        return _ok(t.to_dict(), "定时任务已创建")
    except Exception as e:
        log.error(f"创建定时任务失败: {e}")
        return _err(f"创建定时任务失败: {e}")


@router.get("/scheduled-tasks/{task_id}", summary="获取定时任务详情")
def get_scheduled_task(task_id: str):
    try:
        t = scheduler.get_task(task_id)
        if not t:
            return _err("任务不存在")
        return _ok(t)
    except Exception as e:
        log.error(f"获取定时任务失败: {e}")
        return _err(f"获取定时任务失败: {e}")


@router.put("/scheduled-tasks/{task_id}", summary="更新定时任务")
def update_scheduled_task(task_id: str, req: ScheduledTaskUpdate):
    try:
        kwargs = {k: v for k, v in req.model_dump().items() if v is not None}
        if not scheduler.update_task(task_id, **kwargs):
            return _err("任务不存在或更新失败")
        return _ok(scheduler.get_task(task_id), "定时任务已更新")
    except Exception as e:
        log.error(f"更新定时任务失败: {e}")
        return _err(f"更新定时任务失败: {e}")


@router.delete("/scheduled-tasks/{task_id}", summary="删除定时任务")
def delete_scheduled_task(task_id: str):
    try:
        if not scheduler.remove_task(task_id):
            return _err("任务不存在")
        return _ok(None, "定时任务已删除")
    except Exception as e:
        log.error(f"删除定时任务失败: {e}")
        return _err(f"删除定时任务失败: {e}")


@router.post("/scheduled-tasks/{task_id}/run", summary="立即执行一次定时任务")
def run_scheduled_task(task_id: str):
    try:
        if not scheduler.run_task_now(task_id):
            return _err("任务不存在")
        return _ok(None, "已触发执行")
    except Exception as e:
        log.error(f"立即执行定时任务失败: {e}")
        return _err(f"立即执行定时任务失败: {e}")


@router.get("/scheduled-tasks/{task_id}/history", summary="获取任务执行历史")
def scheduled_task_history(task_id: str, limit: int = Query(20, ge=1, le=200)):
    try:
        return _ok(scheduler.get_task_history(task_id, limit=limit))
    except Exception as e:
        log.error(f"获取任务历史失败: {e}")
        return _err(f"获取任务历史失败: {e}")


# --------------------------------------------------------------------------
# 分布式节点
# --------------------------------------------------------------------------
@router.get("/nodes", summary="列出分布式节点状态")
def list_nodes(status: Optional[str] = Query(None)):
    try:
        from distributed.core import distributed_scanner
        nodes = distributed_scanner.node_manager.list_nodes(status=status)
        from dataclasses import asdict
        return _ok([asdict(n) for n in nodes])
    except Exception as e:
        log.error(f"列出节点失败: {e}")
        return _err(f"列出节点失败: {e}")


# --------------------------------------------------------------------------
# 告警
# --------------------------------------------------------------------------
@router.get("/alerts", summary="列出告警")
def list_alerts(status: Optional[str] = Query(None),
                severity: Optional[str] = Query(None),
                limit: int = Query(50, ge=1, le=500)):
    try:
        return _ok(alert_engine.list_alerts(status=status, severity=severity, limit=limit))
    except Exception as e:
        log.error(f"列出告警失败: {e}")
        return _err(f"列出告警失败: {e}")


@router.get("/alerts/{alert_id}", summary="获取告警详情")
def get_alert(alert_id: str):
    try:
        a = alert_engine.get_alert(alert_id)
        if not a:
            return _err("告警不存在")
        return _ok(a)
    except Exception as e:
        log.error(f"获取告警失败: {e}")
        return _err(f"获取告警失败: {e}")


@router.post("/alerts/{alert_id}/acknowledge", summary="确认告警")
def acknowledge_alert(alert_id: str, req: AckRequest):
    try:
        if not alert_engine.acknowledge_alert(alert_id, req.user):
            return _err("告警不存在")
        return _ok(None, "告警已确认")
    except Exception as e:
        log.error(f"确认告警失败: {e}")
        return _err(f"确认告警失败: {e}")


@router.post("/alerts/{alert_id}/close", summary="关闭告警")
def close_alert(alert_id: str, req: AckRequest):
    try:
        if not alert_engine.close_alert(alert_id, req.user):
            return _err("告警不存在")
        return _err(None, "告警已关闭")
    except Exception as e:
        log.error(f"关闭告警失败: {e}")
        return _err(f"关闭告警失败: {e}")


# --------------------------------------------------------------------------
# 代理池
# --------------------------------------------------------------------------
@router.get("/proxy-pool", summary="代理池状态")
def proxy_pool_status():
    try:
        from distributed.core import distributed_scanner
        pool = distributed_scanner.proxy_pool
        stats = pool.get_stats()
        from dataclasses import asdict
        stats["proxies"] = [asdict(p) for p in pool.list_proxies()]
        return _ok(stats)
    except Exception as e:
        log.error(f"获取代理池状态失败: {e}")
        return _err(f"获取代理池状态失败: {e}")


@router.post("/proxy-pool/check", summary="触发代理健康检查")
def proxy_pool_check():
    try:
        from distributed.core import distributed_scanner
        result = distributed_scanner.proxy_pool.health_check_all()
        return _ok(result, "代理健康检查完成")
    except Exception as e:
        log.error(f"代理健康检查失败: {e}")
        return _err(f"代理健康检查失败: {e}")
