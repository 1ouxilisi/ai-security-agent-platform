#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
workflow_routesAPI服务模块，提供相关REST API接口和Web服务功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from workflow.engine import workflow_engine, WorkflowStatus, PhaseStatus
from workflow.definitions import WORKFLOW_TEMPLATES, create_standard_pentest_workflow, create_quick_scan_workflow
from utils.logger import log

router = APIRouter(prefix="/api/v1/workflows", tags=["工作流"])


# ===== 请求模型 =====
class StartWorkflowRequest(BaseModel):
    """启动工作流请求"""
    workflow_id: str = Field(..., description="工作流模板ID: standard_pentest / quick_scan")
    target: str = Field(..., description="目标IP或域名")
    name: Optional[str] = Field(None, description="工作流名称")
    description: Optional[str] = Field("", description="工作流描述")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="配置参数")


class WorkflowResponse(BaseModel):
    """工作流响应"""
    instance_id: str
    status: str
    message: str


# ===== 工具执行器 =====
async def workflow_tool_executor(tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """工作流工具执行器 - 调用已注册的安全工具"""
    from mcp_server.server import TOOL_DEFINITIONS

    tool_def = next((t for t in TOOL_DEFINITIONS if t["name"] == tool_name), None)
    if not tool_def:
        return {"error": f"未知工具: {tool_name}", "status": "failed"}

    try:
        handler = tool_def["handler"]
        result = handler(**parameters)
        if asyncio.iscoroutine(result):
            result = await result
        return result
    except Exception as e:
        log.error(f"工作流工具执行失败 {tool_name}: {str(e)}")
        return {"error": str(e), "status": "failed"}


# ===== AI分析器 =====
_llm_manager = None

def _get_llm_manager():
    """获取LLM管理器实例（懒加载）"""
    global _llm_manager
    if _llm_manager is None:
        try:
            from llm.multi_llm_manager import MultiLLMManager
            _llm_manager = MultiLLMManager()
        except Exception as e:
            log.error(f"LLM管理器初始化失败: {e}")
            _llm_manager = False
    return _llm_manager if _llm_manager is not False else None


async def workflow_ai_analyzer(prompt: str, context: Dict[str, Any]) -> str:
    """工作流AI分析器 - 调用LLM分析阶段结果"""
    try:
        manager = _get_llm_manager()
        if not manager:
            return "AI分析暂时不可用（LLM管理器未初始化），请查看上方的工具执行结果进行手动分析。"

        # 构建上下文消息
        context_str = json.dumps(context, ensure_ascii=False, indent=2, default=str)
        if len(context_str) > 8000:
            context_str = context_str[:8000] + "\n... (内容已截断)"

        messages = [
            {"role": "system", "content": "你是一名资深渗透测试专家，擅长分析安全扫描结果并给出专业建议。请用中文回答，结构清晰，重点突出。"},
            {"role": "user", "content": f"{prompt}\n\n## 上下文数据\n```json\n{context_str}\n```"}
        ]

        # 在事件循环中执行同步的chat方法
        loop = asyncio.get_event_loop()
        content, metadata = await loop.run_in_executor(
            None,
            lambda: manager.chat(messages, task_type="analysis", timeout=120)
        )

        if content:
            return content
        else:
            error_msg = metadata.get("error", "未知错误") if metadata else "无响应"
            return f"AI分析失败: {error_msg}\n\n请查看上方的工具执行结果进行手动分析。"

    except Exception as e:
        log.error(f"工作流AI分析失败: {str(e)}")
        return f"AI分析暂时不可用: {str(e)}\n\n请查看上方的工具执行结果进行手动分析。"


# 初始化工作流引擎的执行器
workflow_engine.tool_executor = workflow_tool_executor
workflow_engine.ai_analyzer = workflow_ai_analyzer


# ===== 后台任务 =====
async def run_workflow_background(instance_id: str):
    """后台执行工作流"""
    try:
        await workflow_engine.execute_workflow(instance_id)
        log.info(f"工作流后台执行完成: {instance_id}")
    except Exception as e:
        log.error(f"工作流后台执行失败: {instance_id}, 错误: {str(e)}")


# ===== API接口 =====

@router.get("/templates")
async def list_workflow_templates():
    """获取可用的工作流模板列表"""
    templates = []
    for wf_id, wf_def in WORKFLOW_TEMPLATES.items():
        templates.append({
            "id": wf_id,
            "name": wf_def["name"],
            "description": wf_def["description"],
            "phases_count": wf_def["phases_count"],
            "estimated_time": wf_def["estimated_time"]
        })
    return {"total": len(templates), "templates": templates}


@router.post("/start")
async def start_workflow(request: StartWorkflowRequest, background_tasks: BackgroundTasks):
    """启动渗透测试工作流"""
    # 验证工作流模板
    if request.workflow_id not in WORKFLOW_TEMPLATES:
        raise HTTPException(400, f"未知工作流模板: {request.workflow_id}，可用: {list(WORKFLOW_TEMPLATES.keys())}")

    # 验证目标
    if not request.target or not request.target.strip():
        raise HTTPException(400, "目标不能为空")

    # 创建工作流阶段
    if request.workflow_id == "standard_pentest":
        phases = create_standard_pentest_workflow(request.target, request.config)
    elif request.workflow_id == "quick_scan":
        phases = create_quick_scan_workflow(request.target)
    else:
        raise HTTPException(400, f"不支持的工作流: {request.workflow_id}")

    # 创建工作流实例
    instance = workflow_engine.create_instance(
        workflow_id=request.workflow_id,
        name=request.name or f"{WORKFLOW_TEMPLATES[request.workflow_id]['name']} - {request.target}",
        target=request.target,
        phases=phases,
        description=request.description,
        config=request.config
    )

    # 后台执行工作流
    background_tasks.add_task(run_workflow_background, instance.instance_id)

    log.info(f"工作流已启动: {instance.instance_id} - {instance.name} - 目标: {request.target}")

    return {
        "instance_id": instance.instance_id,
        "status": "running",
        "message": f"工作流已启动，共{len(phases)}个阶段，目标: {request.target}",
        "phases": [{"id": p.phase_id, "name": p.name, "order": p.order} for p in phases]
    }


@router.get("")
async def list_workflows():
    """获取所有工作流实例列表"""
    instances = workflow_engine.list_instances()
    # 按创建时间倒序
    instances.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"total": len(instances), "instances": instances}




# ============================================================
# Round 7 新增：DAG 工作流执行/模板/自定义/历史/定时任务端点


@router.get("/dag_templates")
async def list_dag_templates_v7():
    """列出 Round7 DAG 模板概要。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        return {"total": len(list_dag_templates()), "templates": list_dag_templates()}
    except Exception as e:
        raise HTTPException(400, f"获取模板列表失败: {e}")


@router.get("/dag_instances")
async def list_dag_instances():
    """列出 DAG 工作流实例。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        items = dag_engine.list_instances()
        return {"total": len(items), "instances": items}
    except Exception as e:
        raise HTTPException(400, f"获取实例列表失败: {e}")


class ValidateRequest(BaseModel):
    workflow_def: Dict[str, Any] = Field(..., description="待校验的工作流定义")


@router.post("/custom/validate")
async def validate_custom_workflow(request: ValidateRequest):
    """校验自定义工作流。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        return workflow_builder.validate_workflow(request.workflow_def)
    except Exception as e:
        raise HTTPException(400, f"校验失败: {e}")


@router.post("/history/{execution_id}/rerun")
async def rerun_history_execution(execution_id: str):
    """按历史记录重跑。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        new_id = scheduler.rerun_execution(execution_id)
        if not new_id:
            raise HTTPException(404, f"历史记录不存在或重跑失败: {execution_id}")
        return {"old_execution_id": execution_id, "new_instance_id": new_id, "status": "running"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"重跑失败: {e}")


# 注意：以下静态路径端点必须注册在 @router.get("/{instance_id}") 之前，
# 否则会被 {instance_id} 捕获。
# ============================================================

try:
    from workflow.templates import (
        list_templates as list_dag_templates,
        get_template as get_dag_template,
        instantiate_template,
    )
    from workflow.builder import workflow_builder
    from workflow.scheduler import scheduler
    from workflow.engine import dag_engine, StepStatus
    _V7_IMPORTS_OK = True
    _V7_IMPORT_ERR = ""
except Exception as _e:  # pragma: no cover
    _V7_IMPORTS_OK = False
    _V7_IMPORT_ERR = str(_e)
    log.error(f"Round7 工作流模块导入失败: {_e}")


async def _dag_tool_executor(action_type: str, action_params: Dict[str, Any],
                              ctx: Dict[str, Any]) -> Dict[str, Any]:
    """DAG 引擎工具执行器：复用现有 workflow_tool_executor。"""
    tool_name = action_params.get("tool") or action_params.get("action") or action_params.get("tool_name")
    if not tool_name:
        return {"status": "skipped", "message": "未指定工具", "params": action_params}
    return await workflow_tool_executor(tool_name, action_params)


def _bind_dag_executor():
    """绑定 DAG 执行器（幂等）。"""
    try:
        dag_engine.tool_executor = _dag_tool_executor
    except Exception:
        pass

if _V7_IMPORTS_OK:
    _bind_dag_executor()


# ===== 请求模型 =====
class ExecuteRequest(BaseModel):
    """执行 DAG 工作流请求（二选一：template_id 或 workflow_def）。"""
    template_id: Optional[str] = Field(None, description="DAG模板ID")
    target: Optional[str] = Field(None, description="目标")
    workflow_def: Optional[Dict[str, Any]] = Field(None, description="自定义工作流定义（含steps）")
    name: Optional[str] = Field(None, description="工作流名称")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="运行参数")


class CustomWorkflowRequest(BaseModel):
    """保存自定义工作流请求。"""
    name: str = Field(..., description="自定义工作流名称")
    description: Optional[str] = Field("", description="描述")
    workflow_def: Dict[str, Any] = Field(..., description="工作流定义（含steps）")


class ScheduleRequest(BaseModel):
    """创建定时任务请求。"""
    template_id: str = Field(..., description="模板ID")
    target: str = Field(..., description="目标")
    schedule_type: str = Field("interval", description="cron / interval")
    cron_expr: Optional[str] = Field(None, description="cron表达式（分 时 日 月 周）")
    interval_minutes: Optional[int] = Field(None, description="间隔分钟数")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="运行参数")


@router.post("/execute")
async def execute_dag_workflow(request: ExecuteRequest):
    """执行DAG工作流（支持模板ID或自定义workflow_def），立即返回instance_id。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        if request.template_id:
            tpl = get_dag_template(request.template_id)
            if not tpl:
                raise HTTPException(400, f"未知模板: {request.template_id}")
            target = (request.target or "").strip()
            if not target:
                raise HTTPException(400, "执行模板时 target 不能为空")
            wf = instantiate_template(request.template_id, target, request.params or {})
            name = request.name or f"{wf['name']} - {target}"
            steps_def = wf["steps"]
            params = wf.get("params", {})
            description = wf.get("description", "")
        elif request.workflow_def:
            steps_def = request.workflow_def.get("steps") or []
            if not steps_def:
                raise HTTPException(400, "workflow_def 必须包含 steps 数组")
            v = workflow_builder.validate_workflow(request.workflow_def)
            if not v["valid"]:
                raise HTTPException(400, "工作流校验失败: " + "; ".join(v["errors"]))
            name = request.name or request.workflow_def.get("name") or "自定义工作流"
            target = (request.target or request.workflow_def.get("target") or "").strip()
            if not target:
                raise HTTPException(400, "自定义工作流必须提供 target")
            params = request.params or {}
            description = request.workflow_def.get("description", "")
        else:
            raise HTTPException(400, "必须提供 template_id 或 workflow_def")

        inst = dag_engine.create_instance(
            name=name, target=target, steps_def=steps_def,
            description=description, params=params,
        )
        dag_engine.start_async(inst.instance_id)
        return {
            "instance_id": inst.instance_id,
            "status": "running",
            "total_steps": len(steps_def),
            "message": f"DAG工作流已启动，共{len(steps_def)}步",
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[DAG] /execute 失败: {e}")
        raise HTTPException(400, f"执行失败: {e}")


@router.get("/templates/{template_id}")
async def get_dag_template_detail(template_id: str):
    """获取DAG模板详情（含完整步骤定义）。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        tpl = get_dag_template(template_id)
        if not tpl:
            raise HTTPException(404, f"模板不存在: {template_id}")
        return tpl
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"获取模板失败: {e}")


@router.post("/custom")
async def save_custom_workflow(request: CustomWorkflowRequest):
    """保存自定义工作流。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        result = workflow_builder.save_custom_workflow(request.name, request.workflow_def)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, f"保存失败: {e}")


@router.get("/custom")
async def list_custom_workflows():
    """获取自定义工作流列表。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        items = workflow_builder.list_custom_workflows()
        return {"total": len(items), "workflows": items}
    except Exception as e:
        raise HTTPException(400, f"获取列表失败: {e}")


@router.get("/custom/{name}")
async def get_custom_workflow(name: str):
    """获取自定义工作流详情。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        wf = workflow_builder.load_custom_workflow(name)
        if not wf:
            raise HTTPException(404, f"自定义工作流不存在: {name}")
        v = workflow_builder.validate_workflow(wf)
        return {"name": name, "workflow_def": wf, "validation": v}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"获取失败: {e}")


@router.delete("/custom/{name}")
async def delete_custom_workflow(name: str):
    """删除自定义工作流。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        ok = workflow_builder.delete_custom_workflow(name)
        if not ok:
            raise HTTPException(404, f"不存在: {name}")
        return {"deleted": True, "name": name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"删除失败: {e}")


@router.get("/history")
async def get_execution_history(limit: int = 50, offset: int = 0,
                                status: Optional[str] = None):
    """获取工作流执行历史。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        items = scheduler.get_history(limit=limit, offset=offset, status=status)
        return {"total": len(items), "items": items}
    except Exception as e:
        raise HTTPException(400, f"获取历史失败: {e}")


@router.post("/schedule")
async def create_schedule(request: ScheduleRequest):
    """创建定时工作流。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        tpl = get_dag_template(request.template_id)
        if not tpl:
            raise HTTPException(400, f"未知模板: {request.template_id}")
        if request.schedule_type == "cron" and not request.cron_expr:
            raise HTTPException(400, "cron 类型必须提供 cron_expr")
        if request.schedule_type == "interval" and not request.interval_minutes:
            raise HTTPException(400, "interval 类型必须提供 interval_minutes")
        sid = scheduler.add_schedule(
            workflow_template_id=request.template_id,
            target=request.target,
            schedule_type=request.schedule_type,
            cron_expr=request.cron_expr,
            interval_minutes=request.interval_minutes,
            params=request.params,
        )
        scheduler.start()
        return {"schedule_id": sid, "status": "created"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"创建定时任务失败: {e}")


@router.get("/schedule")
async def list_schedules():
    """获取定时任务列表。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        items = scheduler.list_schedules()
        return {"total": len(items), "items": items}
    except Exception as e:
        raise HTTPException(400, f"获取定时任务失败: {e}")


@router.delete("/schedule/{schedule_id}")
async def remove_schedule(schedule_id: str):
    """删除定时任务。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        ok = scheduler.remove_schedule(schedule_id)
        if not ok:
            raise HTTPException(404, f"定时任务不存在: {schedule_id}")
        return {"deleted": True, "schedule_id": schedule_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"删除失败: {e}")


@router.post("/schedule/{schedule_id}/enable")
async def enable_schedule(schedule_id: str):
    """启用定时任务。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        ok = scheduler.enable_schedule(schedule_id)
        if not ok:
            raise HTTPException(404, f"定时任务不存在: {schedule_id}")
        return {"schedule_id": schedule_id, "enabled": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"启用失败: {e}")


@router.post("/schedule/{schedule_id}/disable")
async def disable_schedule(schedule_id: str):
    """禁用定时任务。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        ok = scheduler.disable_schedule(schedule_id)
        if not ok:
            raise HTTPException(404, f"定时任务不存在: {schedule_id}")
        return {"schedule_id": schedule_id, "enabled": False}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"禁用失败: {e}")


@router.get("/{instance_id}/result")
async def get_dag_result(instance_id: str):
    """获取DAG工作流聚合结果。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        inst = dag_engine.get_instance(instance_id)
        if not inst:
            raise HTTPException(404, f"实例不存在: {instance_id}")
        agg = inst.aggregated_result or {}
        if not agg:
            # 运行中实时聚合
            agg = {
                "target": inst.target,
                "name": inst.name,
                "status": inst.status.value,
                "progress": inst.progress(),
                "vulnerabilities": [],
                "severity_count": {},
                "risk_score": 0,
                "risk_level": "info",
                "step_results": {s.step_id: s.to_dict() for s in inst.step_list()},
            }
        return agg
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"获取结果失败: {e}")


@router.get("/{instance_id}/steps")
async def get_dag_steps(instance_id: str):
    """获取DAG工作流所有步骤状态。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        inst = dag_engine.get_instance(instance_id)
        if not inst:
            raise HTTPException(404, f"实例不存在: {instance_id}")
        return {
            "instance_id": instance_id,
            "status": inst.status.value,
            "progress": inst.progress(),
            "steps": [s.to_dict() for s in inst.step_list()],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"获取步骤失败: {e}")


@router.post("/{instance_id}/retry")
async def retry_dag_workflow(instance_id: str):
    """重试失败的工作流（从失败步骤继续）。"""
    if not _V7_IMPORTS_OK:
        raise HTTPException(503, f"Round7模块未就绪: {_V7_IMPORT_ERR}")
    try:
        inst = dag_engine.get_instance(instance_id)
        if not inst:
            raise HTTPException(404, f"实例不存在: {instance_id}")
        ok = dag_engine.retry_failed(instance_id)
        if not ok:
            raise HTTPException(400, "没有失败步骤可重试，或工作流状态不允许")
        return {"instance_id": instance_id, "status": "running", "message": "已重新触发失败步骤"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"重试失败: {e}")

@router.get("/{instance_id}")
async def get_workflow_status(instance_id: str, include_results: bool = True):
    """获取工作流详细状态"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    return instance.to_dict(include_results=include_results)


@router.post("/{instance_id}/cancel")
async def cancel_workflow(instance_id: str):
    """取消正在运行的工作流"""
    success = workflow_engine.cancel_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法取消工作流: {instance_id}（可能已完成或不存在）")
    return {"instance_id": instance_id, "status": "cancelled", "message": "工作流已取消"}


@router.get("/{instance_id}/report")
async def get_workflow_report(instance_id: str):
    """获取工作流报告"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")

    if instance.status != WorkflowStatus.COMPLETED:
        return {
            "instance_id": instance_id,
            "status": instance.status.value,
            "message": "工作流尚未完成，报告生成中...",
            "progress": {
                "completed_phases": sum(1 for p in instance.phases if p.status == PhaseStatus.COMPLETED),
                "total_phases": len(instance.phases),
                "current_phase": instance.get_current_phase().name if instance.get_current_phase() else None
            }
        }

    # 收集所有阶段的AI分析作为报告
    report_sections = []
    for phase in instance.phases:
        if phase.ai_analysis:
            report_sections.append(f"## {phase.name}\n\n{phase.ai_analysis}\n")

    report_content = "\n".join(report_sections) if report_sections else "暂无报告内容"

    return {
        "instance_id": instance_id,
        "target": instance.target,
        "name": instance.name,
        "summary": instance.summary,
        "report": report_content,
        "phases": [
            {
                "name": p.name,
                "status": p.status.value,
                "ai_analysis": p.ai_analysis,
                "results_count": len(p.results),
                "duration_ms": p.to_dict().get("duration_ms")
            }
            for p in instance.phases
        ]
    }


# ===== 增强版API：暂停/继续/人工审核/日志 =====

class ApprovalRequest(BaseModel):
    """人工审核请求"""
    phase_id: str = Field(..., description="阶段ID")
    action: str = Field(..., description="审核动作: approve/reject/skip")
    reason: Optional[str] = Field("", description="审核原因")


@router.post("/{instance_id}/pause")
async def pause_workflow(instance_id: str):
    """暂停工作流"""
    success = workflow_engine.pause_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法暂停工作流: {instance_id}（可能不在运行状态）")
    return {"instance_id": instance_id, "status": "paused", "message": "工作流已暂停"}


@router.post("/{instance_id}/resume")
async def resume_workflow(instance_id: str):
    """继续工作流"""
    success = workflow_engine.resume_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法继续工作流: {instance_id}（可能不在暂停状态）")
    return {"instance_id": instance_id, "status": "running", "message": "工作流已继续执行"}


@router.post("/{instance_id}/approval")
async def submit_approval(instance_id: str, request: ApprovalRequest):
    """提交人工审核结果"""
    success = workflow_engine.submit_approval(
        instance_id=instance_id,
        phase_id=request.phase_id,
        action=request.action,
        reason=request.reason
    )
    if not success:
        raise HTTPException(400, f"提交审核失败: 工作流或阶段不存在，或阶段不在等待审核状态")
    return {
        "instance_id": instance_id,
        "phase_id": request.phase_id,
        "action": request.action,
        "message": f"审核已提交: {request.action}"
    }


@router.get("/{instance_id}/logs")
async def get_workflow_logs(instance_id: str, limit: int = 100):
    """获取工作流执行日志"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    logs = instance.execution_log[-limit:] if limit > 0 else instance.execution_log
    return {
        "instance_id": instance_id,
        "total_logs": len(instance.execution_log),
        "returned": len(logs),
        "logs": logs
    }


@router.get("/{instance_id}/context")
async def get_workflow_context(instance_id: str):
    """获取工作流上下文变量（用于调试和条件判断）"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    return {
        "instance_id": instance_id,
        "context": instance.context,
        "open_ports": instance.context.get("open_ports", []),
        "services": instance.context.get("services", {}),
        "vulnerabilities_count": len(instance.context.get("vulnerabilities", []))
    }


# ===== 增强版API：暂停/继续/人工审核/日志 =====

class ApprovalRequest(BaseModel):
    """人工审核请求"""
    phase_id: str = Field(..., description="阶段ID")
    action: str = Field(..., description="审核动作: approve/reject/skip")
    reason: Optional[str] = Field("", description="审核原因")


@router.post("/{instance_id}/pause")
async def pause_workflow(instance_id: str):
    """暂停工作流"""
    success = workflow_engine.pause_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法暂停工作流: {instance_id}（可能不在运行状态）")
    return {"instance_id": instance_id, "status": "paused", "message": "工作流已暂停"}


@router.post("/{instance_id}/resume")
async def resume_workflow(instance_id: str):
    """继续工作流"""
    success = workflow_engine.resume_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法继续工作流: {instance_id}（可能不在暂停状态）")
    return {"instance_id": instance_id, "status": "running", "message": "工作流已继续执行"}


@router.post("/{instance_id}/approval")
async def submit_approval(instance_id: str, request: ApprovalRequest):
    """提交人工审核结果"""
    success = workflow_engine.submit_approval(
        instance_id=instance_id,
        phase_id=request.phase_id,
        action=request.action,
        reason=request.reason
    )
    if not success:
        raise HTTPException(400, f"提交审核失败: 工作流或阶段不存在，或阶段不在等待审核状态")
    return {
        "instance_id": instance_id,
        "phase_id": request.phase_id,
        "action": request.action,
        "message": f"审核已提交: {request.action}"
    }


@router.get("/{instance_id}/logs")
async def get_workflow_logs(instance_id: str, limit: int = 100):
    """获取工作流执行日志"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    logs = instance.execution_log[-limit:] if limit > 0 else instance.execution_log
    return {
        "instance_id": instance_id,
        "total_logs": len(instance.execution_log),
        "returned": len(logs),
        "logs": logs
    }


@router.get("/{instance_id}/context")
async def get_workflow_context(instance_id: str):
    """获取工作流上下文变量（用于调试和条件判断）"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    return {
        "instance_id": instance_id,
        "context": instance.context,
        "open_ports": instance.context.get("open_ports", []),
        "services": instance.context.get("services", {}),
        "vulnerabilities_count": len(instance.context.get("vulnerabilities", []))
    }


# ===== 增强版API：暂停/继续/人工审核/日志 =====

class ApprovalRequest(BaseModel):
    """人工审核请求"""
    phase_id: str = Field(..., description="阶段ID")
    action: str = Field(..., description="审核动作: approve/reject/skip")
    reason: Optional[str] = Field("", description="审核原因")


@router.post("/{instance_id}/pause")
async def pause_workflow(instance_id: str):
    """暂停工作流"""
    success = workflow_engine.pause_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法暂停工作流: {instance_id}（可能不在运行状态）")
    return {"instance_id": instance_id, "status": "paused", "message": "工作流已暂停"}


@router.post("/{instance_id}/resume")
async def resume_workflow(instance_id: str):
    """继续工作流"""
    success = workflow_engine.resume_workflow(instance_id)
    if not success:
        raise HTTPException(400, f"无法继续工作流: {instance_id}（可能不在暂停状态）")
    return {"instance_id": instance_id, "status": "running", "message": "工作流已继续执行"}


@router.post("/{instance_id}/approval")
async def submit_approval(instance_id: str, request: ApprovalRequest):
    """提交人工审核结果"""
    success = workflow_engine.submit_approval(
        instance_id=instance_id,
        phase_id=request.phase_id,
        action=request.action,
        reason=request.reason
    )
    if not success:
        raise HTTPException(400, f"提交审核失败: 工作流或阶段不存在，或阶段不在等待审核状态")
    return {
        "instance_id": instance_id,
        "phase_id": request.phase_id,
        "action": request.action,
        "message": f"审核已提交: {request.action}"
    }


@router.get("/{instance_id}/logs")
async def get_workflow_logs(instance_id: str, limit: int = 100):
    """获取工作流执行日志"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    logs = instance.execution_log[-limit:] if limit > 0 else instance.execution_log
    return {
        "instance_id": instance_id,
        "total_logs": len(instance.execution_log),
        "returned": len(logs),
        "logs": logs
    }


@router.get("/{instance_id}/context")
async def get_workflow_context(instance_id: str):
    """获取工作流上下文变量（用于调试和条件判断）"""
    instance = workflow_engine.get_instance(instance_id)
    if not instance:
        raise HTTPException(404, f"工作流实例不存在: {instance_id}")
    return {
        "instance_id": instance_id,
        "context": instance.context,
        "open_ports": instance.context.get("open_ports", []),
        "services": instance.context.get("services", {}),
        "vulnerabilities_count": len(instance.context.get("vulnerabilities", []))
    }
