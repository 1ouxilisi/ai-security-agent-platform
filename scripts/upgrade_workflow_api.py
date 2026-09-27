#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upgrade_workflow_api脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

"""升级工作流API：添加暂停/继续/人工审核/日志接口"""

filepath = 'api_server/workflow_routes.py'
with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# 在报告接口后面添加新接口
old = '''@router.get("/{instance_id}/report")
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
            report_sections.append(f"## {phase.name}\\n\\n{phase.ai_analysis}\\n")

    report_content = "\\n".join(report_sections) if report_sections else "暂无报告内容"

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
    }'''

new = '''@router.get("/{instance_id}/report")
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
            report_sections.append(f"## {phase.name}\\n\\n{phase.ai_analysis}\\n")

    report_content = "\\n".join(report_sections) if report_sections else "暂无报告内容"

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
    }'''

if old in content:
    content = content.replace(old, new)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print('✓ 工作流API已升级：添加暂停/继续/人工审核/日志/上下文接口')
else:
    print('✗ 未找到报告接口代码块')
    # 查找类似的行
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'report' in line.lower() and 'def ' in line:
            print(f'  行{i+1}: {line.strip()[:80]}')
