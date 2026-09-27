#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告 API 路由 - 报告生成 / 下载 / 模板管理

端点:
- POST /api/v1/reporting/generate
- GET  /api/v1/reporting/download/{report_id}
- GET  /api/v1/reporting/templates
- POST /api/v1/reporting/templates
- PUT  /api/v1/reporting/templates/{template_id}
- DELETE /api/v1/reporting/templates/{template_id}
- GET  /api/v1/reporting/formats
"""
import os
import sys
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporting.template_manager import TemplateManager  # noqa: E402
from unified.report_generator import UnifiedReportGenerator  # noqa: E402

router = APIRouter(prefix="/api/v1/reporting", tags=["报告管理"])

# 内存中的报告注册表: report_id -> 文件绝对路径
_REPORT_REGISTRY: Dict[str, str] = {}

# 默认输出目录
_DEFAULT_OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports"
)


# ==================== 请求模型 ====================

class GenerateReportRequest(BaseModel):
    """生成报告请求"""
    assessment_data: Dict[str, Any] = Field(..., description="评估数据")
    format: str = Field("html", description="格式: html/pdf/docx/xlsx")
    template_id: Optional[str] = Field(None, description="模板 ID，可选")
    output_dir: Optional[str] = Field(None, description="输出目录，可选")


class TemplateIn(BaseModel):
    """模板保存/更新请求"""
    id: Optional[str] = None
    name: Optional[str] = None
    company_name: Optional[str] = None
    logo_path: Optional[str] = None
    report_title: Optional[str] = None
    header_text: Optional[str] = None
    footer_text: Optional[str] = None
    contact_info: Optional[str] = None
    language: Optional[str] = "zh"
    sections: Optional[list] = None
    is_default: Optional[bool] = False


# ==================== 报告生成与下载 ====================

@router.post("/generate", summary="生成报告")
async def generate_report(req: GenerateReportRequest):
    """根据评估数据生成指定格式的报告"""
    try:
        gen = UnifiedReportGenerator(output_root=req.output_dir or _DEFAULT_OUTPUT_DIR)
        path = gen.generate_report(
            assessment_data=req.assessment_data,
            format=req.format,
            template_id=req.template_id,
            output_dir=req.output_dir,
        )
        report_id = uuid.uuid4().hex[:16]
        _REPORT_REGISTRY[report_id] = os.path.abspath(path)
        return {
            "success": True,
            "report_id": report_id,
            "file_path": os.path.abspath(path),
            "file_size": os.path.getsize(path) if os.path.exists(path) else 0,
            "download_url": f"/api/v1/reporting/download/{report_id}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"报告生成失败: {e}")


@router.get("/download/{report_id}", summary="下载报告")
async def download_report(report_id: str):
    """根据 report_id 下载报告文件"""
    try:
        path = _REPORT_REGISTRY.get(report_id)
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail="报告不存在或已被清理")
        filename = os.path.basename(path)
        media_type = "application/octet-stream"
        ext = os.path.splitext(path)[1].lower()
        if ext == ".pdf":
            media_type = "application/pdf"
        elif ext in (".docx", ".doc"):
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        elif ext in (".xlsx", ".xls"):
            media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif ext in (".html", ".htm"):
            media_type = "text/html; charset=utf-8"
        return FileResponse(path, filename=filename, media_type=media_type)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"下载失败: {e}")


# ==================== 格式列表 ====================

@router.get("/formats", summary="支持的报告格式")
async def list_formats():
    """返回支持的报告格式列表"""
    try:
        return {"success": True, "formats": UnifiedReportGenerator.supported_formats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 模板管理 ====================

def _manager() -> TemplateManager:
    return TemplateManager()


@router.get("/templates", summary="模板列表")
async def list_templates():
    try:
        return {"success": True, "templates": _manager().list_templates()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/templates", summary="保存新模板")
async def create_template(tpl: TemplateIn):
    try:
        cfg = tpl.model_dump(exclude_none=True)
        saved = _manager().save_template(cfg)
        return {"success": True, "template": saved}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/templates/{template_id}", summary="更新模板")
async def update_template(template_id: str, tpl: TemplateIn):
    try:
        updates = tpl.model_dump(exclude_none=True)
        updated = _manager().update_template(template_id, updates)
        return {"success": True, "template": updated}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/templates/{template_id}", summary="删除模板")
async def delete_template(template_id: str):
    try:
        _manager().delete_template(template_id)
        return {"success": True, "deleted": template_id}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
