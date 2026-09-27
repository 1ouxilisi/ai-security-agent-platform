#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告模板 API 路由（13个端点）

前缀: /api/v1/report-templates
"""
import os
import sys
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reporting.template_manager import get_enhanced_manager  # noqa: E402
from reporting.style_presets import apply_preset, list_presets  # noqa: E402

router = APIRouter(prefix="/api/v1/report-templates", tags=["报告模板"])


# ==================== 请求模型 ====================

class TemplateConfigIn(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = ""
    style_preset: Optional[str] = "custom"
    style_vars: Optional[Dict[str, Any]] = None
    sections: Optional[list] = None


class PreviewIn(BaseModel):
    sample_data: Dict[str, Any] = Field(default_factory=dict)


class DuplicateIn(BaseModel):
    new_name: Optional[str] = None


class ImportIn(BaseModel):
    content: str


class ApplyStyleIn(BaseModel):
    preset_id: str


def _mgr():
    return get_enhanced_manager()


# ==================== 1. 模板列表 ====================
@router.get("/list", summary="获取模板列表")
async def list_templates():
    try:
        return {"success": True, "templates": _mgr().list_all_templates()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 1b. 样式预设列表（静态路由必须在/{template_id}之前） ====================
@router.get("/styles", summary="获取样式预设列表")
async def get_styles():
    try:
        return {"success": True, "presets": list_presets()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 2. 模板详情 ====================
@router.get("/{template_id}", summary="获取模板详情")
async def get_template(template_id: str):
    try:
        tpl = _mgr().get_template(template_id)
        if tpl is None:
            raise HTTPException(status_code=404, detail="模板不存在")
        return {"success": True, "template": tpl}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 3. 创建模板 ====================
@router.post("", summary="创建自定义模板")
async def create_template(cfg: TemplateConfigIn):
    try:
        saved = _mgr().create_template(cfg.model_dump(exclude_none=True))
        return {"success": True, "template": saved}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ==================== 4. 更新模板 ====================
@router.put("/{template_id}", summary="更新模板")
async def update_template(template_id: str, cfg: TemplateConfigIn):
    try:
        updated = _mgr().update_template(template_id, cfg.model_dump(exclude_none=True))
        return {"success": True, "template": updated}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 5. 删除模板 ====================
@router.delete("/{template_id}", summary="删除模板")
async def delete_template(template_id: str):
    try:
        _mgr().delete_template(template_id)
        return {"success": True, "deleted": template_id}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 6. 预览模板 ====================
@router.post("/{template_id}/preview", summary="预览模板渲染效果")
async def preview_template(template_id: str, body: PreviewIn):
    try:
        html = _mgr().preview_template(template_id, body.sample_data or {})
        return {"success": True, "html": html}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 7. 复制模板 ====================
@router.post("/{template_id}/duplicate", summary="复制模板")
async def duplicate_template(template_id: str, body: DuplicateIn):
    try:
        new_tpl = _mgr().duplicate_template(template_id, body.new_name)
        return {"success": True, "template": new_tpl}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 8. 导出模板 ====================
@router.get("/{template_id}/export", summary="导出模板(JSON)")
async def export_template(template_id: str):
    try:
        content = _mgr().export_template(template_id)
        return {"success": True, "content": content, "format": "json"}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 9. 导入模板 ====================
@router.post("/import", summary="导入模板")
async def import_template(body: ImportIn):
    try:
        new_id = _mgr().import_template(body.content)
        return {"success": True, "template_id": new_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"导入失败: {e}")


# ==================== 11. 应用样式预设 ====================
@router.post("/{template_id}/apply-style", summary="应用样式预设")
async def apply_style(template_id: str, body: ApplyStyleIn):
    try:
        tpl = _mgr().get_template(template_id)
        if tpl is None:
            raise HTTPException(status_code=404, detail="模板不存在")
        updated = apply_preset(tpl, body.preset_id)
        # 写回（预定义模板会被复制为自定义）
        result = _mgr().update_template(template_id, updated)
        return {"success": True, "template": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 12. 上传Logo ====================
@router.post("/logo", summary="上传Logo")
async def upload_logo(file: UploadFile = File(...), name: Optional[str] = Form(None)):
    try:
        import base64
        content = await file.read()
        b64 = base64.b64encode(content).decode("ascii")
        lid = _mgr().upload_logo(name or file.filename or "logo", b64,
                                 file.content_type or "image/png")
        return {"success": True, "logo_id": lid, "name": name or file.filename}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 13. 删除Logo ====================
@router.delete("/logo/{logo_id}", summary="删除Logo")
async def delete_logo(logo_id: str):
    try:
        _mgr().delete_logo(logo_id)
        return {"success": True, "deleted": logo_id}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
