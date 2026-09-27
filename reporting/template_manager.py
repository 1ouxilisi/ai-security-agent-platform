#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告模板管理器 - 管理多格式报告模板配置

支持:
- 模板持久化到 config/report_templates.json
- CRUD: list / get / save / update / delete
- 默认模板设置与获取
- 内置中文/英文标准模板
- 多语言章节标题映射
"""
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional


# 章节标识常量
SECTION_EXECUTIVE_SUMMARY = "executive_summary"
SECTION_VULN_DETAILS = "vulnerability_details"
SECTION_PORT_LIST = "port_list"
SECTION_REMEDIATION = "remediation"
SECTION_APPENDIX = "appendix"

ALL_SECTIONS = [
    SECTION_EXECUTIVE_SUMMARY,
    SECTION_VULN_DETAILS,
    SECTION_PORT_LIST,
    SECTION_REMEDIATION,
    SECTION_APPENDIX,
]

# 多语言章节标题映射
SECTION_TITLES = {
    "zh": {
        SECTION_EXECUTIVE_SUMMARY: "执行摘要",
        SECTION_VULN_DETAILS: "漏洞详情",
        SECTION_PORT_LIST: "端口清单",
        SECTION_REMEDIATION: "修复建议",
        SECTION_APPENDIX: "附录",
    },
    "en": {
        SECTION_EXECUTIVE_SUMMARY: "Executive Summary",
        SECTION_VULN_DETAILS: "Vulnerability Details",
        SECTION_PORT_LIST: "Port List",
        SECTION_REMEDIATION: "Remediation",
        SECTION_APPENDIX: "Appendix",
    },
}

# 内置默认模板
BUILTIN_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "default_zh",
        "name": "中文标准模板",
        "company_name": "AI Hacking Agent",
        "logo_path": "",
        "report_title": "安全评估报告",
        "header_text": "AI Hacking Agent · 安全评估报告",
        "footer_text": "本报告仅用于授权安全测试与防御评估",
        "contact_info": "",
        "language": "zh",
        "sections": list(ALL_SECTIONS),
        "is_default": True,
        "built_in": True,
    },
    {
        "id": "default_en",
        "name": "English Standard Template",
        "company_name": "AI Hacking Agent",
        "logo_path": "",
        "report_title": "Security Assessment Report",
        "header_text": "AI Hacking Agent · Security Assessment Report",
        "footer_text": "This report is for authorized security testing and defense assessment only.",
        "contact_info": "",
        "language": "en",
        "sections": list(ALL_SECTIONS),
        "is_default": False,
        "built_in": True,
    },
]


class TemplateManager:
    """报告模板管理器"""

    def __init__(self, config_path: Optional[str] = None):
        """初始化模板管理器

        Args:
            config_path: 模板 JSON 文件路径，默认 config/report_templates.json
        """
        if config_path is None:
            # 项目根目录下的 config/report_templates.json
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(project_root, "config", "report_templates.json")
        self.config_path = os.path.abspath(config_path)
        self._ensure_config()

    # ---------------- 内部工具 ----------------

    def _ensure_config(self) -> None:
        """确保配置文件存在，不存在则写入内置模板"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        if not os.path.exists(self.config_path):
            self._write({"templates": BUILTIN_TEMPLATES, "default_id": "default_zh"})

    def _read(self) -> Dict[str, Any]:
        """读取配置文件"""
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            # 损坏时回退到内置模板
            return {"templates": BUILTIN_TEMPLATES, "default_id": "default_zh"}

    def _write(self, data: Dict[str, Any]) -> None:
        """写入配置文件"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _normalize(template: Dict[str, Any]) -> Dict[str, Any]:
        """规范化模板字段，补全默认值"""
        sections = template.get("sections") or list(ALL_SECTIONS)
        return {
            "id": template.get("id") or f"tpl_{uuid.uuid4().hex[:10]}",
            "name": template.get("name") or "未命名模板",
            "company_name": template.get("company_name") or "AI Hacking Agent",
            "logo_path": template.get("logo_path") or "",
            "report_title": template.get("report_title") or "安全评估报告",
            "header_text": template.get("header_text") or "",
            "footer_text": template.get("footer_text") or "",
            "contact_info": template.get("contact_info") or "",
            "language": template.get("language") or "zh",
            "sections": [s for s in sections if s in ALL_SECTIONS] or list(ALL_SECTIONS),
            "is_default": bool(template.get("is_default", False)),
            "built_in": bool(template.get("built_in", False)),
            "updated_at": template.get("updated_at") or time.time(),
        }

    # ---------------- CRUD ----------------

    def list_templates(self) -> List[Dict[str, Any]]:
        """列出全部模板"""
        data = self._read()
        return data.get("templates", [])

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 获取模板，不存在返回 None"""
        for t in self.list_templates():
            if t.get("id") == template_id:
                return t
        return None

    def save_template(self, template_config: Dict[str, Any]) -> Dict[str, Any]:
        """保存新模板（若 id 已存在则报错）"""
        data = self._read()
        templates = data.get("templates", [])
        normalized = self._normalize(template_config)
        # 避免 id 冲突
        if any(t.get("id") == normalized["id"] for t in templates):
            raise ValueError(f"模板 ID 已存在: {normalized['id']}")
        normalized["updated_at"] = time.time()
        templates.append(normalized)
        data["templates"] = templates
        self._write(data)
        return normalized

    def update_template(self, template_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """更新模板字段"""
        data = self._read()
        templates = data.get("templates", [])
        for i, t in enumerate(templates):
            if t.get("id") == template_id:
                merged = dict(t)
                merged.update(updates)
                merged["id"] = template_id  # 不允许改 id
                merged = self._normalize(merged)
                merged["built_in"] = bool(t.get("built_in", False))
                merged["updated_at"] = time.time()
                templates[i] = merged
                data["templates"] = templates
                self._write(data)
                return merged
        raise KeyError(f"模板不存在: {template_id}")

    def delete_template(self, template_id: str) -> bool:
        """删除模板，内置模板禁止删除"""
        data = self._read()
        templates = data.get("templates", [])
        target = next((t for t in templates if t.get("id") == template_id), None)
        if target is None:
            raise KeyError(f"模板不存在: {template_id}")
        if target.get("built_in"):
            raise PermissionError(f"内置模板不可删除: {template_id}")
        templates = [t for t in templates if t.get("id") != template_id]
        data["templates"] = templates
        # 若删的是默认模板，回退到第一个
        if data.get("default_id") == template_id:
            data["default_id"] = templates[0]["id"] if templates else ""
        self._write(data)
        return True

    def set_default(self, template_id: str) -> Dict[str, Any]:
        """设置默认模板"""
        if self.get_template(template_id) is None:
            raise KeyError(f"模板不存在: {template_id}")
        data = self._read()
        data["default_id"] = template_id
        # 同步 is_default 标记
        for t in data.get("templates", []):
            t["is_default"] = (t.get("id") == template_id)
            t["updated_at"] = t.get("updated_at", time.time())
        self._write(data)
        return self.get_template(template_id)

    def get_default(self) -> Dict[str, Any]:
        """获取默认模板，无则返回第一个/中文模板"""
        data = self._read()
        default_id = data.get("default_id")
        if default_id:
            t = self.get_template(default_id)
            if t:
                return t
        templates = self.list_templates()
        return templates[0] if templates else BUILTIN_TEMPLATES[0]

    # ---------------- 多语言辅助 ----------------

    def section_title(self, template: Dict[str, Any], section_key: str) -> str:
        """根据模板语言获取章节标题"""
        lang = template.get("language", "zh")
        mapping = SECTION_TITLES.get(lang, SECTION_TITLES["zh"])
        return mapping.get(section_key, section_key)


# =====================================================================
# 第8轮新增：高级模板定义 / CRUD / 导入导出 / 预览 / 版本 / Logo 管理
# （以下为追加内容，不修改上方既有功能）
# =====================================================================
import json as _json  # noqa: E402
import time as _time  # noqa: E402
import uuid as _uuid  # noqa: E402

# 9个标准章节ID（与 template_engine 保持一致）
FULL_SECTION_IDS = [
    "cover", "toc", "executive_summary", "target_info", "methodology",
    "vuln_details", "risk_assessment", "remediation", "appendix",
]


def _default_sections(visible_ids):
    """根据可见章节ID列表生成章节定义"""
    sec_map = {
        "cover": "封面", "toc": "目录", "executive_summary": "执行摘要",
        "target_info": "目标信息", "methodology": "扫描方法",
        "vuln_details": "漏洞详情", "risk_assessment": "风险评估",
        "remediation": "修复建议", "appendix": "附录",
    }
    sections = []
    for idx, sid in enumerate(FULL_SECTION_IDS):
        sections.append({
            "section_id": sid,
            "title": sec_map.get(sid, sid),
            "visible": sid in visible_ids,
            "order": idx + 1,
            "content_template": "",
        })
    return sections


# 5个预定义模板定义
PRESET_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "standard_report": {
        "id": "standard_report",
        "name": "标准报告",
        "description": "全部9个章节，经典黑白样式",
        "style_preset": "classic_bw",
        "sections": _default_sections(FULL_SECTION_IDS),
        "built_in": True,
    },
    "brief_report": {
        "id": "brief_report",
        "name": "简要报告",
        "description": "封面+执行摘要+漏洞列表+修复建议，科技蓝样式",
        "style_preset": "tech_blue",
        "sections": _default_sections(["cover", "toc", "executive_summary", "vuln_details", "remediation"]),
        "built_in": True,
    },
    "executive_report": {
        "id": "executive_report",
        "name": "管理层报告",
        "description": "封面+执行摘要+风险评估+趋势图表，商务灰样式",
        "style_preset": "business_gray",
        "sections": _default_sections(["cover", "toc", "executive_summary", "risk_assessment", "appendix"]),
        "built_in": True,
    },
    "technical_report": {
        "id": "technical_report",
        "name": "技术报告",
        "description": "封面+目标信息+扫描方法+漏洞详情+修复建议+附录，安全红样式",
        "style_preset": "security_red",
        "sections": _default_sections(["cover", "toc", "target_info", "methodology", "vuln_details", "remediation", "appendix"]),
        "built_in": True,
    },
    "compliance_report": {
        "id": "compliance_report",
        "name": "合规报告",
        "description": "封面+执行摘要+合规检查结果+漏洞详情+修复建议，经典黑白样式",
        "style_preset": "classic_bw",
        "sections": _default_sections(["cover", "toc", "executive_summary", "vuln_details", "remediation"]),
        "built_in": True,
    },
}

# 自定义模板存储
_custom_templates: Dict[str, Dict[str, Any]] = {}
# 模板版本快照
_template_versions: Dict[str, list] = {}
# Logo 存储: logo_id -> {id, name, data(base64), mime, uploaded_at}
_logos: Dict[str, Dict[str, Any]] = {}


class EnhancedTemplateManager:
    """高级模板管理器：预定义模板 + 自定义模板 CRUD + 导入导出 + 预览 + 版本 + Logo"""

    def list_all_templates(self) -> List[Dict[str, Any]]:
        """预定义 + 自定义模板列表"""
        try:
            out = []
            for tid, tpl in PRESET_TEMPLATES.items():
                out.append({**tpl, "source": "preset"})
            for tid, tpl in _custom_templates.items():
                out.append({**tpl, "source": "custom"})
            return out
        except Exception:
            return []

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        try:
            if template_id in PRESET_TEMPLATES:
                return dict(PRESET_TEMPLATES[template_id])
            if template_id in _custom_templates:
                return dict(_custom_templates[template_id])
            return None
        except Exception:
            return None

    def create_template(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """创建自定义模板"""
        try:
            tid = config.get("id") or f"custom_{_uuid.uuid4().hex[:10]}"
            if tid in PRESET_TEMPLATES:
                raise ValueError(f"预定义模板ID不可占用: {tid}")
            tpl = {
                "id": tid,
                "name": config.get("name") or "自定义模板",
                "description": config.get("description", ""),
                "style_preset": config.get("style_preset", "custom"),
                "style_vars": config.get("style_vars", {}),
                "sections": config.get("sections") or _default_sections(FULL_SECTION_IDS),
                "version": 1,
                "built_in": False,
                "created_at": _time.time(),
                "updated_at": _time.time(),
            }
            _custom_templates[tid] = tpl
            _template_versions.setdefault(tid, []).append(self._snapshot(tpl))
            return dict(tpl)
        except Exception:
            raise

    def update_template(self, template_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """更新模板并保存版本快照"""
        try:
            if template_id in PRESET_TEMPLATES:
                # 预定义模板更新 -> 复制为自定义后修改
                base = dict(PRESET_TEMPLATES[template_id])
                base.update(updates)
                base["id"] = f"custom_{_uuid.uuid4().hex[:10]}"
                base["built_in"] = False
                return self.create_template(base)
            if template_id not in _custom_templates:
                raise KeyError(f"模板不存在: {template_id}")
            tpl = dict(_custom_templates[template_id])
            for k in ("name", "description", "style_preset", "style_vars", "sections"):
                if k in updates:
                    tpl[k] = updates[k]
            tpl["version"] = tpl.get("version", 1) + 1
            tpl["updated_at"] = _time.time()
            _custom_templates[template_id] = tpl
            _template_versions.setdefault(template_id, []).append(self._snapshot(tpl))
            return dict(tpl)
        except Exception:
            raise

    def delete_template(self, template_id: str) -> bool:
        try:
            if template_id in PRESET_TEMPLATES:
                raise PermissionError("预定义模板不可删除")
            if template_id not in _custom_templates:
                raise KeyError(f"模板不存在: {template_id}")
            _custom_templates.pop(template_id, None)
            _template_versions.pop(template_id, None)
            return True
        except Exception:
            raise

    def duplicate_template(self, template_id: str, new_name: Optional[str] = None) -> Dict[str, Any]:
        """复制模板"""
        try:
            src = self.get_template(template_id)
            if src is None:
                raise KeyError(f"模板不存在: {template_id}")
            src = dict(src)
            src["built_in"] = False
            src["id"] = f"custom_{_uuid.uuid4().hex[:10]}"
            src["name"] = new_name or (src.get("name", "模板") + " (副本)")
            src.pop("source", None)
            return self.create_template(src)
        except Exception:
            raise

    def export_template(self, template_id: str) -> str:
        """导出模板为JSON字符串"""
        try:
            tpl = self.get_template(template_id)
            if tpl is None:
                raise KeyError(f"模板不存在: {template_id}")
            return _json.dumps(tpl, ensure_ascii=False, indent=2)
        except Exception:
            raise

    def import_template(self, json_str: str) -> str:
        """导入模板，返回模板ID"""
        try:
            data = _json.loads(json_str) if isinstance(json_str, str) else json_str
            data["id"] = f"custom_{_uuid.uuid4().hex[:10]}"
            data["built_in"] = False
            saved = self.create_template(data)
            return saved["id"]
        except Exception:
            raise

    def preview_template(self, template_id: str, sample_data: Dict[str, Any]) -> str:
        """渲染预览HTML"""
        try:
            from reporting.template_engine import ReportTemplateEngine
            tpl = self.get_template(template_id)
            if tpl is None:
                raise KeyError(f"模板不存在: {template_id}")
            from reporting.style_presets import get_preset, generate_css
            preset_id = tpl.get("style_preset", "custom")
            style_vars = tpl.get("style_vars") or get_preset(preset_id).get("style_vars", {})
            tpl_cfg = {"sections": tpl.get("sections"), "style_vars": style_vars}
            engine = ReportTemplateEngine()
            rendered = engine.render_report(tpl_cfg, sample_data or {})
            css = generate_css(style_vars)
            body = "".join(v for v in rendered.values() if v)
            return f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>{body}</body></html>"
        except Exception:
            return "<html><body><p>预览失败</p></body></html>"

    # ---------------- Logo 管理 ----------------
    def upload_logo(self, name: str, data_b64: str, mime: str = "image/png") -> str:
        try:
            lid = f"logo_{_uuid.uuid4().hex[:10]}"
            _logos[lid] = {
                "id": lid, "name": name, "data": data_b64,
                "mime": mime, "uploaded_at": _time.time(),
            }
            return lid
        except Exception:
            raise

    def get_logo(self, logo_id: str) -> Optional[Dict[str, Any]]:
        try:
            return _logos.get(logo_id)
        except Exception:
            return None

    def list_logos(self) -> List[Dict[str, Any]]:
        try:
            return list(_logos.values())
        except Exception:
            return []

    def delete_logo(self, logo_id: str) -> bool:
        try:
            if logo_id not in _logos:
                raise KeyError(f"Logo不存在: {logo_id}")
            _logos.pop(logo_id, None)
            return True
        except Exception:
            raise

    # ---------------- 版本 ----------------
    def get_versions(self, template_id: str) -> list:
        try:
            return _template_versions.get(template_id, [])
        except Exception:
            return []

    @staticmethod
    def _snapshot(tpl: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "version": tpl.get("version", 1),
            "snapshot_time": _time.time(),
            "name": tpl.get("name"),
            "sections": tpl.get("sections"),
            "style_preset": tpl.get("style_preset"),
        }


# 模块级单例
_enhanced_manager = EnhancedTemplateManager()


def get_enhanced_manager() -> EnhancedTemplateManager:
    return _enhanced_manager
