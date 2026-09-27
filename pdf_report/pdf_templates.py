# -*- coding: utf-8 -*-
"""
pdf_templates.py — PDF 模板管理（内存字典存储）。

支持：创建 / 编辑 / 删除 / 设为默认 / 列表 / 预览。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .pdf_styles import default_template_props


class TemplateManager:
    """模板管理器。"""

    def __init__(self) -> None:
        self._templates: Dict[str, Dict[str, Any]] = {}
        self._default_id: str = ""
        self._seed_default()

    def _seed_default(self) -> None:
        props = default_template_props()
        tid = "tpl_default"
        self._templates[tid] = {
            "id": tid, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "is_default": True, **props,
        }
        self._default_id = tid

    # ------------------------------------------------------------------ #
    def list(self) -> List[Dict[str, Any]]:
        return sorted(self._templates.values(),
                      key=lambda x: (not x.get("is_default", False),
                                     x.get("updated_at", "")),
                      reverse=False)

    def get(self, tpl_id: str) -> Optional[Dict[str, Any]]:
        return self._templates.get(tpl_id)

    def get_default(self) -> Dict[str, Any]:
        return self._templates.get(self._default_id,
                                   next(iter(self._templates.values())))

    def create(self, props: Dict[str, Any]) -> Dict[str, Any]:
        tid = props.get("id") or ("tpl_" + uuid.uuid4().hex[:10])
        merged = {**default_template_props(), **props, "id": tid,
                  "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "is_default": False}
        self._templates[tid] = merged
        return merged

    def update(self, tpl_id: str, props: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cur = self._templates.get(tpl_id)
        if cur is None:
            return None
        cur.update({k: v for k, v in props.items() if k != "id"})
        cur["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return cur

    def delete(self, tpl_id: str) -> bool:
        if tpl_id == "tpl_default" or tpl_id == self._default_id:
            return False
        return self._templates.pop(tpl_id, None) is not None

    def set_default(self, tpl_id: str) -> bool:
        if tpl_id not in self._templates:
            return False
        for k, v in self._templates.items():
            v["is_default"] = (k == tpl_id)
        self._default_id = tpl_id
        return True

    def preview(self, tpl_id: str) -> Dict[str, Any]:
        tpl = self.get(tpl_id) or self.get_default()
        return {
            "template": tpl,
            "preview_html": self._render_preview(tpl),
        }

    @staticmethod
    def _render_preview(tpl: Dict[str, Any]) -> str:
        return f"""<!doctype html><html><head><meta charset="utf-8">
<style>
body{{font-family:'Microsoft YaHei',sans-serif;margin:0;background:#111;}}
.cover{{height:340px;background:{tpl.get('cover_bg','#0b5394')};color:#fff;
padding:40px;box-sizing:border-box;position:relative;}}
.cover h1{{margin:60px 0 6px;font-size:30px;}}
.cover .conf{{position:absolute;top:24px;right:30px;border:2px solid #ffd54f;
color:#ffd54f;padding:3px 12px;border-radius:4px;font-size:12px;}}
.body{{padding:24px;color:#ddd;font-size:13px;}}
.bar{{height:10px;background:{tpl.get('primary_color','#0b5394')};width:60%;}}
table{{width:100%;border-collapse:collapse;margin-top:10px;}}
th{{background:{tpl.get('primary_color','#0b5394')};color:#fff;padding:6px;}}
td{{border:1px solid #444;padding:6px;}}
</style></head><body>
<div class="cover"><div class="conf">{tpl.get('confidential','机密')}</div>
<h1>{tpl.get('title','安全评估报告')}</h1>
<div>{tpl.get('subtitle','')}</div></div>
<div class="body"><b>{tpl.get('company','')}</b> · {tpl.get('version','v1.0')}
<div class="bar" style="margin:10px 0"></div>
<table><tr><th>章节</th><th>说明</th></tr>
<tr><td>执行摘要</td><td>关键发现/风险评级</td></tr>
<tr><td>详细发现</td><td>漏洞与分析</td></tr>
</table></div></body></html>"""


_manager: Optional[TemplateManager] = None


def get_template_manager() -> TemplateManager:
    global _manager
    if _manager is None:
        _manager = TemplateManager()
    return _manager
