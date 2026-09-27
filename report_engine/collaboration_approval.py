# -*- coding: utf-8 -*-
"""collaboration_approval.py — 报告协作与审批。

- 多人协作编辑 / Git 式版本管理
- 评论批注 / 审批流（起草→审核→审批→定稿）
- 电子签名 / 修改追踪（diff）/ 定稿管理 / 归档
"""

from __future__ import annotations

import copy
import difflib
import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


APPROVAL_STAGES = ["draft", "review", "approve", "finalized", "archived"]
ROLES = ["author", "reviewer", "approver", "archiver"]


class CollaborationApproval:
    def __init__(self) -> None:
        self.docs: Dict[str, Dict[str, Any]] = {}          # 报告文档（含协作状态）
        self.versions: Dict[str, List[Dict[str, Any]]] = {}
        self.comments: Dict[str, List[Dict[str, Any]]] = {}
        self.signatures: Dict[str, Dict[str, str]] = {}

    # ---------------- 文档创建 ---------------- #
    def create_document(self, report: Dict[str, Any], owner: str = "author") -> Dict[str, Any]:
        doc_id = f"DOC-{uuid.uuid4().hex[:8].upper()}"
        doc = {
            "doc_id": doc_id,
            "report_id": report["report_id"],
            "title": f"{report.get('client','某客户')}-{report.get('template_name','报告')}",
            "owner": owner,
            "stage": "draft",
            "content": copy.deepcopy(report),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "members": [{"user": owner, "role": "author"}],
            "changelog": [{"at": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "created", "by": owner}],
        }
        self.docs[doc_id] = doc
        self.versions[doc_id] = [self._snapshot(doc)]
        self.comments[doc_id] = []
        self.signatures[doc_id] = {}
        return doc

    # ---------------- 协作 ---------------- #
    def add_member(self, doc_id: str, user: str, role: str) -> bool:
        doc = self.docs.get(doc_id)
        if not doc or role not in ROLES:
            return False
        if not any(m["user"] == user for m in doc["members"]):
            doc["members"].append({"user": user, "role": role})
        doc["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return True

    def commit(self, doc_id: str, user: str, patch: Dict[str, Any],
               message: str = "") -> Optional[Dict[str, Any]]:
        doc = self.docs.get(doc_id)
        if not doc:
            return None
        # 应用 patch 到 content
        for k, v in patch.items():
            if k in doc["content"]:
                doc["content"][k] = v
        doc["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        doc["changelog"].append({
            "at": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "commit",
            "by": user, "message": message,
        })
        snap = self._snapshot(doc)
        self.versions.setdefault(doc_id, []).append(snap)
        return snap

    def list_versions(self, doc_id: str) -> List[Dict[str, Any]]:
        return self.versions.get(doc_id, [])

    def diff(self, doc_id: str, v1: str, v2: str) -> Dict[str, Any]:
        hist = {v["version"]: v for v in self.versions.get(doc_id, [])}
        if v1 not in hist or v2 not in hist:
            return {"error": "version not found"}
        c1 = json_dump(hist[v1]["snapshot"])
        c2 = json_dump(hist[v2]["snapshot"])
        diff_lines = list(difflib.unified_diff(
            c1.splitlines(), c2.splitlines(), fromfile=v1, tofile=v2, lineterm="",
        ))
        return {
            "doc_id": doc_id, "from": v1, "to": v2,
            "diff": diff_lines[:200], "diff_lines_count": len(diff_lines),
        }

    # ---------------- 评论 ---------------- #
    def add_comment(self, doc_id: str, user: str, text: str,
                    anchor: str = "") -> Optional[Dict[str, Any]]:
        if doc_id not in self.docs:
            return None
        cmt = {
            "comment_id": f"CMT-{uuid.uuid4().hex[:6].upper()}",
            "user": user, "text": text, "anchor": anchor,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.comments[doc_id].append(cmt)
        return cmt

    def list_comments(self, doc_id: str) -> List[Dict[str, Any]]:
        return self.comments.get(doc_id, [])

    # ---------------- 审批流 ---------------- #
    def advance_stage(self, doc_id: str, user: str, note: str = "") -> Optional[Dict[str, Any]]:
        doc = self.docs.get(doc_id)
        if not doc:
            return None
        cur = APPROVAL_STAGES.index(doc["stage"])
        if cur >= len(APPROVAL_STAGES) - 1:
            return {"doc_id": doc_id, "stage": doc["stage"], "msg": "已终态"}
        doc["stage"] = APPROVAL_STAGES[cur + 1]
        doc["changelog"].append({
            "at": time.strftime("%Y-%m-%d %H:%M:%S"), "event": f"stage->{doc['stage']}",
            "by": user, "message": note,
        })
        doc["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"doc_id": doc_id, "stage": doc["stage"], "msg": note}

    def sign(self, doc_id: str, user: str, role: str, signature: str) -> bool:
        if doc_id not in self.docs:
            return False
        self.signatures[doc_id][f"{user}:{role}"] = {
            "signature": signature,
            "signed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hash": hashlib.sha256(f"{user}|{role}|{signature}".encode()).hexdigest(),
        }
        return True

    def finalize(self, doc_id: str) -> Optional[Dict[str, Any]]:
        doc = self.docs.get(doc_id)
        if not doc:
            return None
        doc["stage"] = "finalized"
        doc["changelog"].append({
            "at": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "finalized",
            "by": "system",
        })
        return doc

    def archive(self, doc_id: str) -> Optional[Dict[str, Any]]:
        doc = self.docs.get(doc_id)
        if not doc:
            return None
        doc["stage"] = "archived"
        doc["changelog"].append({
            "at": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "archived", "by": "system",
        })
        return doc

    def get(self, doc_id: str) -> Optional[Dict[str, Any]]:
        return self.docs.get(doc_id)

    def list_docs(self) -> List[Dict[str, Any]]:
        return list(self.docs.values())

    # ---------------- 内部 ---------------- #
    @staticmethod
    def _snapshot(doc: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "version": f"v{uuid.uuid4().hex[:6]}",
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "snapshot": copy.deepcopy(doc),
        }


def json_dump(obj: Any) -> str:
    import json as _json
    return _json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2)


_COLLAB: CollaborationApproval | None = None


def get_collab() -> CollaborationApproval:
    global _COLLAB
    if _COLLAB is None:
        _COLLAB = CollaborationApproval()
    return _COLLAB
