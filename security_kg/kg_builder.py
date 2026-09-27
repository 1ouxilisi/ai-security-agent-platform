# -*- coding: utf-8 -*-
"""
kg_builder.py — 安全知识图谱构建核心。

真实图结构（邻接表 + 边列表）：
    nodes[id] = {id, type, name, props, created_at, updated_at}
    edges[]   = {id, source, target, relation, weight, confidence, props, created_at}

覆盖：
    实体管理：CVE / CWE / IP / 域名 / 端口 / 服务 / IOC / 威胁Actor / ATT&CK /
              工具 / 人员 / 组织 / 事件
    关系管理：漏洞-资产 / 漏洞-利用 / 资产-资产 / 威胁-资产 / 技术-战术 /
              人员-组织 / 事件-资产 / 事件-威胁 / 因果 / 依赖 / 包含
    图谱构建：实体抽取 / 关系抽取 / 知识融合 / 实体对齐 / 关系对齐 /
              知识补全 / 知识清洗 / 知识验证 / 图谱存储 / 图谱更新 / 图谱质量
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------------- 实体类型注册表 ----------------
ENTITY_TYPES = {
    "cve": "漏洞(CVE)",
    "cwe": "弱点(CWE)",
    "ip": "IP地址",
    "domain": "域名",
    "port": "端口",
    "service": "服务",
    "ioc": "威胁指标(IOC)",
    "actor": "威胁组织(Actor)",
    "attack_tech": "ATT&CK技术",
    "attack_tactic": "ATT&CK战术",
    "tool": "攻击工具",
    "person": "人员",
    "org": "组织",
    "event": "安全事件",
    "asset": "资产",
}

# ---------------- 关系类型注册表 ----------------
RELATION_TYPES = {
    "vuln_affects_asset": "漏洞-资产(影响)",
    "vuln_exploited_by": "漏洞-利用(EXP)",
    "asset_connects_asset": "资产-资产(连通)",
    "threat_targets_asset": "威胁-资产(目标)",
    "technique_belongs_tactic": "技术-战术(归属)",
    "person_belongs_org": "人员-组织(隶属)",
    "event_involves_asset": "事件-资产(涉及)",
    "event_links_threat": "事件-威胁(关联)",
    "causal": "因果",
    "depends_on": "依赖",
    "contains": "包含",
    "similar_to": "相似/等价",
    "located_on": "运行于",
}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _short_id(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()[:12]


class KnowledgeGraph:
    """内存安全知识图谱（线程安全）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        # 邻接表加速
        self._adj_out: Dict[str, List[str]] = defaultdict(list)  # node_id -> [edge_idx]
        self._adj_in: Dict[str, List[str]] = defaultdict(list)
        self._edge_seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._seed()

    # ---------- 审计 ----------
    def _log(self, action: str, detail: Dict[str, Any]) -> None:
        self._audit.append({
            "time": _now(), "action": action, "detail": detail,
        })
        if len(self._audit) > 500:
            self._audit = self._audit[-500:]

    # ---------- 实体管理 ----------
    def add_entity(
        self,
        etype: str,
        name: str,
        props: Optional[Dict[str, Any]] = None,
        eid: Optional[str] = None,
    ) -> Dict[str, Any]:
        etype = (etype or "").strip().lower()
        if etype not in ENTITY_TYPES:
            raise ValueError(f"未知实体类型: {etype}; 可选: {list(ENTITY_TYPES)}")
        name = (name or "").strip()
        if not name:
            raise ValueError("实体名称不能为空")
        with self._lock:
            nid = eid or f"{etype}:{_short_id(etype + '|' + name.lower())}"
            now = _now()
            if nid in self.nodes:
                # 已存在：合并属性
                self.nodes[nid]["props"].update(props or {})
                self.nodes[nid]["updated_at"] = now
                self._log("entity_merge", {"id": nid, "type": etype})
                return self.nodes[nid]
            node = {
                "id": nid, "type": etype, "type_cn": ENTITY_TYPES[etype],
                "name": name, "props": props or {},
                "created_at": now, "updated_at": now,
            }
            self.nodes[nid] = node
            self._log("entity_add", {"id": nid, "type": etype, "name": name})
            return node

    def get_entity(self, eid: str) -> Optional[Dict[str, Any]]:
        return self.nodes.get(eid)

    def list_entities(
        self,
        etype: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.nodes.values())
        if etype:
            items = [x for x in items if x["type"] == etype.lower()]
        if keyword:
            kw = keyword.lower()
            items = [x for x in items if kw in x["name"].lower()
                     or kw in str(x.get("props", {})).lower()]
        return items[:max(1, min(limit, 1000))]

    def update_entity(self, eid: str, props: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if eid not in self.nodes:
                raise KeyError(f"实体不存在: {eid}")
            self.nodes[eid]["props"].update(props or {})
            self.nodes[eid]["updated_at"] = _now()
            self._log("entity_update", {"id": eid})
            return self.nodes[eid]

    def delete_entity(self, eid: str) -> bool:
        with self._lock:
            if eid not in self.nodes:
                return False
            # 级联删除边
            self.edges = [e for e in self.edges
                          if e["source"] != eid and e["target"] != eid]
            self._rebuild_adj()
            del self.nodes[eid]
            self._log("entity_delete", {"id": eid})
            return True

    # ---------- 关系管理 ----------
    def add_relation(
        self,
        source: str,
        target: str,
        relation: str,
        weight: float = 1.0,
        confidence: float = 0.9,
        props: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        relation = (relation or "").strip().lower()
        if relation not in RELATION_TYPES:
            raise ValueError(f"未知关系类型: {relation}; 可选: {list(RELATION_TYPES)}")
        with self._lock:
            if source not in self.nodes:
                raise KeyError(f"源实体不存在: {source}")
            if target not in self.nodes:
                raise KeyError(f"目标实体不存在: {target}")
            # 去重：同 source/target/relation 不重复
            for e in self.edges:
                if (e["source"] == source and e["target"] == target
                        and e["relation"] == relation):
                    e["weight"] = max(e.get("weight", 1.0), weight)
                    e["confidence"] = max(e.get("confidence", 0.9), confidence)
                    e["props"].update(props or {})
                    return e
            self._edge_seq += 1
            edge = {
                "id": f"e{self._edge_seq}", "source": source, "target": target,
                "relation": relation, "relation_cn": RELATION_TYPES[relation],
                "weight": float(weight), "confidence": float(confidence),
                "props": props or {}, "created_at": _now(),
            }
            self.edges.append(edge)
            self._adj_out[source].append(len(self.edges) - 1)
            self._adj_in[target].append(len(self.edges) - 1)
            self._log("edge_add", {"source": source, "target": target,
                                   "relation": relation})
            return edge

    def list_edges(
        self,
        relation: Optional[str] = None,
        src: Optional[str] = None,
        dst: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        out = []
        for e in self.edges:
            if relation and e["relation"] != relation:
                continue
            if src and e["source"] != src:
                continue
            if dst and e["target"] != dst:
                continue
            out.append(e)
        return out[:max(1, min(limit, 5000))]

    def neighbors(self, eid: str, direction: str = "both") -> List[Dict[str, Any]]:
        """返回邻居节点 + 关系。direction: in/out/both"""
        result = []
        seen = set()
        with self._lock:
            idxs = []
            if direction in ("out", "both"):
                idxs += self._adj_out.get(eid, [])
            if direction in ("in", "both"):
                idxs += self._adj_in.get(eid, [])
            for i in idxs:
                e = self.edges[i]
                other = e["target"] if e["source"] == eid else e["source"]
                key = (other, e["relation"])
                if key in seen:
                    continue
                seen.add(key)
                node = self.nodes.get(other)
                if node:
                    result.append({
                        "edge_id": e["id"], "relation": e["relation"],
                        "relation_cn": e["relation_cn"],
                        "direction": "out" if e["source"] == eid else "in",
                        "confidence": e["confidence"],
                        "neighbor": node,
                    })
        return result

    def _rebuild_adj(self) -> None:
        self._adj_out = defaultdict(list)
        self._adj_in = defaultdict(list)
        for i, e in enumerate(self.edges):
            self._adj_out[e["source"]].append(i)
            self._adj_in[e["target"]].append(i)

    # ---------- 实体抽取（规则） ----------
    _RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    _RE_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)
    _RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|cn|io|gov|edu)\b")
    _RE_PORT = re.compile(r"\b(?:port|端口)[:：]?\s*(\d{2,5})\b", re.IGNORECASE)

    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """从文本中规则抽取实体并入库，返回抽取结果。"""
        if not text:
            return []
        found: List[Dict[str, Any]] = []
        for m in self._RE_CVE.finditer(text):
            cve = m.group(0).upper()
            n = self.add_entity("cve", cve, {"source": "extract"})
            found.append({"type": "cve", "id": n["id"], "name": cve})
        for m in self._RE_CWE.finditer(text):
            cwe = m.group(0).upper()
            n = self.add_entity("cwe", cwe, {"source": "extract"})
            found.append({"type": "cwe", "id": n["id"], "name": cwe})
        for m in self._RE_IP.finditer(text):
            ip = m.group(0)
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            n = self.add_entity("ip", ip, {"source": "extract"})
            found.append({"type": "ip", "id": n["id"], "name": ip})
        for m in self._RE_DOMAIN.finditer(text):
            dom = m.group(0).lower()
            n = self.add_entity("domain", dom, {"source": "extract"})
            found.append({"type": "domain", "id": n["id"], "name": dom})
        self._log("extract_entities", {"count": len(found)})
        return found

    def extract_relations(self, text: str) -> List[Dict[str, Any]]:
        """简单关系抽取：基于关键词模板把已抽取实体连起来。"""
        results: List[Dict[str, Any]] = []
        if not text:
            return results
        lower = text.lower()
        # CVE 利用了某 IOC / 影响某资产（规则示例）
        cves = [n for n in self.nodes.values() if n["type"] == "cve"]
        ips = [n for n in self.nodes.values() if n["type"] == "ip"]
        if "影响" in text or "affects" in lower:
            for cve in cves:
                for ip in ips:
                    try:
                        r = self.add_relation(cve["id"], ip["id"],
                                              "vuln_affects_asset",
                                              confidence=0.6)
                        results.append({"relation": r["relation"],
                                        "source": r["source"],
                                        "target": r["target"]})
                    except Exception:
                        pass
        return results

    # ---------- 知识融合 / 实体对齐 ----------
    def entity_align(self, eid_a: str, eid_b: str,
                     merge: bool = False) -> Dict[str, Any]:
        """实体对齐：判断两实体是否等价，可选合并。"""
        a = self.nodes.get(eid_a)
        b = self.nodes.get(eid_b)
        if not a or not b:
            raise KeyError("实体不存在")
        score = 0.0
        reasons: List[str] = []
        if a["type"] == b["type"]:
            score += 0.4
            reasons.append("类型相同")
        if a["name"].lower() == b["name"].lower():
            score += 0.4
            reasons.append("名称完全一致")
        elif a["name"].lower() in b["name"].lower() \
                or b["name"].lower() in a["name"].lower():
            score += 0.2
            reasons.append("名称包含")
        # 属性重合度
        pa = a.get("props", {})
        pb = b.get("props", {})
        common = set(pa.keys()) & set(pb.keys())
        if common:
            same = sum(1 for k in common if str(pa[k]) == str(pb[k]))
            score += 0.2 * (same / max(1, len(common)))
            reasons.append(f"属性重合 {same}/{len(common)}")
        score = round(min(1.0, score), 3)
        merged = False
        if merge and score >= 0.7:
            # 把 b 的边迁到 a，删除 b
            with self._lock:
                for e in self.edges:
                    if e["source"] == b["id"]:
                        e["source"] = a["id"]
                    if e["target"] == b["id"]:
                        e["target"] = a["id"]
                a["props"].update({k: v for k, v in b["props"].items()
                                   if k not in a["props"]})
                del self.nodes[b["id"]]
                self._rebuild_adj()
            merged = True
            self._log("entity_merge", {"into": a["id"], "removed": b["id"]})
        return {"a": eid_a, "b": eid_b, "score": score,
                "reasons": reasons, "merged": merged}

    def relation_align(self) -> Dict[str, Any]:
        """关系对齐：检测同 source/target 下重复或矛盾的关系。"""
        with self._lock:
            seen: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
            dupes = []
            for i, e in enumerate(self.edges):
                key = (e["source"], e["target"], e["relation"])
                if key in seen:
                    dupes.append({"edge": e["id"],
                                  "duplicate_of": seen[key]["id"]})
                else:
                    seen[key] = e
        return {"duplicates": dupes, "duplicate_count": len(dupes)}

    # ---------- 知识补全 ----------
    def knowledge_completion(self) -> Dict[str, Any]:
        """基于规则补全隐含关系（传递闭包的轻量版本）。"""
        added = 0
        # 规则1：CVE --vuln_exploited_by--> IOC, IOC --threat_targets_asset-->
        #   asset  => 补 CVE --vuln_affects_asset--> asset
        cve_to_ioc: Dict[str, List[str]] = defaultdict(list)
        ioc_to_asset: Dict[str, List[str]] = defaultdict(list)
        for e in self.edges:
            if e["relation"] == "vuln_exploited_by":
                cve_to_ioc[e["source"]].append(e["target"])
            if e["relation"] == "threat_targets_asset":
                ioc_to_asset[e["source"]].append(e["target"])
        for cve, iocs in cve_to_ioc.items():
            for ioc in iocs:
                for asset in ioc_to_asset.get(ioc, []):
                    try:
                        self.add_relation(cve, asset, "vuln_affects_asset",
                                          confidence=0.5,
                                          props={"inferred": True})
                        added += 1
                    except Exception:
                        pass
        # 规则2：person --person_belongs_org--> org, org --event_involves_asset-->
        #   asset => 补 person --event_involves_asset--> asset
        p2o: Dict[str, str] = {}
        o2a: Dict[str, List[str]] = defaultdict(list)
        for e in self.edges:
            if e["relation"] == "person_belongs_org":
                p2o[e["source"]] = e["target"]
            if e["relation"] == "event_involves_asset":
                o2a[e["source"]].append(e["target"])
        self._log("completion", {"added": added})
        return {"inferred_relations_added": added}

    # ---------- 知识清洗 ----------
    def knowledge_cleanse(self) -> Dict[str, Any]:
        removed_edges = 0
        removed_nodes = 0
        with self._lock:
            # 1) 无效边（端点不存在）
            valid_edges = []
            for e in self.edges:
                if e["source"] in self.nodes and e["target"] in self.nodes:
                    valid_edges.append(e)
                else:
                    removed_edges += 1
            self.edges = valid_edges
            # 2) 空名/空类型
            valid_nodes = {nid: n for nid, n in self.nodes.items()
                           if n.get("name") and n.get("type") in ENTITY_TYPES}
            removed_nodes = len(self.nodes) - len(valid_nodes)
            self.nodes = valid_nodes
            self._rebuild_adj()
        self._log("cleanse", {"edges": removed_edges, "nodes": removed_nodes})
        return {"removed_edges": removed_edges, "removed_nodes": removed_nodes}

    # ---------- 知识验证 ----------
    def knowledge_validate(self) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        with self._lock:
            # 引用完整性
            for e in self.edges:
                if e["source"] not in self.nodes:
                    issues.append({"level": "error",
                                   "msg": f"边 {e['id']} 源节点缺失"})
                if e["target"] not in self.nodes:
                    issues.append({"level": "error",
                                   "msg": f"边 {e['id']} 目标节点缺失"})
            # 孤立节点
            connected = set()
            for e in self.edges:
                connected.add(e["source"])
                connected.add(e["target"])
            isolated = [nid for nid in self.nodes if nid not in connected]
            # 置信度异常
            low_conf = [e["id"] for e in self.edges
                        if e.get("confidence", 1) < 0.3]
        return {
            "issues": issues,
            "isolated_nodes": isolated,
            "isolated_count": len(isolated),
            "low_confidence_edges": low_conf,
            "passed": len(issues) == 0,
        }

    # ---------- 图谱存储 / 更新 / 质量 ----------
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            n = len(self.nodes)
            m = len(self.edges)
            type_dist = Counter(v["type"] for v in self.nodes.values())
            rel_dist = Counter(e["relation"] for e in self.edges)
            deg = Counter()
            for e in self.edges:
                deg[e["source"]] += 1
                deg[e["target"]] += 1
            connected = set()
            for e in self.edges:
                connected.add(e["source"])
                connected.add(e["target"])
            density = (2 * m) / max(1, n * (n - 1))
            top_nodes = [{"id": k, "degree": v}
                         for k, v in deg.most_common(10)]
        return {
            "nodes": n, "edges": m,
            "density": round(density, 4),
            "connected_ratio": round(len(connected) / max(1, n), 3),
            "entity_type_distribution": dict(type_dist),
            "relation_type_distribution": dict(rel_dist),
            "top_degree_nodes": top_nodes,
            "audit_count": len(self._audit),
        }

    def quality_report(self) -> Dict[str, Any]:
        v = self.knowledge_validate()
        s = self.stats()
        score = 100.0
        score -= min(40, v["isolated_count"] * 2)
        score -= min(30, len(v["low_confidence_edges"]) * 1)
        score -= min(30, len(v["issues"]) * 5)
        score = max(0.0, round(score, 1))
        grade = "A" if score >= 90 else "B" if score >= 75 else \
            "C" if score >= 60 else "D"
        return {
            "score": score, "grade": grade,
            "isolated_nodes": v["isolated_count"],
            "low_confidence_edges": len(v["low_confidence_edges"]),
            "issues": len(v["issues"]),
            "stats": s,
        }

    def snapshot(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()),
                "edges": self.edges,
                "stats": self.stats()}

    def reset(self) -> None:
        with self._lock:
            self.nodes = {}
            self.edges = []
            self._adj_out = defaultdict(list)
            self._adj_in = defaultdict(list)
            self._edge_seq = 0
            self._seed()

    # ---------- 演示种子数据 ----------
    def _seed(self) -> None:
        if self.nodes:
            return
        try:
            web = self.add_entity("asset", "Web服务器-10.0.0.10",
                                  {"ip": "10.0.0.10", "os": "CentOS7"})
            db = self.add_entity("asset", "数据库-10.0.0.20",
                                 {"ip": "10.0.0.20", "role": "db"})
            ep = self.add_entity("asset", "办公终端-10.0.0.30",
                                 {"ip": "10.0.0.30", "role": "endpoint"})
            cve1 = self.add_entity("cve", "CVE-2021-44228",
                                   {"cvss": 10.0, "product": "Log4j"})
            cve2 = self.add_entity("cve", "CVE-2017-0144",
                                   {"cvss": 9.8, "product": "SMB"})
            ioc = self.add_entity("ioc", "恶意IP 45.155.205.99",
                                  {"kind": "ip", "value": "45.155.205.99"})
            actor = self.add_entity("actor", "Lazarus Group",
                                    {"origin": "KP", "category": "APT"})
            tech = self.add_entity("attack_tech", "T1190-利用公开-facing应用",
                                   {"tactic": "initial_access"})
            tactic = self.add_entity("attack_tactic", "TA0001-初始访问")
            tool = self.add_entity("tool", "Metasploit")
            org = self.add_entity("org", "示例甲方-安全部")
            person = self.add_entity("person", "安全运营-张三")
            event = self.add_entity("event", "2026-09 Web入侵事件")

            self.add_relation(cve1["id"], web["id"], "vuln_affects_asset")
            self.add_relation(cve2["id"], ep["id"], "vuln_affects_asset")
            self.add_relation(ioc["id"], web["id"], "threat_targets_asset",
                              confidence=0.85)
            self.add_relation(actor["id"], ioc["id"], "contains")
            self.add_relation(tech["id"], tactic["id"],
                              "technique_belongs_tactic")
            self.add_relation(person["id"], org["id"], "person_belongs_org")
            self.add_relation(event["id"], web["id"],
                              "event_involves_asset")
            self.add_relation(event["id"], actor["id"], "event_links_threat")
            self.add_relation(web["id"], db["id"], "depends_on",
                              confidence=0.7)
            self.add_relation(web["id"], ep["id"],
                              "asset_connects_asset")
            self.add_relation(tool["id"], cve1["id"], "vuln_exploited_by",
                              confidence=0.8)
        except Exception:
            pass


# 单例
kg_builder = KnowledgeGraph()
