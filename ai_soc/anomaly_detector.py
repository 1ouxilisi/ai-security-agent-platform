#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 异常检测器 (Anomaly Detector)
===================================

检测四类异常：
    1. 流量异常：突发流量 / 异常端口 / 异常协议
    2. 行为异常：异常登录时间 / 异常访问模式 / 异常操作序列
    3. 性能异常：CPU / 内存 / 磁盘 / 网络指标异常
    4. 日志异常：错误率突增 / 异常日志模式

检测算法（全部纯 Python 实现，不依赖 scikit-learn）：
    - 基于统计：Z-score、移动平均(Moving Average)、指数加权移动平均(EWMA)
    - 基于规则：阈值 / 白名单 / 黑名单
    - 基于机器学习：孤立森林(Isolation Forest)

仅用于授权的安全监控与运营场景。
"""
import os
import json
import math
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# ----------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------
def _now() -> str:
    """返回当前时间 ISO 字符串"""
    return datetime.now().isoformat()


def _mean(values: List[float]) -> float:
    """计算均值"""
    return sum(values) / len(values) if values else 0.0


def _stdev(values: List[float]) -> float:
    """计算标准差（样本），样本不足时返回 1.0 避免除零"""
    if len(values) < 2:
        return 1.0
    m = _mean(values)
    var = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var) or 1.0


# ----------------------------------------------------------------------
# 纯 Python 孤立森林 (Isolation Forest)
# ----------------------------------------------------------------------
class _IsolationTree:
    """孤立树节点：叶子节点存储 size，内部节点存 split_feature / split_value"""

    def __init__(self):
        self.left = None
        self.right = None
        self.split_feature: int = -1
        self.split_value: float = 0.0
        self.size: int = 0          # 叶子样本数
        self.is_leaf: bool = False
        self.depth: int = 0


class IsolationForest:
    """纯 Python 孤立森林异常检测实现"""

    def __init__(self, n_trees: int = 10, max_samples: int = 256, seed: int = 42):
        self.n_trees = n_trees
        self.max_samples = max_samples
        self.trees: List[_IsolationTree] = []
        self._rng = random.Random(seed)
        self._max_depth: int = 0

    @staticmethod
    def _c_factor(n: int) -> float:
        """孤立森林中用于归一化路径长度的修正因子 c(n)"""
        if n <= 1:
            return 0.0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)

    def _build_tree(self, x: List[List[float]], depth: int) -> _IsolationTree:
        """递归构建孤立树"""
        node = _IsolationTree()
        node.depth = depth
        n = len(x)
        if n <= 1 or depth >= self._max_depth:
            node.is_leaf = True
            node.size = n
            return node

        dim = len(x[0])
        split_feature = self._rng.randint(0, dim - 1)
        col = [row[split_feature] for row in x]
        fmin, fmax = min(col), max(col)
        if fmax - fmin < 1e-9:
            node.is_leaf = True
            node.size = n
            return node

        split_value = self._rng.uniform(fmin, fmax)
        left = [row for row in x if row[split_feature] < split_value]
        right = [row for row in x if row[split_feature] >= split_value]
        node.split_feature = split_feature
        node.split_value = split_value
        node.left = self._build_tree(left, depth + 1)
        node.right = self._build_tree(right, depth + 1)
        return node

    def _path_length(self, row: List[float], node: _IsolationTree, depth: int = 0) -> float:
        """计算单样本在树上的路径长度"""
        if node.is_leaf:
            return depth + self._c_factor(node.size)
        if row[node.split_feature] < node.split_value:
            return self._path_length(row, node.left, depth + 1)
        return self._path_length(row, node.right, depth + 1)

    def fit(self, X: List[List[float]]) -> "IsolationForest":
        """训练孤立森林"""
        self.trees = []
        if not X:
            return self
        sample_size = min(self.max_samples, len(X))
        self._max_depth = int(math.ceil(math.log2(max(sample_size, 2))))
        for _ in range(self.n_trees):
            sample = self._rng.sample(X, sample_size) if len(X) > sample_size else list(X)
            self.trees.append(self._build_tree(sample, 0))
        return self

    def score_samples(self, X: List[List[float]]) -> List[float]:
        """返回每个样本的异常分数（0~1，越高越异常）"""
        if not X or not self.trees:
            return [0.0] * len(X)
        s = self._c_factor(min(self.max_samples, 1))
        results = []
        for row in X:
            avg_path = sum(self._path_length(row, t) for t in self.trees) / len(self.trees)
            # s = 2 ** (-E(h) / c(n))，接近 1 表示异常
            score = math.pow(2.0, -avg_path / s) if s > 0 else 0.0
            results.append(max(0.0, min(1.0, score)))
        return results


# ----------------------------------------------------------------------
# AI 异常检测器
# ----------------------------------------------------------------------
class AnomalyDetector:
    """AI 异常检测器：流量 / 行为 / 性能 / 日志四类异常检测"""

    def __init__(self):
        # 内存存储
        self._tasks: Dict[str, Dict[str, Any]] = {}          # task_id -> 任务状态与结果
        self._anomalies: Dict[str, List[Dict[str, Any]]] = {}  # task_id -> 异常列表
        self._baselines: Dict[str, Dict[str, Any]] = {}      # 基线
        # 规则库
        self._whitelist_ips = {"127.0.0.1", "10.0.0.1"}
        self._blacklist_ports = {23, 161, 4444, 1337}  # 常见高危/异常端口（防御视角观察）
        self._thresholds = {
            "cpu": 90.0,        # CPU 使用率阈值 %
            "memory": 85.0,     # 内存使用率阈值 %
            "disk": 90.0,       # 磁盘使用率阈值 %
            "error_rate": 5.0,  # 错误率阈值 %
        }
        # 数据持久化目录
        self._data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ai_soc", "anomaly"
        )
        os.makedirs(self._data_dir, exist_ok=True)

    # ---------------- 基线学习 ----------------
    def learn_baseline(self, historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于历史数据自动学习正常行为基线，并动态更新。

        :param historical_data: 历史数据，可包含 performance/traffic/log 等序列
        :return: 学习到的基线摘要
        """
        summary: Dict[str, Any] = {"learned_at": _now(), "series": {}}
        try:
            for key in ("performance", "traffic", "log"):
                series = historical_data.get(key, {})
                if isinstance(series, dict) and series:
                    stats: Dict[str, Dict[str, float]] = {}
                    for metric, values in series.items():
                        if isinstance(values, list) and values:
                            nums = [float(v) for v in values if isinstance(v, (int, float))]
                            if nums:
                                stats[metric] = {
                                    "mean": round(_mean(nums), 4),
                                    "stdev": round(_stdev(nums), 4),
                                    "min": round(min(nums), 4),
                                    "max": round(max(nums), 4),
                                    "ewma": round(self._ewma(nums), 4),
                                }
                    summary["series"][key] = stats
            self._baselines["default"] = summary
            self._save_baseline()
        except Exception as e:  # pragma: no cover - 防御性
            summary["error"] = str(e)
        return summary

    @staticmethod
    def _ewma(values: List[float], alpha: float = 0.3) -> float:
        """指数加权移动平均"""
        if not values:
            return 0.0
        e = values[0]
        for v in values[1:]:
            e = alpha * v + (1 - alpha) * e
        return e

    def _save_baseline(self) -> None:
        """持久化基线到 JSON 文件"""
        try:
            path = os.path.join(self._data_dir, "baselines.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._baselines, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ---------------- 主检测入口 ----------------
    def detect(self,
              traffic_data: Optional[Dict[str, Any]] = None,
              behavior_data: Optional[Dict[str, Any]] = None,
              performance_data: Optional[Dict[str, Any]] = None,
              log_data: Optional[Dict[str, Any]] = None) -> str:
        """
        启动异常检测，返回 task_id（检测同步执行并落库）。

        :return: task_id
        """
        task_id = "anom-" + uuid.uuid4().hex[:12]
        self._tasks[task_id] = {"status": "running", "created_at": _now(), "type": "anomaly_detect"}
        try:
            anomalies: List[Dict[str, Any]] = []
            if traffic_data:
                anomalies.extend(self._detect_traffic(traffic_data))
            if behavior_data:
                anomalies.extend(self._detect_behavior(behavior_data))
            if performance_data:
                anomalies.extend(self._detect_performance(performance_data))
            if log_data:
                anomalies.extend(self._detect_log(log_data))

            # 用孤立森林对量化特征做二次异常识别
            self._isolation_scan(anomalies)

            # 为每个异常评分
            for a in anomalies:
                a["score"] = self.get_anomaly_score(a)
                a["alert"] = self._build_alert(a)

            self._anomalies[task_id] = anomalies
            self._tasks[task_id] = {
                "status": "completed",
                "created_at": self._tasks[task_id]["created_at"],
                "completed_at": _now(),
                "total_anomalies": len(anomalies),
            }
        except Exception as e:  # pragma: no cover - 防御性
            self._tasks[task_id] = {"status": "failed", "error": str(e), "created_at": _now()}
            self._anomalies[task_id] = []
        return task_id

    # ---------------- 流量异常 ----------------
    def _detect_traffic(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        # 突发流量：与基线均值比较
        bandwidth = data.get("bandwidth", [])
        if isinstance(bandwidth, list) and len(bandwidth) >= 3:
            nums = [float(v) for v in bandwidth]
            m, s = _mean(nums[:-1]), _stdev(nums[:-1])
            latest = nums[-1]
            z = (latest - m) / s if s else 0.0
            if abs(z) > 3.0:
                results.append({
                    "category": "traffic",
                    "type": "traffic_spike",
                    "message": f"检测到突发流量，最新值{latest:.1f}偏离基线{z:.2f}个标准差",
                    "z_score": round(z, 2),
                    "value": latest,
                })
        # 异常端口
        for port in data.get("ports", []) or []:
            try:
                if int(port) in self._blacklist_ports:
                    results.append({
                        "category": "traffic",
                        "type": "abnormal_port",
                        "message": f"检测到连接异常/高危端口 {port}",
                        "port": int(port),
                    })
            except (TypeError, ValueError):
                continue
        # 异常协议（黑名单）
        proto = data.get("protocol", "")
        if isinstance(proto, str) and proto.lower() in {"unknown", "malformed"}:
            results.append({
                "category": "traffic",
                "type": "abnormal_protocol",
                "message": f"检测到异常协议: {proto}",
                "protocol": proto,
            })
        return results

    # ---------------- 行为异常 ----------------
    def _detect_behavior(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        # 异常登录时间
        login_hour = data.get("login_hour")
        if isinstance(login_hour, (int, float)) and (login_hour < 6 or login_hour > 22):
            results.append({
                "category": "behavior",
                "type": "abnormal_login_time",
                "message": f"检测到非工作时间登录 (hour={login_hour})",
                "login_hour": login_hour,
            })
        # 异常访问模式：白名单外 IP
        src_ip = data.get("source_ip", "")
        if src_ip and src_ip not in self._whitelist_ips:
            results.append({
                "category": "behavior",
                "type": "abnormal_access_pattern",
                "message": f"检测到白名单外来源访问: {src_ip}",
                "source_ip": src_ip,
            })
        # 异常操作序列（高频失败后成功）
        seq = data.get("operation_sequence", []) or []
        if isinstance(seq, list) and len(seq) >= 5:
            fails = sum(1 for s in seq if str(s).lower() in {"fail", "denied"})
            if fails >= 4 and str(seq[-1]).lower() in {"success", "ok"}:
                results.append({
                    "category": "behavior",
                    "type": "abnormal_sequence",
                    "message": f"检测到失败后成功的可疑操作序列 (失败{fails}次)",
                    "fail_count": fails,
                })
        return results

    # ---------------- 性能异常 ----------------
    def _detect_performance(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for metric in ("cpu", "memory", "disk", "network"):
            series = data.get(metric, [])
            if isinstance(series, list) and series:
                nums = [float(v) for v in series]
                latest = nums[-1]
                threshold = self._thresholds.get(metric, 90.0)
                # 阈值规则
                if latest >= threshold:
                    results.append({
                        "category": "performance",
                        "type": f"{metric}_threshold_breach",
                        "message": f"{metric.upper()} 使用率 {latest:.1f}% 超过阈值 {threshold}%",
                        "metric": metric,
                        "value": latest,
                    })
                # EWMA 趋势：最新值相对 EWMA 突增
                ewma = self._ewma(nums)
                if ewma > 0 and (latest - ewma) / ewma > 0.3:
                    results.append({
                        "category": "performance",
                        "type": f"{metric}_spike_ewma",
                        "message": f"{metric.upper()} 相对EWMA基线突增 {((latest-ewma)/ewma*100):.1f}%",
                        "metric": metric,
                        "value": latest,
                        "ewma": round(ewma, 2),
                    })
        return results

    # ---------------- 日志异常 ----------------
    def _detect_log(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        error_rate = data.get("error_rate")
        if isinstance(error_rate, (int, float)) and error_rate >= self._thresholds["error_rate"]:
            results.append({
                "category": "log",
                "type": "error_rate_surge",
                "message": f"错误率突增至 {error_rate:.1f}%，超过阈值 {self._thresholds['error_rate']}%",
                "error_rate": error_rate,
            })
        # 异常日志模式关键词
        suspicious_patterns = {
            "segfault": "段错误（疑似崩溃/漏洞利用）",
            "authentication failure": "大量认证失败",
            "sudo": "检测到 sudo 提权操作",
            "reverse shell": "检测到反向 shell 痕迹",
            "core dumped": "核心转储（疑似崩溃/利用）",
        }
        for line in data.get("lines", []) or []:
            low = str(line).lower()
            for pat, desc in suspicious_patterns.items():
                if pat in low:
                    results.append({
                        "category": "log",
                        "type": "abnormal_log_pattern",
                        "message": f"异常日志模式 [{pat}]: {desc}",
                        "pattern": pat,
                        "sample": str(line)[:200],
                    })
        return results

    # ---------------- 孤立森林二次扫描 ----------------
    def _isolation_scan(self, anomalies: List[Dict[str, Any]]) -> None:
        """若异常包含可量化特征，用孤立森林做离群点评分增强"""
        try:
            feat_map = {
                "traffic": "z_score", "performance": "value", "log": "error_rate",
                "behavior": "login_hour",
            }
            rows, idx = [], []
            for i, a in enumerate(anomalies):
                feat = feat_map.get(a.get("category"), "score")
                v = a.get(feat)
                if isinstance(v, (int, float)):
                    rows.append([float(v), float(len(a.get("type", "")))])
                    idx.append(i)
            if len(rows) >= 4:
                scores = IsolationForest(n_trees=8, max_samples=min(64, len(rows))).fit(rows).score_samples(rows)
                for i, s in zip(idx, scores):
                    anomalies[i]["iforest_score"] = round(s, 3)
        except Exception:
            pass

    # ---------------- 异常评分 ----------------
    def get_anomaly_score(self, anomaly: Dict[str, Any]) -> int:
        """
        计算单个异常的严重程度评分（0-100）。
        综合偏离程度 / 影响范围 / 持续时间。
        """
        score = 20.0
        cat = anomaly.get("category", "")
        # 偏离程度
        if "z_score" in anomaly:
            score += min(40.0, abs(anomaly["z_score"]) * 8.0)
        if "iforest_score" in anomaly:
            score += anomaly["iforest_score"] * 25.0
        # 类别权重
        weight = {"traffic": 15.0, "behavior": 20.0, "performance": 10.0, "log": 18.0}.get(cat, 10.0)
        score += weight
        # 高危类型加成
        if anomaly.get("type") in {"abnormal_port", "abnormal_sequence", "error_rate_surge"}:
            score += 15.0
        # 影响范围 / 持续时间（可选字段）
        score += min(10.0, float(anomaly.get("impact_scope", 0)))
        score += min(10.0, float(anomaly.get("duration", 0)) / 10.0)
        return int(max(0, min(100, round(score))))

    def _build_alert(self, anomaly: Dict[str, Any]) -> Dict[str, Any]:
        """根据异常生成告警/事件记录"""
        level = "critical" if anomaly["score"] >= 80 else "high" if anomaly["score"] >= 60 \
            else "medium" if anomaly["score"] >= 40 else "low"
        return {
            "alert_id": "alt-" + uuid.uuid4().hex[:8],
            "level": level,
            "message": anomaly.get("message", ""),
            "raised_at": _now(),
        }

    # ---------------- 任务状态 / 结果 ----------------
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """获取检测任务状态"""
        task = self._tasks.get(task_id, {})
        if not task:
            return {"task_id": task_id, "status": "not_found"}
        return {"task_id": task_id, **task}

    def get_results(self, task_id: str) -> List[Dict[str, Any]]:
        """获取异常检测结果列表"""
        return self._anomalies.get(task_id, [])

    # ---------------- 报告 ----------------
    def generate_report(self, task_id: str) -> Dict[str, Any]:
        """生成异常检测报告：异常列表 / 严重程度 / 时间线 / 影响分析 / 建议"""
        anomalies = self._anomalies.get(task_id, [])
        status = self._tasks.get(task_id, {})
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_dist: Dict[str, int] = {}
        timeline = []
        for a in anomalies:
            s = a.get("score", 0)
            level = "critical" if s >= 80 else "high" if s >= 60 else "medium" if s >= 40 else "low"
            severity_dist[level] += 1
            category_dist[a.get("category", "unknown")] = category_dist.get(a.get("category", "unknown"), 0) + 1
            timeline.append({"score": s, "type": a.get("type"), "message": a.get("message")})

        top = sorted(anomalies, key=lambda x: x.get("score", 0), reverse=True)[:5]
        return {
            "report_type": "anomaly_detection",
            "task_id": task_id,
            "generated_at": _now(),
            "task_status": status.get("status"),
            "summary": {
                "total_anomalies": len(anomalies),
                "severity_distribution": severity_dist,
                "category_distribution": category_dist,
            },
            "timeline": timeline,
            "impact_analysis": self._impact_analysis(anomalies),
            "top_anomalies": top,
            "recommendations": self._recommend(anomalies),
        }

    @staticmethod
    def _impact_analysis(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        cats = {a.get("category") for a in anomalies}
        affected = []
        mapping = {
            "traffic": "网络可用性与带宽",
            "behavior": "账号与访问安全",
            "performance": "系统服务稳定性",
            "log": "应用与业务健康度",
        }
        for c in cats:
            affected.append(mapping.get(c, "未知域"))
        return {"affected_domains": affected, "overall_risk": "high" if anomalies else "normal"}

    @staticmethod
    def _recommend(anomalies: List[Dict[str, Any]]) -> List[str]:
        recs = {
            "traffic": "检查网络流量基线，对异常端口/协议做封禁与溯源",
            "behavior": "核查异常登录与操作序列，必要时冻结可疑账号并开启 MFA",
            "performance": "排查资源瓶颈，扩容或优化高负载服务",
            "log": "定位错误突增根因，复核可疑日志模式对应的主机",
        }
        out = []
        for a in anomalies:
            r = recs.get(a.get("category"))
            if r and r not in out:
                out.append(r)
        return out or ["当前未发现明显异常，保持基线监控"]


# ---------------- 模块级单例 ----------------
_anomaly_detector_instance: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """获取 AnomalyDetector 单例"""
    global _anomaly_detector_instance
    if _anomaly_detector_instance is None:
        _anomaly_detector_instance = AnomalyDetector()
    return _anomaly_detector_instance


# 模块级单例实例
anomaly_detector: AnomalyDetector = get_anomaly_detector()
