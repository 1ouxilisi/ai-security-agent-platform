#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ml_anomaly.py — 机器学习异常检测模块
=====================================

功能：
    1. 异常检测算法：孤立森林 / One-Class SVM / 自编码器 / LOF / DBSCAN / 统计方法 / 时序异常 / 季节性异常
    2. 模型训练：特征工程 / 特征选择 / 数据预处理 / 模型训练 / 验证 / 调优 / 版本管理
    3. 模型推理：实时 / 批量 / 流式推理、置信度、异常分数、异常类型
    4. 模型监控：性能监控 / 数据漂移 / 概念漂移 / 模型衰减 / 重训练触发 / A/B 测试
    5. 异常分类：已知/未知/新型/复合/持续/瞬时/周期性异常
    6. 异常解释：原因分析 / 特征解释 / 影响评估 / 关联分析 / SHAP / LIME

全部内存字典模拟，scikit-learn/numpy 可选导入。
"""
from __future__ import annotations

import math
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np  # type: ignore
    _HAS_NUMPY = True
except Exception:
    _HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest  # type: ignore
    from sklearn.svm import OneClassSVM  # type: ignore
    from sklearn.neighbors import LocalOutlierFactor  # type: ignore
    from sklearn.cluster import DBSCAN  # type: ignore
    from sklearn.preprocessing import StandardScaler  # type: ignore
    _HAS_SKLEARN = True
except Exception:
    _HAS_SKLEARN = False


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ==================== 模型定义 ====================

_ALGORITHMS = [
    {"id": "isolation_forest", "name": "孤立森林", "category": "树模型",
     "description": "高效高维异常检测，适合大量日志/指标数据",
     "params": {"n_estimators": 100, "contamination": 0.1, "max_samples": "auto"}},
    {"id": "one_class_svm", "name": "One-Class SVM", "category": "核方法",
     "description": "单类支持向量机，适合小样本边界学习",
     "params": {"kernel": "rbf", "gamma": "scale", "nu": 0.05}},
    {"id": "autoencoder", "name": "自编码器", "category": "深度学习",
     "description": "重构误差检测异常，适合序列和高维数据",
     "params": {"latent_dim": 16, "epochs": 50, "batch_size": 32}},
    {"id": "lof", "name": "局部离群因子 LOF", "category": "密度方法",
     "description": "基于局部密度的异常检测，适合空间聚类",
     "params": {"n_neighbors": 20, "contamination": 0.1}},
    {"id": "dbscan", "name": "DBSCAN 聚类", "category": "聚类方法",
     "description": "基于密度的噪声应用空间聚类",
     "params": {"eps": 0.5, "min_samples": 5}},
    {"id": "zscore", "name": "Z-Score 统计", "category": "统计方法",
     "description": "标准分数偏离检测，适合单指标时序",
     "params": {"threshold": 3.0, "window": 100}},
    {"id": "seasonal_decomp", "name": "季节性分解", "category": "时序方法",
     "description": "STL 分解去除趋势/季节后的残差异常",
     "params": {"period": 24, "threshold": 2.5}},
    {"id": "ewma", "name": "EWMA 控制图", "category": "时序方法",
     "description": "指数加权移动平均控制图，渐进式偏移检测",
     "params": {"lambda_": 0.2, "threshold": 3.0}},
]


def _gen_training_data(n: int = 200, n_features: int = 8) -> List[List[float]]:
    """生成模拟训练数据（正常样本）。"""
    data = []
    for _ in range(n):
        row = [random.gauss(0, 1) for _ in range(n_features)]
        data.append(row)
    return data


# ==================== ML 异常检测引擎 ====================

class MLAnomalyDetector:
    """机器学习异常检测引擎。"""

    def __init__(self) -> None:
        self.algorithms: List[Dict[str, Any]] = _ALGORITHMS
        self.models: Dict[str, Dict[str, Any]] = {}
        self.inference_logs: List[Dict[str, Any]] = []
        self.drift_reports: List[Dict[str, Any]] = []
        self.anomalies: List[Dict[str, Any]] = []
        self.explanations: List[Dict[str, Any]] = []
        self._init_default_models()

    def _init_default_models(self) -> None:
        """初始化默认模型实例。"""
        for algo in _ALGORITHMS:
            mid = f"model-{algo['id']}-v1"
            self.models[mid] = {
                "model_id": mid,
                "algorithm_id": algo["id"],
                "algorithm_name": algo["name"],
                "version": "v1",
                "status": "trained",
                "params": dict(algo["params"]),
                "feature_count": 8,
                "train_samples": 200,
                "train_accuracy": round(random.uniform(0.85, 0.97), 4),
                "precision": round(random.uniform(0.80, 0.95), 4),
                "recall": round(random.uniform(0.75, 0.92), 4),
                "f1_score": round(random.uniform(0.78, 0.93), 4),
                "created_at": _now(),
                "last_trained": _now(),
                "train_duration_sec": round(random.uniform(2.5, 45.0), 1),
                "drift_score": round(random.uniform(0.0, 0.15), 4),
                "predictions_made": 0,
                "anomalies_detected": 0,
            }

    # ---------- 模型训练 ----------

    def train_model(self, algorithm_id: str, custom_params: Optional[Dict[str, Any]] = None,
                    n_samples: int = 500) -> Dict[str, Any]:
        """训练新模型。"""
        algo = next((a for a in self.algorithms if a["id"] == algorithm_id), None)
        if not algo:
            return {"error": f"算法 {algorithm_id} 不存在"}

        version = f"v{len([m for m in self.models.values() if m['algorithm_id'] == algorithm_id]) + 1}"
        mid = f"model-{algorithm_id}-{version}"
        t0 = datetime.now()

        # 模拟训练
        train_data = _gen_training_data(n_samples)
        accuracy = round(random.uniform(0.82, 0.98), 4)
        duration = round((datetime.now() - t0).total_seconds() + random.uniform(1.0, 30.0), 1)

        model_info = {
            "model_id": mid,
            "algorithm_id": algorithm_id,
            "algorithm_name": algo["name"],
            "category": algo["category"],
            "version": version,
            "status": "trained",
            "params": {**algo["params"], **(custom_params or {})},
            "feature_count": 8,
            "train_samples": n_samples,
            "train_accuracy": accuracy,
            "precision": round(accuracy * random.uniform(0.95, 1.0), 4),
            "recall": round(accuracy * random.uniform(0.88, 0.98), 4),
            "f1_score": round(accuracy * random.uniform(0.90, 0.96), 4),
            "created_at": _now(),
            "last_trained": _now(),
            "train_duration_sec": duration,
            "drift_score": 0.0,
            "predictions_made": 0,
            "anomalies_detected": 0,
            "training_data_shape": [n_samples, 8],
            "feature_importance": self._simulate_feature_importance(),
        }
        self.models[mid] = model_info
        return model_info

    def _simulate_feature_importance(self) -> List[Dict[str, Any]]:
        features = ["登录频率", "数据访问量", "网络流出", "CPU使用率", "登录时间", "会话时长", "失败次数", "权限变更"]
        return [{"feature": f, "importance": round(random.uniform(0.05, 0.25), 4)} for f in features]

    # ---------- 模型推理 ----------

    def infer(self, model_id: str, features: List[float]) -> Dict[str, Any]:
        """单条实时推理。"""
        model = self.models.get(model_id)
        if not model:
            return {"error": f"模型 {model_id} 不存在"}

        # 模拟推理分数
        anomaly_score = round(random.uniform(0.0, 1.0), 4)
        threshold = 0.7
        is_anomaly = anomaly_score > threshold
        confidence = round(random.uniform(0.65, 0.98), 4)

        result = {
            "model_id": model_id,
            "algorithm": model["algorithm_name"],
            "features": features,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "threshold": threshold,
            "confidence": confidence,
            "anomaly_type": self._classify_anomaly(anomaly_score, confidence),
            "latency_ms": round(random.uniform(0.5, 5.0), 2),
            "timestamp": _now(),
        }

        model["predictions_made"] += 1
        if is_anomaly:
            model["anomalies_detected"] += 1
            self._record_anomaly(result)

        self.inference_logs.append(result)
        return result

    def infer_batch(self, model_id: str, batch: List[List[float]]) -> Dict[str, Any]:
        """批量推理。"""
        results = [self.infer(model_id, row) for row in batch]
        anomalies = [r for r in results if r.get("is_anomaly")]
        return {
            "model_id": model_id,
            "batch_size": len(batch),
            "total_processed": len(results),
            "anomalies_found": len(anomalies),
            "anomaly_rate": round(len(anomalies) / max(len(results), 1), 4),
            "avg_score": round(sum(r["anomaly_score"] for r in results) / max(len(results), 1), 4),
            "results": anomalies[:20],
            "timestamp": _now(),
        }

    # ---------- 异常分类 ----------

    def _classify_anomaly(self, score: float, confidence: float) -> str:
        if score > 0.9:
            return "持续性异常"
        if score > 0.8:
            return "新型异常" if confidence > 0.85 else "未知异常"
        if score > 0.7:
            return "瞬时异常"
        return "正常"

    def _record_anomaly(self, result: Dict[str, Any]) -> None:
        """记录异常事件。"""
        anomaly = {
            "anomaly_id": f"ANM-{uuid.uuid4().hex[:8].upper()}",
            "model_id": result["model_id"],
            "algorithm": result["algorithm"],
            "score": result["anomaly_score"],
            "confidence": result["confidence"],
            "type": result["anomaly_type"],
            "features": result["features"],
            "timestamp": _now(),
            "status": "detected",
        }
        self.anomalies.append(anomaly)

    # ---------- 异常解释 ----------

    def explain_anomaly(self, anomaly_id: str) -> Dict[str, Any]:
        """异常原因分析与特征解释（模拟 SHAP/LIME）。"""
        anomaly = next((a for a in self.anomalies if a["anomaly_id"] == anomaly_id), None)
        if not anomaly:
            return {"error": f"异常 {anomaly_id} 不存在"}

        features = ["登录频率", "数据访问量", "网络流出", "CPU使用率", "登录时间", "会话时长", "失败次数", "权限变更"]
        shap_values = []
        for f in features:
            shap_values.append({
                "feature": f,
                "shap_value": round(random.uniform(-0.5, 0.8), 4),
                "direction": "increase" if random.random() > 0.5 else "decrease",
                "contribution": round(random.uniform(0.05, 0.35), 4),
            })
        shap_values.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

        explanation = {
            "anomaly_id": anomaly_id,
            "method": "SHAP(simulated) + LIME(simulated)",
            "top_contributing_features": shap_values[:5],
            "root_cause": shap_values[0]["feature"] if shap_values else "未知",
            "impact_assessment": {
                "scope": random.choice(["用户级", "部门级", "系统级", "全网级"]),
                "severity": random.choice(["低", "中", "高", "严重"]),
                "estimated_business_impact": random.choice(["无明显影响", "局部中断", "数据泄露风险", "业务降级"]),
            },
            "related_events": random.randint(1, 15),
            "explainability_score": round(random.uniform(0.7, 0.95), 4),
            "timestamp": _now(),
        }
        self.explanations.append(explanation)
        return explanation

    # ---------- 模型监控 ----------

    def check_drift(self, model_id: str) -> Dict[str, Any]:
        """检测数据漂移和概念漂移。"""
        model = self.models.get(model_id)
        if not model:
            return {"error": f"模型 {model_id} 不存在"}

        data_drift = round(random.uniform(0.0, 0.4), 4)
        concept_drift = round(random.uniform(0.0, 0.3), 4)
        drift_detected = data_drift > 0.2 or concept_drift > 0.2

        report = {
            "model_id": model_id,
            "algorithm": model["algorithm_name"],
            "data_drift_score": data_drift,
            "concept_drift_score": concept_drift,
            "drift_detected": drift_detected,
            "drift_type": "数据漂移" if data_drift > 0.2 else ("概念漂移" if concept_drift > 0.2 else "无显著漂移"),
            "psi": round(random.uniform(0.0, 0.5), 4),  # Population Stability Index
            "ks_statistic": round(random.uniform(0.0, 0.3), 4),
            "retrain_recommended": drift_detected or model.get("predictions_made", 0) > 1000,
            "recommendation": "建议重新训练模型" if drift_detected else "模型状态良好",
            "timestamp": _now(),
        }
        model["drift_score"] = max(data_drift, concept_drift)
        self.drift_reports.append(report)
        return report

    def model_ab_test(self, model_a: str, model_b: str) -> Dict[str, Any]:
        """模型 A/B 测试。"""
        ma = self.models.get(model_a)
        mb = self.models.get(model_b)
        if not ma or not mb:
            return {"error": "模型不存在"}

        return {
            "model_a": {"id": model_a, "f1": ma["f1_score"], "precision": ma["precision"], "recall": ma["recall"]},
            "model_b": {"id": model_b, "f1": mb["f1_score"], "precision": mb["precision"], "recall": mb["recall"]},
            "winner": model_a if ma["f1_score"] > mb["f1_score"] else model_b,
            "confidence": round(random.uniform(0.75, 0.95), 4),
            "sample_size": 1000,
            "timestamp": _now(),
        }

    # ---------- 概览 ----------

    def overview(self) -> Dict[str, Any]:
        """ML 异常检测总览。"""
        total_models = len(self.models)
        anomalies_by_type: Dict[str, int] = {}
        for a in self.anomalies:
            anomalies_by_type[a["type"]] = anomalies_by_type.get(a["type"], 0) + 1

        return {
            "total_models": total_models,
            "trained_models": len([m for m in self.models.values() if m["status"] == "trained"]),
            "algorithms_available": len(self.algorithms),
            "total_anomalies": len(self.anomalies),
            "anomalies_by_type": anomalies_by_type,
            "total_inferences": sum(m["predictions_made"] for m in self.models.values()),
            "avg_drift_score": round(sum(m["drift_score"] for m in self.models.values()) / max(total_models, 1), 4),
            "drift_alerts": len([r for r in self.drift_reports if r["drift_detected"]]),
            "explained_anomalies": len(self.explanations),
            "sklearn_available": _HAS_SKLEARN,
            "numpy_available": _HAS_NUMPY,
        }


# 单例
ml_anomaly = MLAnomalyDetector()
