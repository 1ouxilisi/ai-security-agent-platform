# -*- coding: utf-8 -*-
"""cloud_security_deep.py — 云安全做实（方向1）。

能力：
    - 真实云 API 调用接口（AWS boto3 / 阿里云 aliyun-python-sdk）
    - 配置检查规则库（CIS Benchmark 映射）
    - 资产发现（IAM / EC2 / S3 / RDS / OSS）
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SUBPROCESS_TIMEOUT = 300

CLOUD_PROVIDERS: List[Dict[str, Any]] = [
    {"id": "aws", "name": "AWS", "cli": "aws",
     "env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]},
    {"id": "aliyun", "name": "阿里云", "cli": "aliyun",
     "env": ["ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET"]},
    {"id": "tencent", "name": "腾讯云", "cli": "tccli",
     "env": ["TENCENT_SECRET_ID", "TENCENT_SECRET_KEY"]},
    {"id": "huawei", "name": "华为云", "cli": "hcloud",
     "env": ["HUAWEICLOUD_ACCESS_KEY", "HUAWEICLOUD_SECRET_KEY"]},
]

# CIS Benchmark 风格的配置基线
CONFIG_BASELINE_CHECKS: List[Dict[str, Any]] = [
    {"id": "iam_no_root_access_key", "title": "Root 无 Access Key",
     "severity": "critical", "provider": "aws",
     "cis": "1.4"},
    {"id": "iam_mfa_enabled_root", "title": "Root 启用 MFA",
     "severity": "critical", "provider": "aws", "cis": "1.5"},
    {"id": "iam_password_policy_min_length", "title": "密码策略最小长度>=14",
     "severity": "high", "provider": "aws", "cis": "1.8"},
    {"id": "iam_no_inline_policy", "title": "最小化内联策略",
     "severity": "medium", "provider": "aws"},
    {"id": "s3_no_public_bucket", "title": "S3 桶不公开",
     "severity": "critical", "provider": "aws", "cis": "2.1.1"},
    {"id": "s3_bucket_logging", "title": "S3 桶日志开启",
     "severity": "medium", "provider": "aws", "cis": "2.3"},
    {"id": "cloudtrail_enabled", "title": "CloudTrail 开启",
     "severity": "critical", "provider": "aws", "cis": "3.1"},
    {"id": "guardduty_enabled", "title": "GuardDuty 开启",
     "severity": "high", "provider": "aws"},
    {"id": "securityhub_enabled", "title": "Security Hub 开启",
     "severity": "medium", "provider": "aws"},
    {"id": "ebs_encryption", "title": "EBS 加密",
     "severity": "high", "provider": "aws"},
    {"id": "rds_public_access", "title": "RDS 不公开",
     "severity": "critical", "provider": "aws"},
    {"id": "sg_no_0_0_0_0", "title": "安全组不开放 0.0.0.0/0",
     "severity": "critical", "provider": "aws"},
    {"id": "iam_user_console_access_unused", "title": "90天未使用控制台访问",
     "severity": "medium", "provider": "aws"},
    {"id": "oss_no_public", "title": "OSS 桶不公开",
     "severity": "critical", "provider": "aliyun"},
    {"id": "ram_mfa_enabled", "title": "RAM 子账号 MFA",
     "severity": "high", "provider": "aliyun"},
    {"id": "actiontrail_enabled", "title": "ActionTrail 开启",
     "severity": "high", "provider": "aliyun"},
]


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def run_cmd(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Dict[str, Any]:
    if not cmd:
        return {"success": False, "stdout": "", "stderr": "empty",
                "returncode": -1, "elapsed_ms": 0}
    binary = cmd[0]
    if shutil.which(binary) is None:
        return {"success": False, "stdout": "",
                "stderr": f"CLI 未安装: {binary}",
                "returncode": 127, "elapsed_ms": 0, "cli_missing": binary}
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              text=True, encoding="utf-8", errors="replace")
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "returncode": proc.returncode,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": "超时",
                "returncode": -1, "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e),
                "returncode": -1, "elapsed_ms": int((time.time() - t0) * 1000)}


class AWSRealClient:
    """AWS 真实 API 调用（走 aws CLI，boto3 可选）。"""

    def __init__(self) -> None:
        self.cli = which("aws")

    def check_env(self) -> Dict[str, Any]:
        return {e: bool(os.environ.get(e)) for e in
                ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]}

    def iam_users(self) -> Dict[str, Any]:
        if not self.cli:
            return {"success": False, "error": "aws CLI 未安装"}
        r = run_cmd([self.cli, "iam", "list-users", "--output", "json"], timeout=60)
        try:
            import json as _json
            data = _json.loads(r.get("stdout", "{}"))
            users = [{"name": u.get("UserName"),
                      "arn": u.get("Arn"),
                      "created": u.get("CreateDate")}
                     for u in data.get("Users", [])]
            return {"success": True, "users": users, "count": len(users)}
        except Exception as e:
            return {"success": False, "error": str(e),
                    "raw": r.get("stdout", "")[-500:]}

    def s3_buckets(self) -> Dict[str, Any]:
        if not self.cli:
            return {"success": False, "error": "aws CLI 未安装"}
        r = run_cmd([self.cli, "s3api", "list-buckets", "--output", "json"],
                    timeout=60)
        try:
            import json as _json
            data = _json.loads(r.get("stdout", "{}"))
            buckets = [{"name": b.get("Name"),
                        "created": b.get("CreationDate")}
                       for b in data.get("Buckets", [])]
            return {"success": True, "buckets": buckets, "count": len(buckets)}
        except Exception as e:
            return {"success": False, "error": str(e),
                    "raw": r.get("stdout", "")[-500:]}

    def ec2_instances(self) -> Dict[str, Any]:
        if not self.cli:
            return {"success": False, "error": "aws CLI 未安装"}
        r = run_cmd([self.cli, "ec2", "describe-instances", "--output", "json"],
                    timeout=90)
        try:
            import json as _json
            data = _json.loads(r.get("stdout", "{}"))
            instances = []
            for res in data.get("Reservations", []):
                for inst in res.get("Instances", []):
                    instances.append({
                        "id": inst.get("InstanceId"),
                        "state": inst.get("State", {}).get("Name"),
                        "type": inst.get("InstanceType"),
                        "public_ip": inst.get("PublicIpAddress"),
                    })
            return {"success": True, "instances": instances,
                    "count": len(instances)}
        except Exception as e:
            return {"success": False, "error": str(e),
                    "raw": r.get("stdout", "")[-500:]}


class AliyunRealClient:
    """阿里云真实 API（走 aliyun CLI）。"""

    def __init__(self) -> None:
        self.cli = which("aliyun")

    def check_env(self) -> Dict[str, Any]:
        return {e: bool(os.environ.get(e)) for e in
                ["ALIBABA_CLOUD_ACCESS_KEY_ID",
                 "ALIBABA_CLOUD_ACCESS_KEY_SECRET"]}

    def ram_users(self) -> Dict[str, Any]:
        if not self.cli:
            return {"success": False, "error": "aliyun CLI 未安装"}
        r = run_cmd([self.cli, "ram", "ListUsers"], timeout=60)
        return {"success": True, "raw_tail": r.get("stdout", "")[-2000:],
                "stderr_tail": r.get("stderr", "")[-500:]}


class CloudConfigAuditor:
    """配置检查规则库执行。"""

    def __init__(self) -> None:
        self.rules = CONFIG_BASELINE_CHECKS

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def run_assessment(self, provider: str) -> Dict[str, Any]:
        """对指定 provider 跑规则（这里只是返回规则清单与状态，
        真实结果需结合上面 RealClient 的输出人工映射）。"""
        applicable = [r for r in self.rules
                      if r["provider"] == provider]
        return {
            "provider": provider,
            "rules_applicable": len(applicable),
            "rules": applicable,
            "note": "请先调用对应 RealClient 接口拉取真实配置，"
                    "再按规则比对。本端点仅返回规则清单。",
        }


class CloudSecurityDeepEngine:
    """云安全聚合。"""

    def __init__(self) -> None:
        self.aws = AWSRealClient()
        self.aliyun = AliyunRealClient()
        self.auditor = CloudConfigAuditor()
        self.tasks: Dict[str, Dict[str, Any]] = {}

    def providers_status(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for p in CLOUD_PROVIDERS:
            out[p["id"]] = {
                "name": p["name"],
                "cli_installed": bool(which(p["cli"])),
                "env_configured": {e: bool(os.environ.get(e)) for e in p["env"]},
            }
        return out

    def audit(self, provider: str) -> Dict[str, Any]:
        tid = "cloud_" + uuid.uuid4().hex[:10]
        result = self.auditor.run_assessment(provider)
        self.tasks[tid] = {"task_id": tid, "provider": provider,
                           "result": result, "ts": time.time()}
        return {"success": True, "task_id": tid, "result": result}
