# -*- coding: utf-8 -*-
"""
cloud_client.py — 统一云 API 客户端框架（方向4）。

支持：
    - AWS：boto3（EC2 / S3 / IAM / CloudTrail）
    - 阿里云：aliyun SDK（若已安装）

未配置凭证时返回明确错误，不 mock 数据。
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional


class CloudClientError(RuntimeError):
    """云客户端错误。"""


class CloudClient:
    """统一云客户端。"""

    PROVIDERS = ("aws", "aliyun")

    def __init__(self, provider: str = "aws",
                 region: str = "",
                 access_key: str = "",
                 secret_key: str = "",
                 session_token: str = "") -> None:
        if provider not in self.PROVIDERS:
            raise CloudClientError(f"不支持的云厂商: {provider}")
        self.provider = provider
        self.region = region or os.getenv("AWS_DEFAULT_REGION",
                                           "cn-north-1")
        self.access_key = access_key or os.getenv("AWS_ACCESS_KEY_ID", "")
        self.secret_key = secret_key or os.getenv("AWS_SECRET_ACCESS_KEY", "")
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN", "")
        self._sessions: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # 健康检查
    # ------------------------------------------------------------------ #
    def describe(self) -> Dict[str, Any]:
        cred_ok = bool(self.access_key and self.secret_key)
        return {
            "provider": self.provider,
            "region": self.region,
            "credentials_present": cred_ok,
            "boto3_available": self._boto3_available(),
            "aliyun_sdk_available": self._aliyun_sdk_available(),
            "ready": cred_ok and self._boto3_available(),
            "hint": (
                "请设置环境变量 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / "
                "AWS_DEFAULT_REGION（阿里云则 ALIBABA_CLOUD_ACCESS_KEY_ID 等）"
            ),
        }

    @staticmethod
    def _boto3_available() -> bool:
        try:
            import boto3  # noqa: F401
            return True
        except Exception:
            return False

    @staticmethod
    def _aliyun_sdk_available() -> bool:
        try:
            import aliyunsdkcore  # noqa: F401
            return True
        except Exception:
            try:
                import alibabacloud_ecs20140526  # noqa: F401
                return True
            except Exception:
                return False

    # ------------------------------------------------------------------ #
    # AWS session
    # ------------------------------------------------------------------ #
    def aws_client(self, service: str) -> Any:
        if self.provider != "aws":
            raise CloudClientError("当前 provider 非 aws")
        if not self._boto3_available():
            raise CloudClientError(
                "boto3 未安装。请执行: pip install boto3")
        if not (self.access_key and self.secret_key):
            raise CloudClientError("AWS 凭证未配置（环境变量缺失）")
        import boto3  # type: ignore
        return boto3.client(
            service,
            region_name=self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token or None,
        )

    # ------------------------------------------------------------------ #
    # AWS 调用包装（真实 API）
    # ------------------------------------------------------------------ #
    def aws_call(self, service: str, api: str,
                 **kwargs: Any) -> Dict[str, Any]:
        try:
            client = self.aws_client(service)
            fn = getattr(client, api)
            resp = fn(**kwargs)
            # boto3 响应里的 datetime 转字符串
            return {"ok": True, "response": self._jsonify(resp)}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ------------------------------------------------------------------ #
    # 阿里云（占位：检测 SDK，未实现具体 API 时返回明确提示）
    # ------------------------------------------------------------------ #
    def aliyun_call(self, service: str, api: str,
                    **kwargs: Any) -> Dict[str, Any]:
        if self.provider != "aliyun":
            raise CloudClientError("当前 provider 非 aliyun")
        if not self._aliyun_sdk_available():
            return {
                "ok": False,
                "error": (
                    "阿里云 SDK 未安装。请执行: "
                    "pip install aliyun-python-sdk-core "
                    "aliyun-python-sdk-ecs aliyun-python-sdk-oss"
                ),
            }
        return {
            "ok": False,
            "error": (
                f"阿里云 {service}.{api} 调用尚未在 cloud_deep 中实现，"
                "请直接使用 aliyun SDK"
            ),
        }

    # ------------------------------------------------------------------ #
    @classmethod
    def _jsonify(cls, obj: Any) -> Any:
        import datetime
        if isinstance(obj, dict):
            return {k: cls._jsonify(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [cls._jsonify(i) for i in obj]
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        if hasattr(obj, "serialize"):
            try:
                return cls._jsonify(obj.serialize())
            except Exception:
                pass
        return obj
