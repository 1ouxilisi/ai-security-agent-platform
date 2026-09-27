# -*- coding: utf-8 -*-
"""
aliyun_security_check.py — 真实阿里云安全检查（阿里云 SDK 真实调用，不 mock）。

覆盖服务:
    RAM / OSS / ECS / RDS / VPC / ActionTrail

前置:
    - 未安装 SDK -> 明确提示 pip install aliyun-python-sdk-...
    - 未配置凭证 -> 明确提示环境变量
    - 已配置     -> 真实调用并逐条评估
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ._base import Finding, CheckReport, not_ready_report, safe_call


INSTALL_HINT = (
    "pip install aliyun-python-sdk-core aliyun-python-sdk-ram "
    "aliyun-python-sdk-oss aliyun-python-sdk-ecs aliyun-python-sdk-rds "
    "aliyun-python-sdk-vpc aliyun-python-sdk-actiontrail oss2")
CONFIG_HINT = ("配置: 环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID / "
               "ALIBABA_CLOUD_ACCESS_KEY_SECRET / ALIBABA_CLOUD_REGION_ID")


def detect_aliyun_status() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "provider": "aliyun", "sdk_installed": False,
        "credentials_configured": False,
        "region": os.environ.get("ALIBABA_CLOUD_REGION_ID", "cn-hangzhou"),
        "hint": "", "account_identity": None,
    }
    try:
        from aliyunsdkcore.client import AcsClient  # noqa: F401
        out["sdk_installed"] = True
    except Exception:  # noqa: BLE001
        out["hint"] = f"未安装阿里云 SDK。请执行: {INSTALL_HINT}"
        return out

    ak = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID") or os.environ.get(
        "ALIBABA_ACCESS_KEY_ID")
    sk = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET") or os.environ.get(
        "ALIBABA_ACCESS_KEY_SECRET")
    if not ak or not sk:
        out["hint"] = (
            "阿里云凭证未配置。请设置环境变量 "
            "ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET "
            "/ ALIBABA_CLOUD_REGION_ID。建议使用只读 RAM 子账号。")
        return out
    out["credentials_configured"] = True
    out["account_identity"] = {"access_key_id": ak[:6] + "****"}
    out["hint"] = "阿里云凭证已就绪，发起真实调用。"
    return out


class AliyunSecurityChecker:
    """真实阿里云安全检查器。"""

    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017}

    def __init__(self, region: Optional[str] = None) -> None:
        self._region = region or os.environ.get(
            "ALIBABA_CLOUD_REGION_ID", "cn-hangzhou")
        self._client = None

    def _acs(self):
        if self._client is None:
            from aliyunsdkcore.client import AcsClient
            ak = (os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID")
                  or os.environ["ALIBABA_ACCESS_KEY_ID"])
            sk = (os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
                  or os.environ["ALIBABA_ACCESS_KEY_SECRET"])
            self._client = AcsClient(ak, sk, self._region)
        return self._client

    # ------------------------------------------------------------------ #
    def run(self, services: Optional[List[str]] = None) -> Dict[str, Any]:
        status = detect_aliyun_status()
        want = services or ["ram", "oss", "ecs", "rds", "vpc", "actiontrail"]
        reports: Dict[str, CheckReport] = {}
        if not status["sdk_installed"]:
            for svc in want:
                reports[svc] = not_ready_report("aliyun", svc,
                    status["hint"], sdk_installed=False)
            return self._assemble(reports, status)
        if not status["credentials_configured"]:
            for svc in want:
                reports[svc] = not_ready_report("aliyun", svc,
                    status["hint"], credentials_configured=False)
            return self._assemble(reports, status)

        runners = {"ram": self.check_ram, "oss": self.check_oss,
                   "ecs": self.check_ecs, "rds": self.check_rds,
                   "vpc": self.check_vpc,
                   "actiontrail": self.check_actiontrail}
        for svc in want:
            fn = runners.get(svc)
            if fn is None:
                continue
            try:
                reports[svc] = fn()
            except Exception as e:  # noqa: BLE001
                r = CheckReport(provider="aliyun", service=svc,
                                account_identity=status["account_identity"])
                r.errors.append(f"{type(e).__name__}: {e}")
                r.add(Finding(check_id=f"{svc}.error", service=svc,
                              title=f"{svc} 检查失败",
                              actual=f"{type(e).__name__}: {e}",
                              status="error", severity="medium"))
                reports[svc] = r
        return self._assemble(reports, status)

    def _assemble(self, reports: Dict[str, CheckReport],
                  status: Dict[str, Any]) -> Dict[str, Any]:
        merged: List[Finding] = []
        by_service: Dict[str, Any] = {}
        for svc, r in reports.items():
            r.account_identity = status.get("account_identity") or {}
            by_service[svc] = r.summary()
            merged.extend(r.findings)
        agg = CheckReport(provider="aliyun", service="aliyun")
        agg.findings = merged
        return {"provider": "aliyun", "credential_status": status,
                "by_service": by_service,
                "summary": agg.summary(),
                "findings": [f.to_dict() for f in merged]}

    def _do(self, request_cls, **params):
        """构造并发起一个 RPC 请求，返回 (ok, result|err)。"""
        req = request_cls()
        req.set_accept_format("json")
        for k, v in params.items():
            getattr(req, f"set_{k}")(v)
        return safe_call(self._acs().do_action, req)

    # ================================================================== #
    # RAM
    # ================================================================== #
    def check_ram(self) -> CheckReport:
        r = CheckReport(provider="aliyun", service="ram")
        try:
            from aliyunsdkram.request.v20150501 import (
                ListUsersRequest, GetPasswordPolicyRequest,
                ListAccessKeysRequest)
            ok, users = self._do(ListUsersRequest())
            if not ok:
                raise RuntimeError(str(users))
            ulist = (users or {}).get("User", [])
            r.add(Finding("ram.user_count", "ram",
                f"RAM 用户数 {len(ulist)}",
                "枚举 RAM 用户", "ram.ListUsers",
                "成功", f"{len(ulist)} 个", "pass", "info"))
            # 密码策略
            okp, pol = self._do(GetPasswordPolicyRequest())
            if okp:
                pp = (pol or {}).get("PasswordPolicy", {})
                if pp.get("MinimumPasswordLength", 0) < 12:
                    r.add(Finding("ram.pwd_length", "ram",
                        "RAM 密码长度不足", ">=12",
                        "GetPasswordPolicy", ">=12",
                        str(pp.get("MinimumPasswordLength", 0)),
                        "fail", "high",
                        remediation="将最小密码长度提升到 12"))
                if not pp.get("RequireNumbers") or not pp.get("RequireSymbols"):
                    r.add(Finding("ram.pwd_complexity", "ram",
                        "RAM 密码复杂度不足",
                        "要求数字与符号", "GetPasswordPolicy",
                        "RequireNumbers/RequireSymbols 开启",
                        f"数字={pp.get('RequireNumbers')} 符号={pp.get('RequireSymbols')}",
                        "fail", "medium",
                        remediation="启用数字与符号复杂度要求"))
            for u in ulist[:100]:
                uname = u.get("UserName")
                okak, aks = self._do(ListAccessKeysRequest(), UserName=uname)
                if okak:
                    for k in (aks or {}).get("AccessKey", {}).get(
                            "AccessKey", []):
                        if k.get("Status") == "Active":
                            r.add(Finding(f"ram.ak_active.{uname}", "ram",
                                f"RAM 用户 {uname} 存在活跃 AccessKey",
                                "建议优先 RAM 角色而非长期 AK",
                                "ListAccessKeys",
                                "尽量使用 STS 临时凭证",
                                f"AK {k.get('AccessKeyId','')[:8]}**** 活跃",
                                "fail", "low",
                                remediation="定期轮换 AK 并限制来源 IP"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("ram.error", "ram", "RAM 检查失败",
                "ram client", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r

    # ================================================================== #
    # OSS
    # ================================================================== #
    def check_oss(self) -> CheckReport:
        r = CheckReport(provider="aliyun", service="oss")
        try:
            import oss2
            ak = (os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID")
                  or os.environ["ALIBABA_ACCESS_KEY_ID"])
            sk = (os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
                  or os.environ["ALIBABA_ACCESS_KEY_SECRET"])
            auth = oss2.Auth(ak, sk)
            # 列举所有 region 的桶较繁琐，这里枚举当前 region 与常用 region
            endpoints = [f"https://oss-{self._region}.aliyuncs.com"]
            seen = set()
            for ep in endpoints:
                serv = oss2.Service(auth, ep)
                for info in oss2.ObjectIteratorV2(serv):
                    bname = info.key if hasattr(info, "key") else info.name
                    if bname in seen:
                        continue
                    seen.add(bname)
                    bkt = oss2.Bucket(auth, ep, bname)
                    # ACL
                    ok_acl, acl = safe_call(bkt.get_bucket_acl)
                    if ok_acl and acl.acl not in ("private",):
                        r.add(Finding(f"oss.public.{bname}", "oss",
                            f"OSS 桶 {bname} 非私有",
                            "Bucket ACL 应为 private",
                            "get_bucket_acl", "private",
                            acl.acl, "fail", "critical",
                            resource=bname,
                            remediation=f"将 {bname} ACL 改为 private"))
                    # 版本控制
                    ok_v, ver = safe_call(bkt.get_bucket_versioning)
                    if ok_v and getattr(ver, "status", "") != "Enabled":
                        r.add(Finding(f"oss.versioning.{bname}", "oss",
                            f"OSS 桶 {bname} 未启用版本控制",
                            "Versioning 应 Enabled",
                            "get_bucket_versioning", "Enabled",
                            getattr(ver, "status", "未配置"),
                            "fail", "medium", resource=bname,
                            remediation=f"为 {bname} 启用版本控制"))
                    # 加密
                    ok_e, enc = safe_call(bkt.get_bucket_encryption)
                    if not ok_e:
                        r.add(Finding(f"oss.enc.{bname}", "oss",
                            f"OSS 桶 {bname} 未配置服务端加密",
                            "应启用 SSE",
                            "get_bucket_encryption", "已配置",
                            "未配置", "fail", "high", resource=bname,
                            remediation=f"为 {bname} 启用服务端加密"))
                    # 日志
                    ok_l, log = safe_call(bkt.get_bucket_logging)
                    if not ok_l or not getattr(log, "enabled", False):
                        r.add(Finding(f"oss.logging.{bname}", "oss",
                            f"OSS 桶 {bname} 未访问日志",
                            "应开启访问日志",
                            "get_bucket_logging", "enabled",
                            "未开启", "fail", "low", resource=bname,
                            remediation=f"为 {bname} 配置访问日志"))
            if not seen:
                r.add(Finding("oss.none", "oss", "当前 region 无 OSS 桶",
                    "Service.list_buckets", "存在时检查",
                    "0 个", "pass", "info"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("oss.error", "oss", "OSS 检查失败",
                "oss2", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r

    # ================================================================== #
    # ECS
    # ================================================================== #
    def check_ecs(self) -> CheckReport:
        r = CheckReport(provider="aliyun", service="ecs")
        try:
            from aliyunsdkecs.request.v20140526 import (
                DescribeInstancesRequest, DescribeSecurityGroupsRequest,
                DescribeSecurityGroupAttributeRequest, DescribeDisksRequest)
            ok, inst = self._do(DescribeInstancesRequest(),
                                PageSize=50)
            if not ok:
                raise RuntimeError(str(inst))
            ilist = (inst or {}).get("Instances", {}).get("Instance", [])
            for i in ilist[:100]:
                iid = i.get("InstanceId")
                # 释放保护
                if not i.get("DeletionProtection"):
                    r.add(Finding(f"ecs.del_protect.{iid}", "ecs",
                        f"ECS {iid} 未启用释放保护",
                        "关键实例应开启 DeletionProtection",
                        "DescribeInstances", "true", "false",
                        "fail", "low", resource=iid,
                        remediation=f"为 {iid} 开启释放保护"))
                # RAM 角色
                if not i.get("RamRoleName"):
                    r.add(Finding(f"ecs.ram_role.{iid}", "ecs",
                        f"ECS {iid} 未关联 RAM 角色",
                        "应使用 RAM 角色而非 AK",
                        "DescribeInstances(RamRoleName)",
                        "已关联", "未关联",
                        "fail", "medium", resource=iid,
                        remediation=f"为 {iid} 关联 RAM 角色"))
            # 安全组
            okg, sgs = self._do(DescribeSecurityGroupsRequest(), PageSize=100)
            if okg:
                for sg in (sgs or {}).get("SecurityGroups", {}).get(
                        "SecurityGroup", [])[:100]:
                    sgid = sg.get("SecurityGroupId")
                    oka, attr = self._do(
                        DescribeSecurityGroupAttributeRequest(),
                        SecurityGroupId=sgid, Direction="ingress")
                    if oka:
                        for per in (attr or {}).get("Permissions", {}).get(
                                "Permission", []):
                                    cidr = per.get("SourceCidrIp", "")
                                    port_range = per.get("PortRange", "")
                                    if cidr in ("0.0.0.0/0", "::/0", ""):
                                        if "22/22" in port_range or "3389/3389" in port_range or "1/65535" in port_range:
                                            r.add(Finding(f"ecs.sg_open.{sgid}", "ecs",
                                                f"安全组 {sgid} 过度开放",
                                                "敏感端口不应 0.0.0.0/0",
                                                "DescribeSecurityGroupAttribute",
                                                "限制来源",
                                                f"端口 {port_range} 来源 {cidr}",
                                                "fail", "high", resource=sgid,
                                                remediation=f"收紧 {sgid} 的 {port_range} 规则"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("ecs.error", "ecs", "ECS 检查失败",
                "ecs client", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r

    # ================================================================== #
    # RDS
    # ================================================================== #
    def check_rds(self) -> CheckReport:
        r = CheckReport(provider="aliyun", service="rds")
        try:
            from aliyunsdkrds.request.v20140815 import (
                DescribeDBInstancesRequest)
            ok, dbs = self._do(DescribeDBInstancesRequest(), PageSize=50)
            if not ok:
                raise RuntimeError(str(dbs))
            dlist = (dbs or {}).get("Items", {}).get("DBInstance", [])
            for db in dlist[:100]:
                did = db.get("DBInstanceId")
                net_type = db.get("ConnectionMode", "")
                # 白名单
                ip_list = db.get("SecurityIPList", "")
                if "0.0.0.0/0" in ip_list:
                    r.add(Finding(f"rds.whitelist.{did}", "rds",
                        f"RDS {did} 白名单放行 0.0.0.0/0",
                        "白名单不应允许所有 IP",
                        "DescribeDBInstances(SecurityIPList)",
                        "限定 IP", ip_list,
                        "fail", "critical", resource=did,
                        remediation=f"收紧 {did} 白名单"))
                # 备份
                if int(db.get("BackupRetentionPeriod", 0) or 0) < 7:
                    r.add(Finding(f"rds.backup.{did}", "rds",
                        f"RDS {did} 备份保留 < 7 天",
                        "备份保留 >= 7 天",
                        "DescribeDBInstances", ">=7",
                        str(db.get("BackupRetentionPeriod", 0)),
                        "fail", "medium", resource=did,
                        remediation=f"将 {did} 备份保留提升到 >=7 天"))
                # 加密
                if db.get("DBInstanceStorageEncrypted") in (False, "false", "False"):
                    r.add(Finding(f"rds.enc.{did}", "rds",
                        f"RDS {did} 存储未加密",
                        "存储应加密",
                        "DescribeDBInstances", "true", "false",
                        "fail", "high", resource=did,
                        remediation=f"为 {did} 启用存储加密"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("rds.error", "rds", "RDS 检查失败",
                "rds client", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r

    # ================================================================== #
    # VPC
    # ================================================================== #
    def check_vpc(self) -> CheckReport:
        r = CheckReport(provider="aliyun", service="vpc")
        try:
            from aliyunsdkvpc.request.v20160428 import (
                DescribeVpcsRequest, DescribeFlowLogsRequest)
            ok, fl = self._do(DescribeFlowLogsRequest(), PageSize=50)
            enabled = set()
            if ok:
                for f in (fl or {}).get("FlowLogs", {}).get("FlowLog", []):
                    if f.get("Status") == "Active":
                        enabled.add(f.get("ResourceId"))
            okv, vpcs = self._do(DescribeVpcsRequest(), PageSize=50)
            if okv:
                for v in (vpcs or {}).get("Vpcs", {}).get("Vpc", [])[:50]:
                    vid = v.get("VpcId")
                    if vid not in enabled:
                        r.add(Finding(f"vpc.flow.{vid}", "vpc",
                            f"VPC {vid} 未启用流日志",
                            "应开启 Flow Logs",
                            "DescribeFlowLogs", "Active",
                            "无", "fail", "medium", resource=vid,
                            remediation=f"为 {vid} 配置流日志"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("vpc.error", "vpc", "VPC 检查失败",
                "vpc client", "成功",
                f"{type(e).__name__}: {e}", "error", "medium"))
        return r

    # ================================================================== #
    # ActionTrail
    # ================================================================== #
    def check_actiontrail(self) -> CheckReport:
        r = CheckReport(provider="aliyun", service="actiontrail")
        try:
            from aliyunsdkactiontrail.request.v20171204 import (
                DescribeTrailsRequest)
            ok, trails = self._do(DescribeTrailsRequest())
            if not ok:
                raise RuntimeError(str(trails))
            tlist = (trails or {}).get("TrailList", [])
            if not tlist:
                r.add(Finding("at.none", "actiontrail",
                    "未创建任何操作审计跟踪",
                    "必须启用 ActionTrail",
                    "DescribeTrails", "至少 1 条", "0 条",
                    "fail", "critical",
                    remediation="创建多维度 ActionTrail 并投递到 OSS/SLS"))
            for t in tlist:
                name = t.get("Name")
                if not t.get("IsOrganizationTrail") and not t.get("TrackAllEvents"):
                    r.add(Finding(f"at.all_events.{name}", "actiontrail",
                        f"跟踪 {name} 未记录全部事件",
                        "应 TrackAllEvents=true",
                        "DescribeTrails", "true", "false",
                        "fail", "high",
                        remediation=f"将 {name} 改为记录全部事件"))
                if not t.get("OssWriteRoleArn"):
                    r.add(Finding(f"at.oss.{name}", "actiontrail",
                        f"跟踪 {name} 未投递到 OSS",
                        "日志应投递到 OSS/SLS",
                        "DescribeTrails", "已配置投递", "未配置",
                        "fail", "medium",
                        remediation=f"为 {name} 配置 OSS 投递"))
        except Exception as e:  # noqa: BLE001
            r.errors.append(f"{type(e).__name__}: {e}")
            r.add(Finding("at.error", "actiontrail",
                "ActionTrail 检查失败", "actiontrail client",
                "成功", f"{type(e).__name__}: {e}",
                "error", "medium"))
        return r


_default_checker: Optional[AliyunSecurityChecker] = None


def get_aliyun_checker(region: Optional[str] = None) -> AliyunSecurityChecker:
    global _default_checker
    if _default_checker is None:
        _default_checker = AliyunSecurityChecker(region)
    return _default_checker
