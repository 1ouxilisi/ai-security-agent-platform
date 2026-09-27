# -*- coding: utf-8 -*-
"""
aws_security_check.py — 真实 AWS 安全检查（boto3 真实调用，不 mock）。

覆盖服务:
    IAM / S3 / EC2 / RDS / VPC / CloudTrail / GuardDuty / Config

前置:
    - 未安装 boto3  -> 明确提示 `pip install boto3`
    - 未配置凭证    -> 明确提示 `aws configure` / 环境变量
    - 已配置凭证    -> 真实调用并逐条评估
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ._base import Finding, CheckReport, not_ready_report, safe_call


# --------------------------------------------------------------------------- #
# 凭证 / SDK 检测
# --------------------------------------------------------------------------- #
def detect_aws_status() -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "provider": "aws", "sdk_installed": False,
        "credentials_configured": False, "region": "", "hint": "",
        "account_identity": None,
    }
    try:
        import boto3  # noqa: F401
        out["sdk_installed"] = True
    except Exception:  # noqa: BLE001
        out["hint"] = ("未安装 boto3。请执行: pip install boto3 "
                       "botocore。 未安装 SDK 无法发起真实 AWS 调用。")
        return out

    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        out["region"] = session.region_name or os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1")
        if creds is None:
            out["hint"] = (
                "AWS 凭证未配置。请任选其一: 1) 环境变量 "
                "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION; "
                "2) 运行 `aws configure` 写入 ~/.aws/credentials; "
                "3) 实例角色 / SSO。建议使用只读审计角色(SecurityAudit)。")
            return out
        out["credentials_configured"] = True
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        out["account_identity"] = {
            "account": ident.get("Account"), "arn": ident.get("Arn"),
            "user_id": ident.get("UserId")}
        out["hint"] = "凭证有效，已发起真实 AWS API 调用。"
    except Exception as e:  # noqa: BLE001
        out["hint"] = f"AWS 凭证检测失败（真实错误）: {type(e).__name__}: {e}"
    return out


INSTALL_HINT = "pip install boto3 botocore"
CONFIG_HINT = ("配置: aws configure 或设置 AWS_ACCESS_KEY_ID / "
               "AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION")


class AWSSecurityChecker:
    """真实 AWS 安全检查器。"""

    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 23}

    # ------------------------------------------------------------------ #
    def __init__(self, region: Optional[str] = None) -> None:
        self._region = region
        self._session = None

    def _get_session(self):
        if self._session is None:
            import boto3
            self._session = boto3.Session()
        return self._session

    def _region_name(self) -> str:
        s = self._get_session()
        return self._region or s.region_name or os.environ.get(
            "AWS_DEFAULT_REGION", "us-east-1")

    # ------------------------------------------------------------------ #
    # 总入口
    # ------------------------------------------------------------------ #
    def run(self, services: Optional[List[str]] = None) -> Dict[str, Any]:
        status = detect_aws_status()
        want = services or ["iam", "s3", "ec2", "rds", "vpc",
                            "cloudtrail", "guardduty", "config"]
        reports: Dict[str, CheckReport] = {}
        if not status["sdk_installed"]:
            for svc in want:
                reports[svc] = not_ready_report(
                    "aws", svc, status["hint"], sdk_installed=False)
            return self._assemble(reports, status)
        if not status["credentials_configured"]:
            for svc in want:
                reports[svc] = not_ready_report(
                    "aws", svc, status["hint"],
                    credentials_configured=False)
            return self._assemble(reports, status)

        runners = {
            "iam": self.check_iam, "s3": self.check_s3,
            "ec2": self.check_ec2, "rds": self.check_rds,
            "vpc": self.check_vpc, "cloudtrail": self.check_cloudtrail,
            "guardduty": self.check_guardduty, "config": self.check_config,
        }
        for svc in want:
            fn = runners.get(svc)
            if fn is None:
                continue
            try:
                reports[svc] = fn()
            except Exception as e:  # noqa: BLE001
                r = CheckReport(provider="aws", service=svc,
                                account_identity=status["account_identity"])
                r.errors.append(f"{type(e).__name__}: {e}")
                r.add(Finding(check_id=f"{svc}.error", service=svc,
                              title=f"{svc} 检查失败",
                              actual=f"{type(e).__name__}: {e}",
                              status="error", severity="medium",
                              remediation="检查 IAM 权限与网络可达性"))
                reports[svc] = r
        return self._assemble(reports, status)

    def _assemble(self, reports: Dict[str, CheckReport],
                  status: Dict[str, Any]) -> Dict[str, Any]:
        merged = []
        by_service: Dict[str, Any] = {}
        for svc, r in reports.items():
            r.account_identity = status.get("account_identity") or {}
            by_service[svc] = r.summary()
            merged.extend(r.findings)
        agg = CheckReport(provider="aws", service="aws",
                          account_identity=status["account_identity"])
        agg.findings = merged
        agg.ready = status["credentials_configured"]
        agg.hint = status["hint"]
        return {"provider": "aws", "credential_status": status,
                "by_service": by_service,
                "summary": agg.summary(),
                "findings": [f.to_dict() for f in merged]}

    # ================================================================== #
    # IAM 真实检查
    # ================================================================== #
    def check_iam(self) -> CheckReport:
        r = CheckReport(provider="aws", service="iam")
        iam = self._get_session().client("iam")

        # 1. 密码策略
        ok, data = safe_call(iam.get_account_password_policy)
        if ok:
            p = data.get("PasswordPolicy", {})
            if p.get("MinimumPasswordPasswordLength", p.get("MinimumPasswordLength", 0)) < 14:
                r.add(Finding("iam.password_length", "iam",
                    "IAM 密码长度不足", "账户密码策略要求最小长度",
                    "get_account_password_policy", ">= 14 位",
                    f"当前 {p.get('MinimumPasswordLength', 0)} 位",
                    "fail", "high", remediation="将最小密码长度提升到 14 位以上"))
            else:
                r.add(Finding("iam.password_length", "iam",
                    "IAM 密码长度合规", "密码最小长度 >=14",
                    "get_account_password_policy", ">=14", "合规",
                    "pass", "info"))
            for flag, label, sev in [
                (p.get("RequireSymbols"), "符号", "low"),
                (p.get("RequireNumbers"), "数字", "low"),
                (p.get("RequireUppercaseCharacters"), "大写", "low"),
                (p.get("RequireLowercaseCharacters"), "小写", "low")]:
                r.add(Finding(f"iam.complexity_{label}", "iam",
                    f"密码复杂度要求({label})", f"是否强制{label}",
                    "get_account_password_policy", "启用",
                    "已启用" if flag else "未启用",
                    "pass" if flag else "fail", "low",
                    remediation=f"启用{label}复杂度要求" if not flag else ""))
            if p.get("MaxPasswordAge", 999) > 90:
                r.add(Finding("iam.password_rotation", "iam",
                    "密码轮换周期过长", "90 天内必须轮换",
                    "get_account_password_policy", "<= 90 天",
                    f"当前 {p.get('MaxPasswordAge', '无限制')} 天",
                    "fail", "medium", remediation="设置 MaxPasswordAge <= 90"))
            if p.get("PasswordReusePrevention", 0) < 5:
                r.add(Finding("iam.password_reuse", "iam",
                    "密码重用限制不足", "禁止最近 5 次重用",
                    "get_account_password_policy", ">= 5 代",
                    f"当前 {p.get('PasswordReusePrevention', 0)} 代",
                    "fail", "low", remediation="设置 PasswordReusePrevention >= 5"))
        else:
            r.add(Finding("iam.password_policy", "iam",
                "未设置 IAM 密码策略", "账户应配置密码策略",
                "get_account_password_policy", "已配置",
                f"未配置（{data}）", "fail", "high",
                remediation="创建账户密码策略，强制长度/复杂度/轮换/重用"))

        # 2. 根账户 MFA
        ok, s = safe_call(iam.get_account_summary)
        if ok:
            summ = s.get("SummaryMap", {})
            root_mfa = summ.get("AccountMFAEnabled", 0)
            r.add(Finding("iam.root_mfa", "iam",
                "根账户 MFA 状态", "根账户必须启用 MFA",
                "get_account_summary(AccountMFAEnabled)", "1",
                str(root_mfa),
                "pass" if str(root_mfa) == "1" else "fail",
                "critical", remediation="立即为根账户启用虚拟 MFA 硬件 Token"))

        # 3. 用户逐条检查
        ok, lu = safe_call(iam.list_users)
        if ok:
            users = lu.get("Users", [])
            now = datetime.now(timezone.utc)
            for u in users:
                uname = u.get("UserName", "")
                arn = u.get("Arn", "")
                # MFA
                ok2, m = safe_call(iam.list_mfa_devices, UserName=uname)
                mfa_on = bool(ok2 and m.get("MFADevices"))
                r.add(Finding(f"iam.user_mfa.{uname}", "iam",
                    f"IAM 用户 {uname} MFA", "每个 IAM 用户启用 MFA",
                    "list_mfa_devices", "至少 1 台 MFA 设备",
                    f"{len(m.get('MFADevices', [])) if ok2 else '查询失败'} 台",
                    "pass" if mfa_on else "fail", "high",
                    resource=arn,
                    remediation=f"为 {uname} 启用 MFA" if not mfa_on else ""))
                # 未登录天数
                last = u.get("PasswordLastUsed")
                if last is None:
                    days_idle = 9999
                else:
                    days_idle = (now - last).days
                if days_idle >= 90:
                    r.add(Finding(f"iam.user_idle.{uname}", "iam",
                        f"未使用用户 {uname}", "90 天未登录应禁用",
                        "list_users(PasswordLastUsed)", "< 90 天",
                        f"{days_idle} 天未登录", "fail", "medium",
                        resource=arn,
                        remediation=f"禁用或删除长期未使用用户 {uname}"))
                # AccessKey 过期
                ok3, ak = safe_call(iam.list_access_keys, UserName=uname)
                if ok3:
                    for k in ak.get("AccessKeyMetadata", []):
                        create = k.get("CreateDate")
                        age_days = (now - create).days if create else 0
                        status_k = k.get("Status", "Inactive")
                        if age_days >= 90:
                            r.add(Finding(f"iam.ak_age.{uname}", "iam",
                                f"访问密钥未轮换 {uname}", "AccessKey 90 天内轮换",
                                "list_access_keys(CreateDate)", "< 90 天",
                                f"{age_days} 天，状态 {status_k}",
                                "fail", "high", resource=arn,
                                remediation=f"轮换 {uname} 的 AccessKey {k.get('AccessKeyId')}"))
                        if status_k == "Active":
                            ok4, last_use = safe_call(
                                iam.get_access_key_last_used,
                                AccessKeyId=k.get("AccessKeyId"))
                            # 未使用的活跃 AK
                            if ok4:
                                lu_date = last_use.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                                if lu_date is None and age_days >= 90:
                                    r.add(Finding(f"iam.ak_unused.{uname}", "iam",
                                        f"从未使用的活跃 AccessKey {uname}",
                                        "长期未使用的 AK 应禁用",
                                        "get_access_key_last_used",
                                        "已使用或已禁用",
                                        f"创建 {age_days} 天从未使用",
                                        "fail", "medium", resource=arn,
                                        remediation=f"禁用未使用的 AK {k.get('AccessKeyId')}"))

            # 4. 过度权限：管理员策略 / 通配符
            okg, gp = safe_call(iam.list_policies, Scope="Local",
                                OnlyAttached=True)
            if okg:
                for p in gp.get("Policies", [])[:200]:
                    name = p.get("PolicyName", "")
                    if name in ("AdministratorAccess",):
                        r.add(Finding(f"iam.admin_policy.{name}", "iam",
                            f"存在管理员策略 {name}",
                            "应避免广泛使用 * 管理员策略",
                            "list_policies", "无 AdministratorAccess 附加",
                            f"策略 {name} 附件 {p.get('AttachmentCount',0)}",
                            "fail" if p.get("AttachmentCount", 0) > 0 else "pass",
                            "high",
                            remediation=f"审计 {name} 的附加范围，遵循最小权限"))
            # 5. 角色信任策略通配符主体
            okr, roles = safe_call(iam.list_roles)
            if okr:
                for role in roles.get("Roles", [])[:200]:
                    rp = role.get("AssumeRolePolicyDocument", {})
                    stmts = rp.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for st in stmts:
                        principal = st.get("Principal", {})
                        eff = st.get("Effect", "Allow")
                        if eff == "Allow":
                            svc = principal.get("Service")
                            aws_p = principal.get("AWS")
                            if aws_p == "*" or principal == "*" or aws_p == ["*"]:
                                r.add(Finding(f"iam.role_trust.{role.get('RoleName')}", "iam",
                                    f"角色 {role.get('RoleName')} 信任策略过宽",
                                    "不应信任通配符 AWS 主体",
                                    "list_roles(AssumeRolePolicyDocument)",
                                    "限定具体主体",
                                    f"Principal 含 * : {aws_p}",
                                    "fail", "high",
                                    resource=role.get("Arn", ""),
                                    remediation="收紧角色信任策略 Principal 到具体账号/服务"))
        return r

    # ================================================================== #
    # S3 真实检查
    # ================================================================== #
    def check_s3(self) -> CheckReport:
        r = CheckReport(provider="aws", service="s3")
        s3 = self._get_session().client("s3")
        ok, lb = safe_call(s3.list_buckets)
        if not ok:
            r.errors.append(str(lb))
            r.add(Finding("s3.list", "s3", "无法列出 S3 桶",
                "list_buckets", "成功", str(lb), "error", "medium"))
            return r
        for b in lb.get("Buckets", []):
            name = b.get("Name", "")
            # 公开访问块
            okb, bpa = safe_call(s3.get_public_access_block, Bucket=name)
            if okb:
                cfg = bpa.get("PublicAccessBlockConfiguration", {})
                blocked = all([cfg.get("BlockPublicAcls"),
                               cfg.get("IgnorePublicAcls"),
                               cfg.get("BlockPublicPolicy"),
                               cfg.get("RestrictPublicBuckets")])
                r.add(Finding(f"s3.block_public.{name}", "s3",
                    f"存储桶 {name} 公开访问块",
                    "BlockPublicAccess 四项必须全部启用",
                    "get_public_access_block",
                    "全部 True",
                    str(cfg), "pass" if blocked else "fail",
                    "critical", resource=f"arn:aws:s3:::{name}",
                    remediation=f"为 {name} 启用 BlockPublicAccess 全部四项" if not blocked else ""))
            # 加密
            oke, enc = safe_call(s3.get_bucket_encryption, Bucket=name)
            enc_enabled = False
            kms = False
            if oke:
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    enc_enabled = True
                    app = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    kms = app.get("KMSMasterKeyID") is not None
            r.add(Finding(f"s3.encryption.{name}", "s3",
                f"存储桶 {name} 默认加密",
                "应启用 SSE（优先 SSE-KMS）",
                "get_bucket_encryption", "SSE 已配置",
                f"加密={'未启用' if not enc_enabled else 'KMS' if kms else 'SSE-S3'}",
                "pass" if enc_enabled else "fail",
                "high", resource=f"arn:aws:s3:::{name}",
                remediation=f"为 {name} 启用默认加密(SSE-KMS)" if not enc_enabled else ""))
            # 版本控制
            okv, ver = safe_call(s3.get_bucket_versioning, Bucket=name)
            v_enabled = bool(okv and ver.get("Status") == "Enabled")
            r.add(Finding(f"s3.versioning.{name}", "s3",
                f"存储桶 {name} 版本控制",
                "Versioning 应 Enabled",
                "get_bucket_versioning", "Enabled",
                ver.get("Status", "Suspended/未配置") if okv else str(ver),
                "pass" if v_enabled else "fail",
                "medium", resource=f"arn:aws:s3:::{name}",
                remediation=f"为 {name} 启用版本控制" if not v_enabled else ""))
            # 访问日志
            okl, log = safe_call(s3.get_bucket_logging, Bucket=name)
            logging_on = bool(okl and log.get("LoggingEnabled"))
            r.add(Finding(f"s3.logging.{name}", "s3",
                f"存储桶 {name} 服务器访问日志",
                "应开启 Server Access Logging",
                "get_bucket_logging", "已配置目标桶",
                "已配置" if logging_on else "未配置",
                "pass" if logging_on else "fail",
                "low", resource=f"arn:aws:s3:::{name}",
                remediation=f"为 {name} 配置访问日志目标桶" if not logging_on else ""))
            # 传输加密强制(策略 Deny non-TLS)
            okp, pol = safe_call(s3.get_bucket_policy, Bucket=name)
            force_ssl = False
            if okp:
                doc = pol.get("Policy", "")
                force_ssl = ("aws:SecureTransport" in doc and "false" in doc)
            r.add(Finding(f"s3.force_ssl.{name}", "s3",
                f"存储桶 {name} 强制传输加密",
                "Bucket Policy 应 Deny 非 SSL 传输",
                "get_bucketPolicy", "存在 Deny SecureTransport=false",
                "已强制" if force_ssl else "未强制",
                "pass" if force_ssl else "fail",
                "medium", resource=f"arn:aws:s3:::{name}",
                remediation=f"为 {name} 增加 Deny aws:SecureTransport=false 语句" if not force_ssl else ""))
        return r

    # ================================================================== #
    # EC2 真实检查
    # ================================================================== #
    def check_ec2(self) -> CheckReport:
        r = CheckReport(provider="aws", service="ec2")
        region = self._region_name()
        ec2 = self._get_session().client("ec2", region_name=region)

        # 安全组
        ok, sgs = safe_call(ec2.describe_security_groups)
        used_sgs = set()
        if ok:
            okinst, inst = safe_call(ec2.describe_instances)
            if okinst:
                for res in inst.get("Reservations", []):
                    for i in res.get("Instances", []):
                        for g in i.get("SecurityGroups", []):
                            used_sgs.add(g.get("GroupId"))
            for sg in sgs.get("SecurityGroups", []):
                gid = sg.get("GroupId")
                name = sg.get("GroupName")
                for perm in sg.get("IpPermissions", []):
                    for ip in perm.get("IpRanges", []):
                        cidr = ip.get("CidrIp", "")
                        from_p = perm.get("FromPort")
                        to_p = perm.get("ToPort")
                        is_open_world = cidr in ("0.0.0.0/0", "::/0")
                        sensitive = (from_p in self.SENSITIVE_PORTS
                                     or to_p in self.SENSITIVE_PORTS)
                        all_ports = from_p in (None, -1) and to_p in (None, -1)
                        if is_open_world and sensitive:
                            r.add(Finding(f"ec2.sg_sensitive.{gid}", "ec2",
                                f"安全组 {name}({gid}) 暴露敏感端口",
                                "敏感端口不应对 0.0.0.0/0 开放",
                                "describe_security_groups",
                                "敏感端口限制源",
                                f"端口 {from_p}-{to_p} 来源 {cidr}",
                                "fail", "critical", resource=gid,
                                remediation=f"收紧 {gid} 的 {from_p}/{to_p} 入站来源"))
                        elif is_open_world and all_ports:
                            r.add(Finding(f"ec2.sg_allports.{gid}", "ec2",
                                f"安全组 {name}({gid}) 对全网开放所有端口",
                                "不应对 0.0.0.0/0 开放全部端口",
                                "describe_security_groups",
                                "限定端口与来源",
                                f"全部端口 {cidr}",
                                "fail", "high", resource=gid,
                                remediation=f"移除 {gid} 的 0.0.0.0/0 全端口规则"))
                if gid not in used_sgs:
                    r.add(Finding(f"ec2.sg_unused.{gid}", "ec2",
                        f"未使用的安全组 {name}({gid})",
                        "未关联实例的安全组应清理",
                        "describe_security_groups/describe_instances",
                        "全部 SG 均被使用",
                        "未关联任何实例",
                        "fail", "low", resource=gid,
                        remediation=f"删除未使用的安全组 {gid}"))
        else:
            r.errors.append(str(sgs))

        # 实例
        ok2, inst2 = safe_call(ec2.describe_instances)
        if ok2:
            for res in inst2.get("Reservations", []):
                for i in res.get("Instances", []):
                    iid = i.get("InstanceId")
                    # IMDSv1
                    md = i.get("MetadataOptions", {})
                    ht = md.get("HttpTokens", "optional")
                    if ht != "required":
                        r.add(Finding(f"ec2.imdsv1.{iid}", "ec2",
                            f"实例 {iid} 启用了 IMDSv1",
                            "应强制 IMDSv2(HttpTokens=required)",
                            "describe_instances(MetadataOptions)",
                            "HttpTokens=required",
                            f"HttpTokens={ht}",
                            "fail", "high", resource=iid,
                            remediation=f"对 {iid} 强制 IMDSv2"))
                    # 终止保护
                    if not i.get("DisableApiTermination"):
                        r.add(Finding(f"ec2.term_protect.{iid}", "ec2",
                            f"实例 {iid} 未启用终止保护",
                            "关键实例应启用 DisableApiTermination",
                            "describe_instances", "true", "false",
                            "fail", "low", resource=iid,
                            remediation=f"为 {iid} 启用终止保护"))
                    # IAM 角色
                    if not i.get("IamInstanceProfile"):
                        r.add(Finding(f"ec2.iam_role.{iid}", "ec2",
                            f"实例 {iid} 未关联 IAM 角色",
                            "应使用实例角色而非硬编码 AK",
                            "describe_instances(IamInstanceProfile)",
                            "已关联实例配置档", "未关联",
                            "fail", "medium", resource=iid,
                            remediation=f"为 {iid} 关联最小权限实例角色"))
                    # 详细监控
                    if not i.get("Monitoring", {}).get("State") == "enabled":
                        r.add(Finding(f"ec2.detailed_mon.{iid}", "ec2",
                            f"实例 {iid} 未启用详细监控",
                            "应启用 CloudWatch 详细监控(1分钟)",
                            "describe_instances(Monitoring.State)",
                            "enabled",
                            i.get("Monitoring", {}).get("State"),
                            "fail", "low", resource=iid,
                            remediation=f"为 {iid} 启用详细监控"))
        # EBS 未加密
        okv, vols = safe_call(ec2.describe_volumes)
        if okv:
            for v in vols.get("Volumes", []):
                if not v.get("Encrypted"):
                    r.add(Finding(f"ec2.ebs_enc.{v.get('VolumeId')}", "ec2",
                        f"EBS 卷 {v.get('VolumeId')} 未加密",
                        "EBS 卷应启用加密",
                        "describe_volumes(Encrypted)", "true", "false",
                        "fail", "high", resource=v.get("VolumeId"),
                        remediation=f"替换或加密卷 {v.get('VolumeId')}"))
        # 未使用 EIP
        okeip, eips = safe_call(ec2.describe_addresses)
        if okeip:
            for eip in eips.get("Addresses", []):
                if not eip.get("InstanceId"):
                    r.add(Finding(f"ec2.eip_unused.{eip.get('PublicIp')}", "ec2",
                        f"未使用的弹性IP {eip.get('PublicIp')}",
                        "未关联实例的 EIP 应释放以降本",
                        "describe_addresses", "已关联实例",
                        "未关联", "fail", "low",
                        resource=eip.get("PublicIp"),
                        remediation=f"释放闲置 EIP {eip.get('PublicIp')}"))
        return r

    # ================================================================== #
    # RDS 真实检查
    # ================================================================== #
    def check_rds(self) -> CheckReport:
        r = CheckReport(provider="aws", service="rds")
        region = self._region_name()
        rds = self._get_session().client("rds", region_name=region)
        ok, dbs = safe_call(rds.describe_db_instances)
        if not ok:
            r.errors.append(str(dbs))
            r.add(Finding("rds.list", "rds", "无法列出 RDS",
                "describe_db_instances", "成功", str(dbs), "error", "medium"))
            return r
        for db in dbs.get("DBInstances", []):
            did = db.get("DBInstanceIdentifier")
            arn = db.get("DBInstanceArn")
            if db.get("PubliclyAccessible"):
                r.add(Finding(f"rds.public.{did}", "rds",
                    f"RDS {did} 公开可访问",
                    "数据库不应 PubliclyAccessible",
                    "describe_db_instances", "false", "true",
                    "fail", "critical", resource=arn,
                    remediation=f"关闭 {did} 的 PubliclyAccessible 并限制安全组"))
            if not db.get("StorageEncrypted"):
                r.add(Finding(f"rds.enc.{did}", "rds",
                    f"RDS {did} 存储未加密",
                    "StorageEncrypted 应为 true",
                    "describe_db_instances", "true", "false",
                    "fail", "high", resource=arn,
                    remediation=f"为 {did} 启用存储加密"))
            if db.get("BackupRetentionPeriod", 0) < 7:
                r.add(Finding(f"rds.backup.{did}", "rds",
                    f"RDS {did} 备份保留过短",
                    "自动备份保留 >= 7 天",
                    "describe_db_instances", ">= 7",
                    str(db.get("BackupRetentionPeriod", 0)),
                    "fail", "medium", resource=arn,
                    remediation=f"将 {did} 备份保留提升到 >=7 天"))
            if not db.get("MultiAZ"):
                r.add(Finding(f"rds.multi_az.{did}", "rds",
                    f"RDS {did} 未配置多 AZ",
                    "生产库应启用 MultiAZ 高可用",
                    "describe_db_instances", "true", "false",
                    "fail", "medium", resource=arn,
                    remediation=f"为 {did} 启用 MultiAZ"))
            # 日志导出
            logs = db.get("EnableCloudwatchLogsExports", [])
            if not logs:
                r.add(Finding(f"rds.logs.{did}", "rds",
                    f"RDS {did} 未导出 CloudWatch 日志",
                    "应启用审计/错误日志导出",
                    "describe_db_instances", "至少一种日志", "无",
                    "fail", "low", resource=arn,
                    remediation=f"为 {did} 启用 CloudWatch 日志导出"))
        return r

    # ================================================================== #
    # VPC 真实检查（基于 EC2 API）
    # ================================================================== #
    def check_vpc(self) -> CheckReport:
        r = CheckReport(provider="aws", service="vpc")
        region = self._region_name()
        ec2 = self._get_session().client("ec2", region_name=region)

        ok, fl = safe_call(ec2.describe_flow_logs)
        vpcs_with_fl = set()
        if ok:
            for fl_ in fl.get("FlowLogs", []):
                if fl_.get("FlowLogStatus") == "ACTIVE":
                    vpcs_with_fl.add(fl_.get("ResourceId"))
        else:
            r.errors.append(str(fl))

        okv, vpcs = safe_call(ec2.describe_vpcs)
        if okv:
            for vpc in vpcs.get("Vpcs", []):
                vid = vpc.get("VpcId")
                if vid not in vpcs_with_fl:
                    r.add(Finding(f"vpc.flowlog.{vid}", "vpc",
                        f"VPC {vid} 未启用 Flow Logs",
                        "VPC 应开启流日志",
                        "describe_flow_logs", "存在 ACTIVE 流日志",
                        "无 ACTIVE 流日志",
                        "fail", "medium", resource=vid,
                        remediation=f"为 {vid} 配置 VPC Flow Logs 到 CloudWatch/S3"))
                if vpc.get("IsDefault"):
                    r.add(Finding(f"vpc.default.{vid}", "vpc",
                        f"默认 VPC {vid} 仍在使用",
                        "生产环境建议移除默认 VPC",
                        "describe_vpcs(IsDefault)", "false",
                        "true", "fail", "low", resource=vid,
                        remediation="清理或限制默认 VPC 使用"))
        # 默认安全组放行
        okd, dsg = safe_call(ec2.describe_security_groups,
                             Filters=[{"Name": "group-name", "Values": ["default"]}])
        if okd:
            for sg in dsg.get("SecurityGroups", []):
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    r.add(Finding(f"vpc.default_sg.{sg.get('GroupId')}", "vpc",
                        f"默认安全组 {sg.get('GroupId')} 含放行规则",
                        "默认安全组应不含任何入站/出站放行",
                        "describe_security_groups(default)",
                        "无规则", f"入站{len(sg.get('IpPermissions',[]))} 出站{len(sg.get('IpPermissionsEgress',[]))}",
                        "fail", "medium", resource=sg.get("GroupId"),
                        remediation=f"移除默认安全组 {sg.get('GroupId')} 的放行规则"))
        return r

    # ================================================================== #
    # CloudTrail 真实检查
    # ================================================================== #
    def check_cloudtrail(self) -> CheckReport:
        r = CheckReport(provider="aws", service="cloudtrail")
        ct = self._get_session().client("cloudtrail",
                                        region_name=self._region_name())
        ok, trails = safe_call(ct.describe_trails,
                               IncludeShadowTrails=False)
        if not ok:
            r.errors.append(str(trails))
            r.add(Finding("ct.list", "cloudtrail", "无法列出 CloudTrail",
                "describe_trails", "成功", str(trails), "error", "medium"))
            return r
        ts = trails.get("TrailList", [])
        if not ts:
            r.add(Finding("ct.none", "cloudtrail",
                "未创建任何 CloudTrail 跟踪",
                "必须创建至少一个多区域跟踪",
                "describe_trails", "至少 1 个跟踪", "0 个",
                "fail", "critical",
                remediation="创建多区域 CloudTrail 并写入加密 S3"))
            return r
        for t in ts:
            name = t.get("Name")
            arn = t.get("TrailARN")
            if not t.get("IsMultiRegionTrail"):
                r.add(Finding(f"ct.multi.{name}", "cloudtrail",
                    f"跟踪 {name} 非多区域",
                    "CloudTrail 应记录多区域",
                    "describe_trails", "true", "false",
                    "fail", "high", resource=arn,
                    remediation=f"将 {name} 改为多区域跟踪"))
            if not t.get("LogFileValidationEnabled"):
                r.add(Finding(f"ct.log_validation.{name}", "cloudtrail",
                    f"跟踪 {name} 未启用日志文件完整性校验",
                    "应启用 LogFileValidation",
                    "describe_trails", "true", "false",
                    "fail", "medium", resource=arn,
                    remediation=f"为 {name} 启用日志文件校验"))
            if not t.get("KmsKeyId"):
                r.add(Finding(f"ct.kms.{name}", "cloudtrail",
                    f"跟踪 {name} 未使用 KMS 加密",
                    "日志应使用 KMS 加密",
                    "describe_trails", "存在 KmsKeyId", "无",
                    "fail", "medium", resource=arn,
                    remediation=f"为 {name} 配置 KMS 加密"))
            ok2, st = safe_call(ct.get_trail_status, Name=name)
            if ok2 and not st.get("IsLogging"):
                r.add(Finding(f"ct.logging.{name}", "cloudtrail",
                    f"跟踪 {name} 已停止记录",
                    "CloudTrail 必须持续记录",
                    "get_trail_status(IsLogging)", "true", "false",
                    "fail", "high", resource=arn,
                    remediation=f"重新启用 {name} 记录"))
        return r

    # ================================================================== #
    # GuardDuty 真实检查
    # ================================================================== #
    def check_guardduty(self) -> CheckReport:
        r = CheckReport(provider="aws", service="guardduty")
        region = self._region_name()
        gd = self._get_session().client("guardduty", region_name=region)
        ok, det = safe_call(gd.list_detectors)
        if not ok:
            r.errors.append(str(det))
            r.add(Finding("gd.list", "guardduty", "无法查询 GuardDuty",
                "list_detectors", "成功", str(det), "error", "medium"))
            return r
        detectors = det.get("DetectorIds", [])
        if not detectors:
            r.add(Finding("gd.none", "guardduty",
                "GuardDuty 未启用（无 Detector）",
                "应启用 GuardDuty 威胁检测",
                "list_detectors", "至少 1 个 Detector", "0 个",
                "fail", "high",
                remediation="在该区域启用 GuardDuty Detector"))
            return r
        for did in detectors:
            ok2, st = safe_call(gd.get_detector, DetectorId=did)
            if ok2:
                if st.get("Status") != "ENABLED":
                    r.add(Finding(f"gd.disabled.{did}", "guardduty",
                        f"Detector {did} 未启用",
                        "GuardDuty 应处于 ENABLED",
                        "get_detector", "ENABLED", st.get("Status"),
                        "fail", "high",
                        remediation=f"启用 GuardDuty Detector {did}"))
                # 高危发现未处理
                okf, fd = safe_call(gd.list_findings, DetectorId=did,
                                    FindingCriteria={"Criterion": {
                                        "severity": {"Gte": 7.0}}})
                if okf:
                    cnt = len(fd.get("FindingIds", []))
                    if cnt:
                        r.add(Finding(f"gd.findings.{did}", "guardduty",
                            f"存在 {cnt} 条高危/严重 GuardDuty 发现",
                            "高危发现应及时处置",
                            "list_findings(severity>=7)", "0 条未处理",
                            f"{cnt} 条", "fail", "high",
                            remediation="在 GuardDuty 控制台处置/归档高危发现"))
        return r

    # ================================================================== #
    # AWS Config 真实检查
    # ================================================================== #
    def check_config(self) -> CheckReport:
        r = CheckReport(provider="aws", service="config")
        cfg = self._get_session().client("config",
                                        region_name=self._region_name())
        ok, rec = safe_call(cfg.describe_configuration_recorders)
        if not ok:
            r.errors.append(str(rec))
            r.add(Finding("cfg.list", "config", "无法查询 Config",
                "describe_configuration_recorders", "成功", str(rec),
                "error", "medium"))
            return r
        recs = rec.get("ConfigurationRecorders", [])
        if not recs:
            r.add(Finding("cfg.none", "config",
                "AWS Config 未启用（无 Recorder）",
                "应启用 AWS Config 配置录制",
                "describe_configuration_recorders", "至少 1 个 Recorder",
                "0 个", "fail", "high",
                remediation="创建 Configuration Recorder 与 Delivery Channel"))
            return r
        for rec_ in recs:
            if not rec_.get("roleARN"):
                r.add(Finding(f"cfg.role.{rec_.get('name')}", "config",
                    f"Config Recorder {rec_.get('name')} 未关联角色",
                    "Recorder 必须关联 IAM 角色",
                    "describe_configuration_recorders", "存在 roleARN",
                    "无", "fail", "high",
                    remediation="为 Recorder 配置足够权限的 IAM 角色"))
        # 合规规则数
        okr, rules = safe_call(cfg.describe_config_rules)
        if okr:
            n = len(rules.get("ConfigRules", []))
            if n < 10:
                r.add(Finding("cfg.rules_count", "config",
                    f"Config 规则数量不足({n})",
                    "建议部署 >=10 条托管合规规则",
                    "describe_config_rules", ">= 10", str(n),
                    "fail", "low",
                    remediation="通过 AWS Config 托管规则批量部署 CIS 相关规则"))
        return r


_default_checker: Optional[AWSSecurityChecker] = None


def get_aws_checker(region: Optional[str] = None) -> AWSSecurityChecker:
    global _default_checker
    if _default_checker is None:
        _default_checker = AWSSecurityChecker(region)
    return _default_checker
