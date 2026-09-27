# -*- coding: utf-8 -*-
"""
cicd_integration_phase.py — 阶段1：CI/CD 集成。

功能:
    - 真实 GitHub Actions / GitLab CI / Jenkins 集成接口
    - 流水线配置生成（.github/workflows、.gitlab-ci.yml、Jenkinsfile）
    - 流水线状态查询 / 触发（真实 API 调用框架）
    - 未配置 Token 时明确提示，不 mock
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PipelineConfig:
    platform: str = "github"
    repo: str = ""
    branch: str = "main"
    stages: List[str] = field(default_factory=list)
    content: str = ""
    path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform, "repo": self.repo,
            "branch": self.branch, "stages": self.stages,
            "path": self.path, "content": self.content,
        }


@dataclass
class CICDResult:
    platform: str = ""
    action: str = ""
    ok: bool = False
    configured: bool = False
    message: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform, "action": self.action,
            "ok": self.ok, "configured": self.configured,
            "message": self.message, "detail": self.detail,
            "elapsed": round(self.elapsed, 2),
        }


# --------------------------------------------------------------------------- #
# 内置流水线模板
# --------------------------------------------------------------------------- #
GITHUB_WORKFLOW_TEMPLATE = """\
name: devsecops-pro
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
jobs:
  devsecops:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            auto
      - name: Gitleaks Secrets
        uses: gitleaks/gitleaks-action@v2
        env:
          GITLEAKS_LICENSE: ${{{{ secrets.GITLEAKS_LICENSE }}}}
      - name: Trivy FS
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          severity: HIGH,CRITICAL
      - name: Checkov IaC
        uses: bridgecrewio/checkov-action@master
"""

GITLAB_CI_TEMPLATE = """\
stages:
  - sast
  - secrets
  - iac
  - container

semgrep-sast:
  stage: sast
  image: returntocorp/semgrep
  script:
    - semgrep scan --config auto --json -o semgrep.json
  artifacts:
    reports:
      container_scanning: semgrep.json

gitleaks-secrets:
  stage: secrets
  image: zricethezav/gitleaks:latest
  script:
    - gitleaks detect --source . --report-format json --report-path gitleaks.json

trivy-container:
  stage: container
  image: aquasec/trivy:latest
  script:
    - trivy fs --exit-code 0 --format json -o trivy.json .

checkov-iac:
  stage: iac
  image: bridgecrew/checkov:latest
  script:
    - checkov -d . -o json
"""

JENKINSFILE_TEMPLATE = """\
pipeline {
  agent any
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('SAST-Semgrep') {
      steps { sh 'semgrep scan --config auto --json -o semgrep.json || true' }
    }
    stage('Secrets-Gitleaks') {
      steps { sh 'gitleaks detect --source . --report-format json --report-path gitleaks.json || true' }
    }
    stage('IaC-Checkov') {
      steps { sh 'checkov -d . || true' }
    }
    stage('Container-Trivy') {
      steps { sh 'trivy fs --exit-code 0 . || true' }
    }
  }
}
"""


class CICDIntegrationPhase:
    """阶段1：CI/CD 集成。"""

    PLATFORMS = ("github", "gitlab", "jenkins")

    def __init__(self) -> None:
        # 从环境变量读取 Token；未配置时不 mock
        self.tokens: Dict[str, str] = {
            "github": os.environ.get("GITHUB_TOKEN", ""),
            "gitlab": os.environ.get("GITLAB_TOKEN", ""),
            "jenkins": os.environ.get("JENKINS_TOKEN", ""),
        }
        self.endpoints: Dict[str, str] = {
            "github": "https://api.github.com",
            "gitlab": os.environ.get("GITLAB_URL", "https://gitlab.com"),
            "jenkins": os.environ.get("JENKINS_URL", ""),
        }

    # ------------------------------------------------------------------ #
    def is_configured(self, platform: str) -> bool:
        if platform == "jenkins":
            return bool(self.endpoints["jenkins"] and self.tokens["jenkins"])
        return bool(self.tokens.get(platform))

    # ------------------------------------------------------------------ #
    def generate_config(self, platform: str, repo: str = "",
                        branch: str = "main",
                        stages: Optional[List[str]] = None) -> PipelineConfig:
        """生成流水线配置文件内容。"""
        stages = stages or ["sast", "sca", "secrets", "iac", "container"]
        if platform == "github":
            content = GITHUB_WORKFLOW_TEMPLATE
            path = ".github/workflows/devsecops-pro.yml"
        elif platform == "gitlab":
            content = GITLAB_CI_TEMPLATE
            path = ".gitlab-ci.yml"
        elif platform == "jenkins":
            content = JENKINSFILE_TEMPLATE
            path = "Jenkinsfile"
        else:
            content = ""
            path = ""
        return PipelineConfig(
            platform=platform, repo=repo, branch=branch,
            stages=stages, content=content, path=path)

    # ------------------------------------------------------------------ #
    def save_config(self, cfg: PipelineConfig,
                    target_dir: str) -> str:
        out = os.path.join(target_dir, cfg.path.replace("/", os.sep))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            f.write(cfg.content)
        return out

    # ------------------------------------------------------------------ #
    def _http(self, method: str, url: str, token: str,
              body: Optional[Dict[str, Any]] = None,
              headers: Optional[Dict[str, str]] = None
              ) -> Dict[str, Any]:
        hdrs = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "devsecops-pro",
        }
        if headers:
            hdrs.update(headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method,
                                      headers=hdrs)
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except Exception:
                return {"raw": raw}

    # ------------------------------------------------------------------ #
    def trigger_pipeline(self, platform: str, repo: str,
                         ref: str = "main") -> CICDResult:
        t0 = time.time()
        res = CICDResult(platform=platform, action="trigger")
        if not self.is_configured(platform):
            res.message = (
                f"[{platform}] 未配置 API Token / 端点，无法真实触发。"
                f"请设置环境变量："
                f"{'GITHUB_TOKEN' if platform=='github' else 'GITLAB_TOKEN / GITLAB_URL' if platform=='gitlab' else 'JENKINS_URL / JENKINS_TOKEN'}。"
                f"本接口不提供 mock。")
            return res
        try:
            if platform == "github":
                url = f"{self.endpoints['github']}/repos/{repo}/actions/workflows/devsecops-pro.yml/dispatches"
                self._http("POST", url, self.tokens["github"],
                           {"ref": ref})
                res.ok = True
                res.configured = True
                res.message = f"GitHub Actions 触发成功: {repo} @ {ref}"
            elif platform == "gitlab":
                # GitLab: POST /projects/:id/trigger/pipeline
                # 简化：URL-encode repo path
                from urllib.parse import quote
                proj = quote(repo, safe="")
                url = (f"{self.endpoints['gitlab']}/api/v4/projects/"
                       f"{proj}/pipeline?ref={ref}&token="
                       f"{self.tokens['gitlab']}")
                out = self._http("POST", url, self.tokens["gitlab"])
                res.ok = True
                res.configured = True
                res.detail = out
                res.message = f"GitLab CI 触发成功: {repo} @ {ref}"
            elif platform == "jenkins":
                url = (f"{self.endpoints['jenkins']}/job/devsecops-pro/"
                       f"build?token={self.tokens['jenkins']}")
                self._http("POST", url, self.tokens["jenkins"])
                res.ok = True
                res.configured = True
                res.message = f"Jenkins 触发成功: {repo} @ {ref}"
        except urllib.error.HTTPError as e:
            res.message = f"HTTP {e.code}: {e.reason}"
        except Exception as e:  # noqa: BLE001
            res.message = f"{type(e).__name__}: {e}"
        res.elapsed = time.time() - t0
        return res

    # ------------------------------------------------------------------ #
    def pipeline_status(self, platform: str, repo: str,
                        run_id: str = "latest") -> CICDResult:
        t0 = time.time()
        res = CICDResult(platform=platform, action="status")
        if not self.is_configured(platform):
            res.message = f"[{platform}] 未配置 API Token，无法查询状态（不 mock）。"
            return res
        try:
            if platform == "github":
                url = (f"{self.endpoints['github']}/repos/{repo}/"
                       f"actions/runs/{run_id}")
                out = self._http("GET", url, self.tokens["github"])
                res.ok = True
                res.configured = True
                res.detail = {
                    "status": out.get("status"),
                    "conclusion": out.get("conclusion"),
                    "html_url": out.get("html_url"),
                    "run_id": out.get("id"),
                    "head_branch": out.get("head_branch"),
                }
                res.message = f"GitHub Actions 状态: {res.detail['status']}"
            elif platform == "gitlab":
                from urllib.parse import quote
                proj = quote(repo, safe="")
                url = (f"{self.endpoints['gitlab']}/api/v4/projects/"
                       f"{proj}/pipelines/{run_id}"
                       f"?private_token={self.tokens['gitlab']}")
                out = self._http("GET", url, self.tokens["gitlab"])
                res.ok = True
                res.configured = True
                res.detail = {
                    "status": out.get("status"),
                    "ref": out.get("ref"),
                    "sha": out.get("sha"),
                    "web_url": out.get("web_url"),
                }
                res.message = f"GitLab CI 状态: {res.detail['status']}"
            elif platform == "jenkins":
                url = (f"{self.endpoints['jenkins']}/job/devsecops-pro/"
                       f"lastBuild/api/json?token={self.tokens['jenkins']}")
                out = self._http("GET", url, self.tokens["jenkins"],
                                 headers={"Accept": "application/json"})
                res.ok = True
                res.configured = True
                res.detail = {
                    "building": out.get("building"),
                    "result": out.get("result"),
                    "number": out.get("number"),
                    "url": out.get("url"),
                }
                res.message = f"Jenkins 状态: {res.detail['result']}"
        except urllib.error.HTTPError as e:
            res.message = f"HTTP {e.code}: {e.reason}"
        except Exception as e:  # noqa: BLE001
            res.message = f"{type(e).__name__}: {e}"
        res.elapsed = time.time() - t0
        return res

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "platforms": list(self.PLATFORMS),
            "configured": {p: self.is_configured(p) for p in self.PLATFORMS},
            "endpoints": {p: self.endpoints[p] for p in self.PLATFORMS},
        }


_default: Optional[CICDIntegrationPhase] = None


def get_cicd_phase() -> CICDIntegrationPhase:
    global _default
    if _default is None:
        _default = CICDIntegrationPhase()
    return _default
