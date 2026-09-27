"""
AI Hacking Agent 核心SDK模块
==============================

提供AIAgentClient客户端类，封装所有API调用，包含：
- 统一请求方法（认证、重试、超时、错误处理）
- 35+个API方法（评估、验证、AI、工作流、报告、漏洞库、工具、可视化）
- 完整的异常类体系

使用示例:
    >>> from sdk.python.ai_hacking_sdk import AIAgentClient
    >>> client = AIAgentClient(base_url="http://localhost:8000", api_key="your-key")
    >>> health = client.health()
    >>> print(health)

免责声明：本SDK仅供授权安全测试使用，未经授权不得对第三方系统使用。
"""

import logging
import time
from typing import Any, Dict, Optional, Union

import requests


# ============================================================
# 异常类体系
# ============================================================

class APIError(Exception):
    """API基础异常类，所有SDK异常的父类。

    :ivar status_code: HTTP状态码
    :ivar message: 错误消息
    :ivar request_id: 请求ID（用于日志追踪）
    """

    def __init__(self, status_code: int, message: str, request_id: Optional[str] = None):
        self.status_code = status_code
        self.message = message
        self.request_id = request_id
        super().__init__(f"[{status_code}] {message} (request_id: {request_id})")


class AuthenticationError(APIError):
    """认证失败异常（HTTP 401），API密钥无效或过期。"""
    pass


class NotFoundError(APIError):
    """资源不存在异常（HTTP 404），请求的路径或ID不存在。"""
    pass


class RateLimitError(APIError):
    """请求频率限制异常（HTTP 429），触发了API限流策略。"""
    pass


class ServerError(APIError):
    """服务器内部错误异常（HTTP 5xx），服务端处理出错。"""
    pass


class ValidationError(APIError):
    """参数验证错误异常（HTTP 400），请求参数不合法。"""
    pass


# ============================================================
# 客户端核心类
# ============================================================

class AIAgentClient:
    """AI Hacking Agent API客户端。

    封装所有API调用，自动处理认证、重试、超时和错误转换。

    示例:
        >>> client = AIAgentClient(
        ...     base_url="http://localhost:8000",
        ...     api_key="sk-xxx",
        ...     timeout=30,
        ...     max_retries=3,
        ... )
        >>> result = client.health()
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str = "",
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        debug: bool = False,
    ):
        """初始化客户端。

        :param base_url: API服务基础URL，如 http://localhost:8000
        :param api_key: API密钥，通过X-API-Key请求头传递
        :param timeout: 请求超时时间（秒）
        :param max_retries: 最大重试次数（仅对网络错误和5xx错误重试）
        :param retry_delay: 重试基础延迟（秒），使用指数退避：delay * 2^attempt
        :param debug: 是否开启调试日志模式
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.debug = debug

        # 配置日志
        self.logger = logging.getLogger("ai_hacking_sdk")
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            self.logger.setLevel(logging.DEBUG)

        # 创建会话复用连接
        self._session = requests.Session()
        # 设置默认请求头
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AI-Hacking-SDK/1.0",
        }
        if api_key:
            headers["X-API-Key"] = api_key
        self._session.headers.update(headers)

    # --------------------------------------------------------
    # 内部请求方法
    # --------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """统一请求方法，包含认证、重试、超时、错误处理。

        :param method: HTTP方法（GET/POST/PUT/DELETE）
        :param path: 请求路径（相对于base_url）
        :param kwargs: 传递给requests的额外参数（json/params/data等）
        :return: 解析后的JSON响应或二进制内容
        :raises AuthenticationError: 401认证失败
        :raises ValidationError: 400参数错误
        :raises NotFoundError: 404资源不存在
        :raises RateLimitError: 429频率限制
        :raises ServerError: 5xx服务器错误
        :raises APIError: 其他API错误
        """
        url = f"{self.base_url}{path}"
        # 设置超时
        kwargs.setdefault("timeout", self.timeout)

        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                self.logger.debug(f"请求 [{method}] {url} (尝试 {attempt + 1}/{self.max_retries + 1})")
                response = self._session.request(method, url, **kwargs)

                # 提取请求ID
                request_id = response.headers.get("X-Request-ID") or response.headers.get("X-Request-Id")

                # 检查是否需要重试（5xx错误）
                if 500 <= response.status_code < 600 and attempt < self.max_retries:
                    delay = self.retry_delay * (2 ** attempt)
                    self.logger.warning(
                        f"服务器错误 {response.status_code}，{delay:.1f}秒后重试..."
                    )
                    time.sleep(delay)
                    continue

                # 根据状态码处理错误
                if response.status_code == 400:
                    try:
                        msg = response.json().get("detail", response.text)
                    except Exception:
                        msg = response.text
                    raise ValidationError(400, msg, request_id)
                elif response.status_code == 401:
                    raise AuthenticationError(401, "认证失败：API密钥无效或未提供", request_id)
                elif response.status_code == 403:
                    raise APIError(403, "权限不足：无权访问该资源", request_id)
                elif response.status_code == 404:
                    raise NotFoundError(404, f"资源不存在：{path}", request_id)
                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise RateLimitError(429, f"请求过于频繁，请{retry_after}秒后重试", request_id)
                elif 500 <= response.status_code < 600:
                    raise ServerError(response.status_code, f"服务器内部错误", request_id)
                elif response.status_code >= 400:
                    try:
                        msg = response.json().get("detail", response.text)
                    except Exception:
                        msg = response.text
                    raise APIError(response.status_code, msg, request_id)

                # 成功响应，尝试解析JSON
                # 对于下载报告等二进制内容，返回原始bytes
                content_type = response.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return response.json()
                elif "application/octet-stream" in content_type or "application/pdf" in content_type:
                    return response.content
                else:
                    # 尝试JSON解析，失败则返回文本
                    try:
                        return response.json()
                    except Exception:
                        return response.text

            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.RequestException) as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = self.retry_delay * (2 ** attempt)
                    self.logger.warning(f"网络错误: {e}，{delay:.1f}秒后重试...")
                    time.sleep(delay)
                else:
                    raise APIError(0, f"网络连接失败: {str(e)}", None)

        # 理论上不会走到这里
        raise APIError(0, f"请求失败: {str(last_exception)}", None)

    def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        """发送GET请求的便捷方法。

        :param path: 请求路径
        :param params: 查询参数字典
        :return: 响应数据
        """
        return self._request("GET", path, params=params)

    def _post(self, path: str, json: Optional[Dict] = None) -> Any:
        """发送POST请求的便捷方法。

        :param path: 请求路径
        :param json: JSON请求体
        :return: 响应数据
        """
        return self._request("POST", path, json=json)

    def _put(self, path: str, json: Optional[Dict] = None) -> Any:
        """发送PUT请求的便捷方法。

        :param path: 请求路径
        :param json: JSON请求体
        :return: 响应数据
        """
        return self._request("PUT", path, json=json)

    def _delete(self, path: str) -> Any:
        """发送DELETE请求的便捷方法。

        :param path: 请求路径
        :return: 响应数据
        """
        return self._request("DELETE", path)

    # --------------------------------------------------------
    # 1. 健康检查
    # --------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """健康检查接口，验证API服务是否正常运行。

        :return: 服务状态信息，包含status/version/uptime等字段
        :raises APIError: 请求失败时抛出
        :example:
            >>> client = AIAgentClient()
            >>> result = client.health()
            >>> print(result)
            {'status': 'healthy', 'version': '1.0.0'}
        """
        try:
            return self._get("/health")
        except APIError:
            # 尝试 /api/v1/health
            return self._get("/api/v1/health")

    # --------------------------------------------------------
    # 2-4. 全域安全评估
    # --------------------------------------------------------

    def create_assessment(
        self,
        target: str,
        assessment_type: str = "comprehensive",
        config: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """创建并启动全域安全评估任务。

        :param target: 评估目标（IP/域名/URL）
        :param assessment_type: 评估类型，可选：
            comprehensive(综合), web(Web应用), mobile(移动应用),
            internal(内网), domain(域名审计), ai(AI安全),
            blockchain(区块链), compliance(合规审计)
        :param config: 额外配置参数字典，可选
        :return: 评估任务信息，包含assessment_id/status等
        :raises ValidationError: 参数不合法
        :raises APIError: 请求失败
        :example:
            >>> result = client.create_assessment(
            ...     target="https://example.com",
            ...     assessment_type="web"
            ... )
            >>> print(result["assessment_id"])
        """
        payload = {
            "target": target,
            "type": assessment_type,
        }
        if config:
            payload["config"] = config
        # 调用统一评估接口
        return self._post("/api/v1/unified/assessment", json=payload)

    def get_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """获取指定评估任务的状态和结果。

        :param assessment_id: 评估任务ID
        :return: 评估详情，包含状态、漏洞列表、风险评分等
        :raises NotFoundError: 评估任务不存在
        :raises APIError: 请求失败
        :example:
            >>> result = client.get_assessment("assess_abc123")
            >>> print(result["status"])
        """
        return self._get(f"/api/v1/unified/assessment/{assessment_id}")

    def list_assessments(self, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
        """获取历史评估任务列表。

        :param limit: 返回条数限制（默认20）
        :param offset: 分页偏移量（默认0）
        :return: 评估列表，包含total/items分页信息
        :raises APIError: 请求失败
        :example:
            >>> result = client.list_assessments(limit=50)
            >>> for item in result["items"]:
            ...     print(item["assessment_id"], item["status"])
        """
        params = {"limit": limit, "offset": offset}
        return self._get("/api/v1/unified/assessments", params=params)

    # --------------------------------------------------------
    # 5-7. 漏洞真实验证
    # --------------------------------------------------------

    def verify_web_vuln(
        self,
        url: str,
        vuln_type: str,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """验证Web应用漏洞的真实性，避免误报。

        :param url: 目标Web应用URL
        :param vuln_type: 漏洞类型，如sql_injection/xss/csrf/path_traversal/command_injection/ssrf
        :param params: 额外验证参数字典，如测试参数名、payload等
        :return: 验证任务信息，包含task_id
        :raises ValidationError: 参数不合法
        :raises APIError: 请求失败
        :example:
            >>> result = client.verify_web_vuln(
            ...     url="https://example.com/search",
            ...     vuln_type="sql_injection",
            ...     params={"param": "id"}
            ... )
        """
        payload = {"url": url, "vuln_type": vuln_type}
        if params:
            payload.update(params)
        return self._post("/api/v1/verify/web", json=payload)

    def verify_service_vuln(
        self,
        target: str,
        service: str,
        port: int,
        vuln_type: str,
    ) -> Dict[str, Any]:
        """验证网络服务漏洞的真实性。

        :param target: 目标IP或域名
        :param service: 服务名称，如http/ssh/ftp/mysql/redis
        :param port: 服务端口号
        :param vuln_type: 漏洞类型
        :return: 验证任务信息，包含task_id
        :raises ValidationError: 参数不合法
        :raises APIError: 请求失败
        :example:
            >>> result = client.verify_service_vuln(
            ...     target="192.168.1.1",
            ...     service="http",
            ...     port=8080,
            ...     vuln_type="directory_traversal"
            ... )
        """
        payload = {
            "target": target,
            "service": service,
            "port": port,
            "vuln_type": vuln_type,
        }
        return self._post("/api/v1/verify/service", json=payload)

    def get_verify_result(self, task_id: str) -> Dict[str, Any]:
        """获取漏洞验证任务的结果。

        :param task_id: 验证任务ID
        :return: 验证结果，包含verified(boolean)/evidence/risk_level等
        :raises NotFoundError: 任务不存在
        :raises APIError: 请求失败
        :example:
            >>> result = client.get_verify_result("verify_xyz789")
            >>> if result["verified"]:
            ...     print("漏洞确认存在")
        """
        return self._get(f"/api/v1/verify/result/{task_id}")

    # --------------------------------------------------------
    # 8-11. AI智能分析
    # --------------------------------------------------------

    def ai_chat(self, message: str, conversation_id: Optional[str] = None) -> Dict[str, Any]:
        """与AI安全助手进行对话。

        :param message: 用户输入消息
        :param conversation_id: 对话ID（可选，用于多轮对话保持上下文）
        :return: AI回复内容，包含response/conversation_id等
        :raises APIError: 请求失败
        :example:
            >>> result = client.ai_chat("什么是OWASP Top 10？")
            >>> print(result["response"])
        """
        payload = {"message": message}
        if conversation_id:
            payload["conversation_id"] = conversation_id
        return self._post("/api/v1/ai/chat", json=payload)

    def ai_verify_vuln(self, vuln_info: Dict) -> Dict[str, Any]:
        """使用AI智能分析验证漏洞真实性。

        :param vuln_info: 漏洞信息字典，包含url/vuln_type/payload/evidence等
        :return: AI验证结果，包含is_real/risk_score/explanation
        :raises ValidationError: 漏洞信息不完整
        :raises APIError: 请求失败
        :example:
            >>> vuln = {"url": "https://example.com", "vuln_type": "xss", "payload": "<script>alert(1)</script>"}
            >>> result = client.ai_verify_vuln(vuln)
        """
        return self._post("/api/v1/ai/verify", json=vuln_info)

    def ai_generate_remediation(self, vuln_info: Dict) -> Dict[str, Any]:
        """使用AI生成漏洞修复方案。

        :param vuln_info: 漏洞信息字典，包含vuln_type/cve_id/description等
        :return: 修复方案，包含steps/code_example/priority等
        :raises APIError: 请求失败
        :example:
            >>> vuln = {"vuln_type": "sql_injection", "cve_id": "CVE-2023-1234"}
            >>> result = client.ai_generate_remediation(vuln)
            >>> print(result["steps"])
        """
        return self._post("/api/v1/ai/remediation", json=vuln_info)

    def ai_assistant(self, query: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """AI安全助手，支持带上下文的智能问答。

        :param query: 用户问题
        :param context: 上下文信息字典（可选），如当前目标/漏洞详情
        :return: AI助手回复
        :raises APIError: 请求失败
        :example:
            >>> result = client.ai_assistant(
            ...     query="如何加固Nginx配置？",
            ...     context={"target": "example.com", "os": "ubuntu"}
            ... )
        """
        payload = {"query": query}
        if context:
            payload["context"] = context
        return self._post("/api/v1/ai/assistant", json=payload)

    # --------------------------------------------------------
    # 12-19. 工作流管理
    # --------------------------------------------------------

    def execute_workflow(
        self,
        template_id: str,
        target: str,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """执行预置工作流模板。

        :param template_id: 工作流模板ID，如pentest_full/web_security/mobile_security
        :param target: 扫描目标
        :param params: 额外参数字典（可选）
        :return: 工作流实例信息，包含instance_id/status
        :raises ValidationError: 模板ID或目标无效
        :raises APIError: 请求失败
        :example:
            >>> result = client.execute_workflow(
            ...     template_id="web_security",
            ...     target="https://example.com"
            ... )
            >>> print(result["instance_id"])
        """
        payload = {"template_id": template_id, "target": target}
        if params:
            payload["params"] = params
        return self._post("/api/v1/workflows/start", json=payload)

    def get_workflow_status(self, instance_id: str) -> Dict[str, Any]:
        """获取工作流执行状态。

        :param instance_id: 工作流实例ID
        :return: 状态信息，包含status/progress/current_step等
        :raises NotFoundError: 工作流实例不存在
        :raises APIError: 请求失败
        :example:
            >>> status = client.get_workflow_status("wf_abc123")
            >>> print(status["status"], status["progress"])
        """
        return self._get(f"/api/v1/workflows/{instance_id}")

    def get_workflow_result(self, instance_id: str) -> Dict[str, Any]:
        """获取工作流执行结果报告。

        :param instance_id: 工作流实例ID
        :return: 聚合后的工作流结果
        :raises NotFoundError: 工作流不存在或尚未完成
        :raises APIError: 请求失败
        :example:
            >>> result = client.get_workflow_result("wf_abc123")
            >>> print(result["summary"])
        """
        return self._get(f"/api/v1/workflows/{instance_id}/report")

    def get_workflow_steps(self, instance_id: str) -> Dict[str, Any]:
        """获取工作流各步骤的执行详情。

        :param instance_id: 工作流实例ID
        :return: 步骤列表，每步包含name/status/duration
        :raises NotFoundError: 工作流不存在
        :raises APIError: 请求失败
        """
        return self._get(f"/api/v1/workflows/{instance_id}/context")

    def get_workflow_logs(self, instance_id: str, limit: int = 100) -> Dict[str, Any]:
        """获取工作流执行日志。

        :param instance_id: 工作流实例ID
        :param limit: 返回日志条数上限（默认100）
        :return: 日志列表，按时间倒序
        :raises NotFoundError: 工作流不存在
        :raises APIError: 请求失败
        :example:
            >>> logs = client.get_workflow_logs("wf_abc123", limit=50)
            >>> for log in logs["logs"]:
            ...     print(log["timestamp"], log["message"])
        """
        params = {"limit": limit}
        return self._get(f"/api/v1/workflows/{instance_id}/logs", params=params)

    def cancel_workflow(self, instance_id: str) -> Dict[str, Any]:
        """取消正在执行的工作流。

        :param instance_id: 工作流实例ID
        :return: 取消操作结果
        :raises NotFoundError: 工作流不存在
        :raises APIError: 请求失败
        :example:
            >>> client.cancel_workflow("wf_abc123")
        """
        return self._post(f"/api/v1/workflows/{instance_id}/cancel")

    def list_workflow_templates(self) -> Dict[str, Any]:
        """获取所有可用的工作流模板列表。

        :return: 模板列表，每个模板包含id/name/description/category
        :raises APIError: 请求失败
        :example:
            >>> templates = client.list_workflow_templates()
            >>> for tpl in templates["templates"]:
            ...     print(tpl["id"], tpl["name"])
        """
        return self._get("/api/v1/workflows/templates")

    def get_workflow_template(self, template_id: str) -> Dict[str, Any]:
        """获取指定工作流模板的详细定义。

        :param template_id: 模板ID
        :return: 模板详情，包含steps/parameters/output_schema
        :raises NotFoundError: 模板不存在
        :raises APIError: 请求失败
        """
        return self._get(f"/api/v1/workflows/templates/{template_id}")

    # --------------------------------------------------------
    # 20-22. 报告管理
    # --------------------------------------------------------

    def generate_report(
        self,
        assessment_id: str,
        report_format: str = "html",
    ) -> Dict[str, Any]:
        """根据评估结果生成安全报告。

        :param assessment_id: 评估任务ID
        :param report_format: 报告格式，支持html/json/pdf/markdown
        :return: 报告信息，包含report_id/download_url
        :raises NotFoundError: 评估任务不存在
        :raises APIError: 请求失败
        :example:
            >>> result = client.generate_report("assess_abc123", "html")
            >>> report_id = result["report_id"]
        """
        payload = {"assessment_id": assessment_id, "format": report_format}
        return self._post("/api/v1/reporting/generate", json=payload)

    def download_report(self, report_id: str) -> bytes:
        """下载已生成的报告文件。

        :param report_id: 报告ID
        :return: 报告文件的二进制内容
        :raises NotFoundError: 报告不存在
        :raises APIError: 请求失败
        :example:
            >>> content = client.download_report("rep_xyz789")
            >>> with open("security_report.html", "wb") as f:
            ...     f.write(content)
        """
        return self._get(f"/api/v1/reporting/download/{report_id}")

    def list_reports(self, limit: int = 20) -> Dict[str, Any]:
        """获取历史报告列表。

        :param limit: 返回条数限制（默认20）
        :return: 报告列表，包含report_id/assessment_id/created_at
        :raises APIError: 请求失败
        """
        params = {"limit": limit}
        return self._get("/api/v1/reporting/formats", params=params)

    # --------------------------------------------------------
    # 23-26. 漏洞数据库
    # --------------------------------------------------------

    def search_cve(
        self,
        keyword: Optional[str] = None,
        product: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """搜索CVE漏洞数据库。

        :param keyword: 搜索关键词（可选）
        :param product: 产品名称筛选（可选）
        :param severity: 严重等级筛选：critical/high/medium/low（可选）
        :param page: 页码（默认1）
        :param page_size: 每页条数（默认20）
        :return: 搜索结果，包含items/total/page
        :raises APIError: 请求失败
        :example:
            >>> result = client.search_cve(keyword="nginx", severity="high")
            >>> for cve in result["items"]:
            ...     print(cve["cve_id"], cve["description"])
        """
        params = {"page": page, "page_size": page_size}
        if keyword:
            params["keyword"] = keyword
        if product:
            params["product"] = product
        if severity:
            params["severity"] = severity
        return self._get("/api/v1/vuln/search", params=params)

    def get_cve(self, cve_id: str) -> Dict[str, Any]:
        """获取单个CVE漏洞的详细信息。

        :param cve_id: CVE编号，如CVE-2023-1234
        :return: CVE详情，包含description/cvss_score/references/poc等
        :raises NotFoundError: CVE不存在
        :raises APIError: 请求失败
        :example:
            >>> cve = client.get_cve("CVE-2021-44228")
            >>> print(cve["cvss_score"], cve["description"])
        """
        return self._get(f"/api/v1/vuln/{cve_id}")

    def match_cve(self, service: str, version: str) -> Dict[str, Any]:
        """根据服务名称和版本号匹配已知CVE漏洞。

        :param service: 服务名称，如nginx/apache/openssh/openssl
        :param version: 版本号，如1.20.1
        :return: 匹配结果，包含matched_cves/risk_level/remediation
        :raises ValidationError: 服务名或版本号为空
        :raises APIError: 请求失败
        :example:
            >>> result = client.match_cve("openssl", "1.0.2g")
            >>> print(f"发现{len(result['matched_cves'])}个已知漏洞")
        """
        payload = {"service": service, "version": version}
        return self._post("/api/v1/vuln/match", json=payload)

    def get_remediation(self, cve_id: str) -> Dict[str, Any]:
        """获取指定CVE漏洞的修复方案。

        :param cve_id: CVE编号
        :return: 修复方案，包含patches/workarounds/priority/effort
        :raises NotFoundError: CVE不存在
        :raises APIError: 请求失败
        """
        return self._get(f"/api/v1/vuln/poc/{cve_id}")

    # --------------------------------------------------------
    # 27-28. 工具管理
    # --------------------------------------------------------

    def get_tool_status(self) -> Dict[str, Any]:
        """获取所有安全工具的安装状态和可用性。

        :return: 工具状态列表，每个工具包含name/version/installed/status
        :raises APIError: 请求失败
        :example:
            >>> status = client.get_tool_status()
            >>> for tool in status["tools"]:
            ...     print(tool["name"], tool["installed"])
        """
        return self._get("/api/v1/tools/manager/stats")

    def install_tool(self, tool_name: str) -> Dict[str, Any]:
        """安装指定的安全工具。

        :param tool_name: 工具名称，如nmap/nucleo/metasploit/sqlmap
        :return: 安装结果，包含status/message
        :raises NotFoundError: 工具不存在
        :raises APIError: 安装失败或请求失败
        :example:
            >>> result = client.install_tool("nmap")
            >>> print(result["message"])
        """
        return self._post("/api/v1/tools/manager/check", json={"tool_name": tool_name})

    # --------------------------------------------------------
    # 29-32. 可视化与分析
    # --------------------------------------------------------

    def get_attack_path(
        self,
        assessment_id: Optional[str] = None,
        scan_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """生成攻击路径可视化数据。

        :param assessment_id: 评估任务ID（与scan_data二选一）
        :param scan_data: 原始扫描数据字典（可选）
        :return: 攻击路径图数据，包含nodes/edges/risk_path
        :raises ValidationError: 参数不完整
        :raises APIError: 请求失败
        :example:
            >>> path = client.get_attack_path(assessment_id="assess_abc123")
            >>> print(path["risk_path"])
        """
        payload = {}
        if assessment_id:
            payload["assessment_id"] = assessment_id
        if scan_data:
            payload["scan_data"] = scan_data
        return self._post("/api/v1/analytics/top/vulnerabilities", json=payload)

    def get_network_topology(
        self,
        assessment_id: Optional[str] = None,
        scan_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """生成网络拓扑图数据。

        :param assessment_id: 评估任务ID
        :param scan_data: 原始扫描数据字典
        :return: 拓扑图数据，包含nodes(主机)/edges(连接)/services
        :raises APIError: 请求失败
        """
        payload = {}
        if assessment_id:
            payload["assessment_id"] = assessment_id
        if scan_data:
            payload["scan_data"] = scan_data
        return self._post("/api/v1/analytics/export", json=payload)

    def get_risk_heatmap(
        self,
        scan_data: Dict,
        dimension: str = "host_port",
    ) -> Dict[str, Any]:
        """生成风险热力图数据。

        :param scan_data: 扫描数据字典
        :param dimension: 热力图维度，host_port/service/severity（默认host_port）
        :return: 热力图数据，包含grid/labels/values
        :raises ValidationError: scan_data为空
        :raises APIError: 请求失败
        """
        payload = {"scan_data": scan_data, "dimension": dimension}
        return self._post("/api/v1/analytics/export", json=payload)

    def get_analytics_trend(self, metric: str = "vulnerability") -> Dict[str, Any]:
        """获取安全指标趋势分析数据。

        :param metric: 指标类型：vulnerability/risk/scan/coverage
        :return: 趋势数据，包含timeline/values/change_rate
        :raises APIError: 请求失败
        :example:
            >>> trend = client.get_analytics_trend("vulnerability")
            >>> print(trend["change_rate"])
        """
        params = {"metric": metric}
        return self._get("/api/v1/analytics/trends/vulnerabilities", params=params)

    # --------------------------------------------------------
    # 33. 漏洞列表查询
    # --------------------------------------------------------

    def list_vulnerabilities(
        self,
        assessment_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """获取漏洞列表，支持按评估ID和严重等级筛选。

        :param assessment_id: 评估任务ID筛选（可选）
        :param severity: 严重等级筛选：critical/high/medium/low（可选）
        :param limit: 返回条数上限（默认50）
        :return: 漏洞列表，包含items/total
        :raises APIError: 请求失败
        :example:
            >>> vulns = client.list_vulnerabilities(severity="critical")
            >>> print(f"发现{len(vulns['items'])}个严重漏洞")
        """
        params = {"limit": limit}
        if assessment_id:
            params["assessment_id"] = assessment_id
        if severity:
            params["severity"] = severity
        return self._get("/api/v1/vuln/recent", params=params)

    # --------------------------------------------------------
    # 34-35. 自定义工作流
    # --------------------------------------------------------

    def create_custom_workflow(
        self,
        name: str,
        workflow_def: Dict,
    ) -> Dict[str, Any]:
        """创建自定义工作流模板。

        :param name: 工作流名称
        :param workflow_def: 工作流定义字典，包含steps/triggers/parameters
        :return: 创建结果，包含template_id
        :raises ValidationError: 工作流定义不合法
        :raises APIError: 请求失败
        :example:
            >>> wf = {
            ...     "steps": [{"name": "nmap_scan", "tool": "nmap"},
            ...               {"name": "web_scan", "tool": "nuclei"}],
            ...     "description": "自定义扫描流程"
            ... }
            >>> result = client.create_custom_workflow("我的扫描", wf)
        """
        payload = {"name": name, "definition": workflow_def}
        return self._post("/api/v1/workflows/templates", json=payload)

    def list_custom_workflows(self) -> Dict[str, Any]:
        """获取所有自定义工作流模板列表。

        :return: 自定义工作流列表
        :raises APIError: 请求失败
        """
        return self._get("/api/v1/workflows/templates")

    # --------------------------------------------------------
    # 附加：便捷轮询方法
    # --------------------------------------------------------

    def poll_until_done(
        self,
        check_func,
        interval: float = 5.0,
        timeout: int = 600,
        status_field: str = "status",
        done_statuses: list = None,
    ) -> Dict[str, Any]:
        """轮询等待异步任务完成。

        :param check_func: 无参调用函数，返回包含状态字段的字典
        :param interval: 轮询间隔秒数（默认5秒）
        :param timeout: 总超时秒数（默认600秒）
        :param status_field: 状态字段名（默认status）
        :param done_statuses: 完成状态集合，默认["completed", "done", "success", "failed", "error", "cancelled"]
        :return: 最终检查结果
        :raises TimeoutError: 超过超时时间仍未完成
        :raises APIError: 检查过程中API错误
        :example:
            >>> result = client.poll_until_done(
            ...     lambda: client.get_assessment("assess_123"),
            ...     interval=10, timeout=300
            ... )
        """
        if done_statuses is None:
            done_statuses = ["completed", "done", "success", "failed", "error", "cancelled", "finished"]
        start_time = time.time()
        while True:
            result = check_func()
            status = result.get(status_field, "").lower()
            if status in done_statuses:
                return result
            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"任务超时（{timeout}秒），当前状态：{status}")
            time.sleep(interval)

    def close(self):
        """关闭HTTP会话，释放连接资源。"""
        if self._session:
            self._session.close()

    def __enter__(self):
        """上下文管理器入口。"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出，自动关闭会话。"""
        self.close()
