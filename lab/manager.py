#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manager模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import os
import sys
import time
import subprocess
import socket
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from utils.logger import log


@dataclass
class LabInstance:
    """靶场实例"""
    lab_id: str
    name: str
    description: str
    port: int
    status: str = "stopped"  # stopped/running/error
    url: str = ""
    process: Optional[subprocess.Popen] = None
    start_time: Optional[float] = None
    vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "lab_id": self.lab_id,
            "name": self.name,
            "description": self.description,
            "port": self.port,
            "status": self.status,
            "url": self.url,
            "start_time": self.start_time,
            "uptime_seconds": round(time.time() - self.start_time, 2) if self.start_time and self.status == "running" else 0,
            "vulnerabilities": self.vulnerabilities
        }


class VulnerableLabManager:
    """漏洞靶场管理器"""

    def __init__(self):
        """初始化VulnerableLabManager实例。

        Args:
            self: 类实例。
        """
        self.labs: Dict[str, LabInstance] = {}
        self._lab_processes: Dict[str, subprocess.Popen] = {}

        # 注册内置靶场
        self._register_builtin_labs()

    def _register_builtin_labs(self):
        """注册内置靶场"""
        # 简易漏洞靶场（纯Python Flask）
        self.labs["simple-vuln-lab"] = LabInstance(
            lab_id="simple-vuln-lab",
            name="简易漏洞靶场",
            description="纯Python Flask实现的漏洞靶场，包含SQL注入/XSS/命令注入/文件上传/SSRF/IDOR/弱口令等常见漏洞，适合演示和测试",
            port=9000,
            vulnerabilities=[
                "SQL注入 (GET参数id)",
                "反射型XSS (搜索参数q)",
                "存储型XSS (留言板)",
                "命令注入 (ping功能host参数)",
                "文件上传漏洞 (上传webshell)",
                "SSRF (url获取功能)",
                "IDOR (用户信息遍历)",
                "弱口令 (admin/admin)",
                "目录遍历 (文件下载)",
                "XXE (XML解析)"
            ]
        )

        # DVWA（Docker方式）
        self.labs["dvwa"] = LabInstance(
            lab_id="dvwa",
            name="DVWA (Damn Vulnerable Web App)",
            description="PHP/MySQL实现的经典漏洞靶场，包含暴力破解/命令注入/CSRF/文件包含/文件上传/SQL注入/XSS等。需要Docker环境。",
            port=8080,
            vulnerabilities=[
                "暴力破解",
                "命令注入",
                "CSRF",
                "文件包含",
                "文件上传",
                "SQL注入",
                "SQL注入(盲注)",
                "反射型XSS",
                "存储型XSS",
                "DOM型XSS"
            ]
        )

        # Juice Shop（Docker方式）
        self.labs["juice-shop"] = LabInstance(
            lab_id="juice-shop",
            name="OWASP Juice Shop",
            description="OWASP官方维护的现代Web应用靶场，包含100+个挑战，覆盖OWASP Top 10所有漏洞。需要Docker环境。",
            port=3000,
            vulnerabilities=[
                "SQL注入",
                "XSS",
                "CSRF",
                "SSRF",
                "XXE",
                "文件上传",
                "路径遍历",
                "JWT攻击",
                "OAuth漏洞",
                "API漏洞"
            ]
        )

    def list_labs(self) -> List[Dict[str, Any]]:
        """列出所有靶场"""
        return [lab.to_dict() for lab in self.labs.values()]

    def get_lab(self, lab_id: str) -> Optional[LabInstance]:
        """获取靶场信息"""
        return self.labs.get(lab_id)

    def check_docker_available(self) -> bool:
        """检查Docker是否可用"""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def check_port_available(self, port: int) -> bool:
        """检查端口是否可用"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("127.0.0.1", port))
                return result != 0
        except Exception:
            return True

    async def start_lab(self, lab_id: str, port: int = None) -> Dict[str, Any]:
        """启动靶场"""
        lab = self.labs.get(lab_id)
        if not lab:
            return {"status": "error", "message": f"靶场不存在: {lab_id}"}

        if lab.status == "running":
            return {"status": "error", "message": f"靶场已在运行: {lab.url}"}

        target_port = port or lab.port

        # 检查端口
        if not self.check_port_available(target_port):
            return {"status": "error", "message": f"端口 {target_port} 已被占用，请换个端口"}

        if lab_id == "simple-vuln-lab":
            return await self._start_simple_lab(lab, target_port)
        elif lab_id == "dvwa":
            return await self._start_docker_lab(lab, "vulnerables/web-dvwa", target_port, "80")
        elif lab_id == "juice-shop":
            return await self._start_docker_lab(lab, "bkimminich/juice-shop", target_port, "3000")
        else:
            return {"status": "error", "message": f"不支持的靶场类型: {lab_id}"}

    async def _start_simple_lab(self, lab: LabInstance, port: int) -> Dict[str, Any]:
        """启动简易漏洞靶场（纯Python Flask）"""
        try:
            # 生成靶场脚本
            lab_script = self._generate_simple_lab_script(port)
            script_path = os.path.join(os.path.dirname(__file__), "simple_vuln_lab.py")

            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(lab_script)

            # 启动Flask应用
            env = os.environ.copy()
            env["FLASK_APP"] = script_path
            env["FLASK_ENV"] = "development"

            process = subprocess.Popen(
                [sys.executable, script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )

            # 等待启动
            await asyncio.sleep(3)

            # 检查是否启动成功
            if process.poll() is not None:
                stderr = process.stderr.read().decode('utf-8', errors='replace')
                return {"status": "error", "message": f"靶场启动失败: {stderr[:500]}"}

            lab.process = process
            lab.status = "running"
            lab.port = port
            lab.url = f"http://127.0.0.1:{port}"
            lab.start_time = time.time()
            self._lab_processes[lab.lab_id] = process

            log.info(f"简易漏洞靶场启动成功: {lab.url}")
            return {
                "status": "success",
                "message": f"靶场启动成功: {lab.name}",
                "url": lab.url,
                "port": port,
                "default_credentials": "admin/admin",
                "vulnerabilities": lab.vulnerabilities
            }

        except Exception as e:
            log.error(f"启动简易靶场失败: {e}")
            return {"status": "error", "message": f"启动失败: {str(e)}"}

    async def _start_docker_lab(self, lab: LabInstance, image: str, host_port: int, container_port: str) -> Dict[str, Any]:
        """启动Docker靶场"""
        if not self.check_docker_available():
            return {
                "status": "error",
                "message": "Docker未安装或不可用。请先安装Docker Desktop，或使用纯Python简易靶场(simple-vuln-lab)。"
            }

        try:
            # 拉取镜像（如果不存在）
            log.info(f"拉取Docker镜像: {image}")
            pull_result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True, text=True, timeout=300
            )

            # 启动容器
            container_name = f"ai-hacking-{lab.lab_id}"
            run_result = subprocess.run(
                ["docker", "run", "-d", "--name", container_name,
                 "-p", f"{host_port}:{container_port}",
                 "--rm", image],
                capture_output=True, text=True, timeout=60
            )

            if run_result.returncode != 0:
                return {"status": "error", "message": f"容器启动失败: {run_result.stderr[:500]}"}

            lab.status = "running"
            lab.port = host_port
            lab.url = f"http://127.0.0.1:{host_port}"
            lab.start_time = time.time()

            log.info(f"Docker靶场启动成功: {lab.url}")
            return {
                "status": "success",
                "message": f"靶场启动成功: {lab.name}",
                "url": lab.url,
                "port": host_port,
                "container_name": container_name,
                "vulnerabilities": lab.vulnerabilities
            }

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Docker操作超时，镜像拉取可能需要较长时间"}
        except Exception as e:
            return {"status": "error", "message": f"启动失败: {str(e)}"}

    async def stop_lab(self, lab_id: str) -> Dict[str, Any]:
        """停止靶场"""
        lab = self.labs.get(lab_id)
        if not lab:
            return {"status": "error", "message": f"靶场不存在: {lab_id}"}

        if lab.status != "running":
            return {"status": "error", "message": "靶场未在运行"}

        try:
            if lab_id == "simple-vuln-lab":
                # 停止Python进程
                process = self._lab_processes.get(lab_id)
                if process:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    del self._lab_processes[lab_id]
            else:
                # 停止Docker容器
                container_name = f"ai-hacking-{lab_id}"
                subprocess.run(
                    ["docker", "stop", container_name],
                    capture_output=True, timeout=30
                )

            lab.status = "stopped"
            lab.process = None
            lab.start_time = None

            log.info(f"靶场已停止: {lab_id}")
            return {"status": "success", "message": f"靶场已停止: {lab.name}"}

        except Exception as e:
            return {"status": "error", "message": f"停止失败: {str(e)}"}

    def _generate_simple_lab_script(self, port: int) -> str:
        """生成简易漏洞靶场的Flask脚本"""
        return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简易漏洞靶场 - Simple Vulnerable Lab
包含：SQL注入/XSS/命令注入/文件上传/SSRF/IDOR/目录遍历/弱口令
WARNING: 仅用于安全测试和学习，禁止用于非法用途！
"""
from flask import Flask, request, render_template_string, redirect, session, jsonify, send_file
import os
import sqlite3
import subprocess
import urllib.request

app = Flask(__name__)
app.secret_key = "vulnerable-lab-secret-key"

# 初始化数据库
def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin', 'admin@lab.com', 'admin')")
    c.execute("INSERT INTO users VALUES (2, 'user1', '123456', 'user1@lab.com', 'user')")
    c.execute("INSERT INTO users VALUES (3, 'user2', 'password', 'user2@lab.com', 'user')")
    c.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, username TEXT, content TEXT)")
    conn.commit()
    return conn

DB = init_db()

@app.route("/")
def index():
    return """
    <h1>简易漏洞靶场</h1>
    <ul>
        <li><a href="/login">登录 (弱口令 admin/admin)</a></li>
        <li><a href="/sqli?id=1">SQL注入</a></li>
        <li><a href="/xss?q=test">反射型XSS</a></li>
        <li><a href="/comment">存储型XSS (留言板)</a></li>
        <li><a href="/ping?host=127.0.0.1">命令注入</a></li>
        <li><a href="/upload">文件上传</a></li>
        <li><a href="/fetch?url=http://127.0.0.1">SSRF</a></li>
        <li><a href="/user?id=1">IDOR</a></li>
        <li><a href="/download?file=test.txt">目录遍历</a></li>
    </ul>
    """

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        c = DB.cursor()
        c.execute(f"SELECT * FROM users WHERE username='{{username}}' AND password='{{password}}'")
        user = c.fetchone()
        if user:
            session["user"] = user[1]
            return f"<h1>登录成功</h1><p>欢迎, {{user[1]}} ({{user[4]}})</p><a href='/'>返回</a>"
        return "<h1>登录失败</h1><a href='/login'>重试</a>"
    return """
    <form method="POST">
        <input name="username" placeholder="用户名"><br>
        <input name="password" type="password" placeholder="密码"><br>
        <button type="submit">登录</button>
    </form>
    <p>提示: admin/admin</p>
    """

@app.route("/sqli")
def sqli():
    user_id = request.args.get("id", "1")
    c = DB.cursor()
    try:
        c.execute(f"SELECT id, username, email, role FROM users WHERE id={{user_id}}")
        users = c.fetchall()
        result = "<h2>SQL注入测试</h2><table border='1'><tr><th>ID</th><th>用户名</th><th>邮箱</th><th>角色</th></tr>"
        for u in users:
            result += f"<tr><td>{{u[0]}}</td><td>{{u[1]}}</td><td>{{u[2]}}</td><td>{{u[3]}}</td></tr>"
        result += "</table>"
        return result
    except Exception as e:
        return f"<h2>SQL错误</h2><pre>{{str(e)}}</pre>"

@app.route("/xss")
def xss():
    q = request.args.get("q", "")
    return f"<h1>搜索结果</h1><p>您搜索的内容: {{q}}</p><a href='/'>返回</a>"

@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "POST":
        username = request.form.get("username", "anonymous")
        content = request.form.get("content", "")
        c = DB.cursor()
        c.execute(f"INSERT INTO messages (username, content) VALUES ('{{username}}', '{{content}}')")
        DB.commit()
    c = DB.cursor()
    c.execute("SELECT username, content FROM messages")
    messages = c.fetchall()
    html = "<h1>留言板 (存储型XSS)</h1>"
    for m in messages:
        html += f"<p><b>{{m[0]}}</b>: {{m[1]}}</p>"
    html += """
    <form method="POST">
        <input name="username" placeholder="用户名"><br>
        <textarea name="content" placeholder="留言内容"></textarea><br>
        <button type="submit">提交</button>
    </form>
    <a href='/'>返回</a>
    """
    return html

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        result = subprocess.check_output(f"ping -n 2 {{host}}", shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"<h1>Ping结果</h1><pre>{{result.decode('utf-8', errors='replace')}}</pre><a href='/'>返回</a>"
    except Exception as e:
        return f"<h1>执行结果</h1><pre>{{str(e)}}</pre><a href='/'>返回</a>"

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            filepath = os.path.join("uploads", f.filename)
            os.makedirs("uploads", exist_ok=True)
            f.save(filepath)
            return f"<h1>上传成功</h1><p>文件: {{f.filename}}</p><p>路径: {{filepath}}</p><a href='/'>返回</a>"
    return """
    <h1>文件上传漏洞</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file"><br>
        <button type="submit">上传</button>
    </form>
    <a href='/'>返回</a>
    """

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "http://127.0.0.1")
    try:
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode("utf-8", errors="replace")[:2000]
        return f"<h1>SSRF测试</h1><p>请求URL: {{url}}</p><pre>{{content}}</pre><a href='/'>返回</a>"
    except Exception as e:
        return f"<h1>SSRF结果</h1><pre>{{str(e)}}</pre><a href='/'>返回</a>"

@app.route("/user")
def user_info():
    user_id = request.args.get("id", "1")
    c = DB.cursor()
    c.execute(f"SELECT id, username, email, role FROM users WHERE id={{user_id}}")
    user = c.fetchone()
    if user:
        return f"<h1>用户信息 (IDOR测试)</h1><p>ID: {{user[0]}}</p><p>用户名: {{user[1]}}</p><p>邮箱: {{user[2]}}</p><p>角色: {{user[3]}}</p><a href='/'>返回</a>"
    return "<h1>用户不存在</h1><a href='/'>返回</a>"

@app.route("/download")
def download():
    filename = request.args.get("file", "test.txt")
    try:
        filepath = os.path.join(".", filename)
        with open(filepath, "r") as f:
            content = f.read()
        return f"<h1>文件内容 (目录遍历测试)</h1><pre>{{content[:2000]}}</pre><a href='/'>返回</a>"
    except Exception as e:
        return f"<h1>读取失败</h1><pre>{{str(e)}}</pre><a href='/'>返回</a>"

if __name__ == "__main__":
    print(f"简易漏洞靶场启动: http://127.0.0.1:{port}")
    print("WARNING: 仅用于安全测试和学习！")
    app.run(host="127.0.0.1", port={port}, debug=False)
'''


# 全局实例
lab_manager = VulnerableLabManager()
