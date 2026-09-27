#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simple_vuln_lab模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
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
    """初始化相关组件。

        Returns:
            操作结果。
    """
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
    """在...中。

        Returns:
            操作结果。
    """
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
    """在...中。

        Returns:
            操作结果。
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        c = DB.cursor()
        c.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        user = c.fetchone()
        if user:
            session["user"] = user[1]
            return f"<h1>登录成功</h1><p>欢迎, {user[1]} ({user[4]})</p><a href='/'>返回</a>"
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
    """执行相关操作。

        Returns:
            操作结果。
    """
    user_id = request.args.get("id", "1")
    c = DB.cursor()
    try:
        c.execute(f"SELECT id, username, email, role FROM users WHERE id={user_id}")
        users = c.fetchall()
        result = "<h2>SQL注入测试</h2><table border='1'><tr><th>ID</th><th>用户名</th><th>邮箱</th><th>角色</th></tr>"
        for u in users:
            result += f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td><td>{u[3]}</td></tr>"
        result += "</table>"
        return result
    except Exception as e:
        return f"<h2>SQL错误</h2><pre>{str(e)}</pre>"

@app.route("/xss")
def xss():
    """执行相关操作。

        Returns:
            操作结果。
    """
    q = request.args.get("q", "")
    return f"<h1>搜索结果</h1><p>您搜索的内容: {q}</p><a href='/'>返回</a>"

@app.route("/comment", methods=["GET", "POST"])
def comment():
    """执行相关操作。

        Returns:
            操作结果。
    """
    if request.method == "POST":
        username = request.form.get("username", "anonymous")
        content = request.form.get("content", "")
        c = DB.cursor()
        c.execute(f"INSERT INTO messages (username, content) VALUES ('{username}', '{content}')")
        DB.commit()
    c = DB.cursor()
    c.execute("SELECT username, content FROM messages")
    messages = c.fetchall()
    html = "<h1>留言板 (存储型XSS)</h1>"
    for m in messages:
        html += f"<p><b>{m[0]}</b>: {m[1]}</p>"
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
    """在...中。

        Returns:
            操作结果。
    """
    host = request.args.get("host", "127.0.0.1")
    try:
        result = subprocess.check_output(f"ping -n 2 {host}", shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"<h1>Ping结果</h1><pre>{result.decode('utf-8', errors='replace')}</pre><a href='/'>返回</a>"
    except Exception as e:
        return f"<h1>执行结果</h1><pre>{str(e)}</pre><a href='/'>返回</a>"

@app.route("/upload", methods=["GET", "POST"])
def upload():
    """加载相关数据。

        Returns:
            操作结果。
    """
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            filepath = os.path.join("uploads", f.filename)
            os.makedirs("uploads", exist_ok=True)
            f.save(filepath)
            return f"<h1>上传成功</h1><p>文件: {f.filename}</p><p>路径: {filepath}</p><a href='/'>返回</a>"
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
    """执行相关操作。

        Returns:
            操作结果。
    """
    url = request.args.get("url", "http://127.0.0.1")
    try:
        response = urllib.request.urlopen(url, timeout=5)
        content = response.read().decode("utf-8", errors="replace")[:2000]
        return f"<h1>SSRF测试</h1><p>请求URL: {url}</p><pre>{content}</pre><a href='/'>返回</a>"
    except Exception as e:
        return f"<h1>SSRF结果</h1><pre>{str(e)}</pre><a href='/'>返回</a>"

@app.route("/user")
def user_info():
    """在...中。

        Returns:
            操作结果。
    """
    user_id = request.args.get("id", "1")
    c = DB.cursor()
    c.execute(f"SELECT id, username, email, role FROM users WHERE id={user_id}")
    user = c.fetchone()
    if user:
        return f"<h1>用户信息 (IDOR测试)</h1><p>ID: {user[0]}</p><p>用户名: {user[1]}</p><p>邮箱: {user[2]}</p><p>角色: {user[3]}</p><a href='/'>返回</a>"
    return "<h1>用户不存在</h1><a href='/'>返回</a>"

@app.route("/download")
def download():
    """加载相关数据。

        Returns:
            操作结果。
    """
    filename = request.args.get("file", "test.txt")
    try:
        filepath = os.path.join(".", filename)
        with open(filepath, "r") as f:
            content = f.read()
        return f"<h1>文件内容 (目录遍历测试)</h1><pre>{content[:2000]}</pre><a href='/'>返回</a>"
    except Exception as e:
        return f"<h1>读取失败</h1><pre>{str(e)}</pre><a href='/'>返回</a>"

if __name__ == "__main__":
    print(f"简易漏洞靶场启动: http://127.0.0.1:9000")
    print("WARNING: 仅用于安全测试和学习！")
    app.run(host="127.0.0.1", port=9000, debug=False)
