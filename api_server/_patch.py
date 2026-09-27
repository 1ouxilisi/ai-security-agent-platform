p = r'E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\api_server\ai_security_console.html'
s = open(p, encoding='utf-8').read()

# 1. 加靶场tab
old = '<div class="tab" onclick="sw(event,\'intel\')">威胁情报</div>\n  <div class="tab" onclick="sw(event,\'payloads\')">Payload库</div>'
new = '<div class="tab" onclick="sw(event,\'intel\')">威胁情报</div>\n  <div class="tab" onclick="sw(event,\'range\')">靶场环境</div>\n  <div class="tab" onclick="sw(event,\'payloads\')">Payload库</div>'
s = s.replace(old, new)

# 2. 加靶场panel（在payloads panel前面）
range_panel = '''
  <div class="panel" id="p-range">
    <div class="card">
      <h3>靶场环境一键部署</h3>
      <p>合法练习环境，用于演示和测试扫描能力</p>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:10px">
        <div style="background:#0f172a;padding:14px;border-radius:8px;border-left:3px solid #ef4444">
          <b style="color:#ef4444">DVWA</b>
          <p style="margin:8px 0 4px;font-size:11px">Damn Vulnerable Web App - 练习SQLi/XSS/RFI</p>
          <pre style="font-size:10px;color:#22c55e;background:#000;padding:8px;border-radius:4px">docker run -d -p 8080:80 vulnerables/web-dvwa</pre>
          <button onclick="window.open('http://localhost:8080','_blank')" class="btn-green" style="margin-top:8px">打开DVWA</button>
        </div>
        <div style="background:#0f172a;padding:14px;border-radius:8px;border-left:3px solid #eab308">
          <b style="color:#eab308">Juice Shop</b>
          <p style="margin:8px 0 4px;font-size:11px">OWASP Juice Shop - 现代Web漏洞练习</p>
          <pre style="font-size:10px;color:#22c55e;background:#000;padding:8px;border-radius:4px">docker run -d -p 3000:3000 bkimminich/juice-shop</pre>
          <button onclick="window.open('http://localhost:3000','_blank')" class="btn-green" style="margin-top:8px">打开Juice Shop</button>
        </div>
        <div style="background:#0f172a;padding:14px;border-radius:8px;border-left:3px solid #38bdf8">
          <b style="color:#38bdf8">WebGoat</b>
          <p style="margin:8px 0 4px;font-size:11px">OWASP WebGoat - 安全教学靶场</p>
          <pre style="font-size:10px;color:#22c55e;background:#000;padding:8px;border-radius:4px">docker run -d -p 8081:8080 webgoat/webgoat</pre>
          <button onclick="window.open('http://localhost:8081/WebGoat','_blank')" class="btn-green" style="margin-top:8px">打开WebGoat</button>
        </div>
        <div style="background:#0f172a;padding:14px;border-radius:8px;border-left:3px solid #a78bfa">
          <b style="color:#a78bfa">Vulnerable API</b>
          <p style="margin:8px 0 4px;font-size:11px">VAmPI - API安全练习</p>
          <pre style="font-size:10px;color:#22c55e;background:#000;padding:8px;border-radius:4px">docker run -d -p 5000:5000 ehess/vampi</pre>
          <button onclick="window.open('http://localhost:5000','_blank')" class="btn-green" style="margin-top:8px">打开VAmPI</button>
        </div>
      </div>
      <div style="margin-top:14px;padding:10px;background:#1e3a5f;border-radius:6px;font-size:11px;color:#93c5fd">
        <b>使用方法:</b> 先确保Docker Desktop已启动，复制上面命令到PowerShell运行，等容器启动后点"打开"按钮。然后回到"一键扫描"输入 localhost:8080 等地址测试。
      </div>
    </div>
  </div>

  <div class="panel" id="p-payloads">'''
s = s.replace('  <div class="panel" id="p-payloads">', range_panel, 1)

# 3. 扫描页加打印PDF按钮
s = s.replace('<button onclick="exportHTML()" class="btn-blue" style="margin-left:8px">导出HTML报告</button>',
              '<button onclick="exportHTML()" class="btn-blue" style="margin-left:8px">导出HTML报告</button>\n      <button onclick="printReport()" style="background:#dc2626;margin-left:8px">打印PDF</button>')

# 4. 加printReport函数
s = s.replace("function exportHTML(){",
"""function printReport(){
  if(!lastReport){alert('先运行扫描');return}
  const w=window.open('','_blank');
  w.document.write('<html><head><title>安全报告PDF</title><style>body{font-family:monospace;padding:40px;white-space:pre-wrap;font-size:12px}</style></head><body><h1>AI安全扫描报告</h1><p>'+new Date().toLocaleString()+'</p><pre>'+lastReport.replace(/</g,'&lt;')+'</pre></body></html>');
  w.document.close();w.print();
}
function exportHTML(){""")

open(p, 'w', encoding='utf-8').write(s)
print('done, size:', len(s))
