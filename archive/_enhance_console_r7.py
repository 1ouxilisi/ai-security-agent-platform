# -*- coding: utf-8 -*-
with open('api_server/console.html', 'r', encoding='utf-8') as f:
    c = f.read()

# 1. tab-bar添加2个新Tab（在系统配置之后）
old_tab = '    <div class="tab" onclick="switchTab(\'sysconfig\')">系统配置</div>'
new_tab = old_tab
new_tab += '\n    <div class="tab" onclick="switchTab(\'workflow\')">统一工作流</div>'
new_tab += '\n    <div class="tab" onclick="switchTab(\'overview\')">总览仪表盘</div>'
c = c.replace(old_tab, new_tab)

# 2. 在MCP tab-content之前添加2个新面板
mcp_marker = '  <div class="tab-content" id="tab-mcp">'
new_panels = '''  <div class="tab-content" id="tab-workflow">
    <div class="card">
      <h3>统一作战工作流</h3>
      <p style="color:#94a3b8;font-size:13px;margin-bottom:10px">一键执行：侦察→扫描→攻击链分析→风险评分→报告生成→自动入库→审计日志</p>
      <div class="row">
        <input type="text" id="wf-target" placeholder="目标IP/域名" style="flex:2">
        <select id="wf-type">
          <option value="full">全流程(推荐)</option>
          <option value="recon">仅侦察</option>
          <option value="scan">侦察+扫描</option>
          <option value="report">仅报告</option>
        </select>
        <select id="wf-depth">
          <option value="quick">快速</option>
          <option value="standard" selected>标准</option>
          <option value="deep">深度</option>
        </select>
      </div>
      <div class="row" style="margin-top:8px">
        <label style="font-size:12px;color:#94a3b8"><input type="checkbox" id="wf-auto-vuln" checked> 自动入库漏洞管理</label>
        <label style="font-size:12px;color:#94a3b8"><input type="checkbox" id="wf-auto-asset" checked> 自动入库资产管理</label>
        <label style="font-size:12px;color:#94a3b8"><input type="checkbox" id="wf-auto-audit" checked> 自动记录审计日志</label>
      </div>
      <button onclick="startWorkflow()" style="margin-top:10px">启动全流程工作流</button>
      <div id="wf-result" style="margin-top:15px;display:none"></div>
      <div id="wf-progress" style="margin-top:15px;display:none">
        <div style="background:#1e293b;border-radius:8px;padding:10px;margin-bottom:10px">
          <div id="wf-progress-bar" style="height:6px;background:#334155;border-radius:3px;overflow:hidden"><div id="wf-progress-fill" style="height:100%;background:linear-gradient(90deg,#38bdf8,#818cf8);width:0%;transition:width 0.5s"></div></div>
          <div id="wf-progress-text" style="font-size:12px;color:#94a3b8;margin-top:5px">初始化...</div>
        </div>
        <div id="wf-steps" style="font-size:13px"></div>
      </div>
    </div>
    <div class="card" style="margin-top:15px">
      <h4>工作流任务列表</h4>
      <button onclick="loadWorkflowTasks()" style="margin-bottom:10px">刷新任务</button>
      <div id="wf-tasks" style="font-size:13px"></div>
    </div>
  </div>
  <div class="tab-content" id="tab-overview">
    <div class="card">
      <h3>总览仪表盘</h3>
      <div id="overview-health" style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:15px 0;text-align:center"></div>
      <div id="overview-modules" style="margin-top:15px"></div>
      <button onclick="loadOverview()" style="margin-top:10px">刷新总览</button>
    </div>
  </div>
  <div class="tab-content" id="tab-mcp">'''
c = c.replace(mcp_marker, new_panels)

# 3. script添加新函数
script_end = '</script>'
new_funcs = '''
async function startWorkflow() {
  const target = document.getElementById('wf-target').value.trim();
  if(!target) return alert('请输入目标');
  document.getElementById('wf-result').style.display = 'none';
  document.getElementById('wf-progress').style.display = 'block';
  document.getElementById('wf-steps').innerHTML = '';
  const r = await api('/api/v1/workflow/run','POST',{
    target, workflow_type: document.getElementById('wf-type').value,
    depth: document.getElementById('wf-depth').value,
    auto_create_vuln: document.getElementById('wf-auto-vuln').checked,
    auto_create_asset: document.getElementById('wf-auto-asset').checked,
    auto_audit: document.getElementById('wf-auto-audit').checked
  });
  if(r.success) {
    const taskId = r.data.task_id;
    document.getElementById('wf-progress-text').textContent = '任务已启动: '+taskId+'，正在执行...';
    pollWorkflow(taskId);
  } else {
    document.getElementById('wf-progress-text').textContent = '启动失败: '+r.error;
  }
}
async function pollWorkflow(taskId) {
  const r = await api('/api/v1/workflow/tasks/'+taskId);
  if(!r.success) return;
  const d = r.data;
  document.getElementById('wf-progress-fill').style.width = d.progress+'%';
  document.getElementById('wf-progress-text').textContent = d.current_step+' ('+d.progress+'%) - '+d.status_label;
  let stepsHtml = '';
  (d.steps||[]).forEach(function(s){
    const icon = s.status==='completed' ? '✅' : s.status==='running' ? '⏳' : '⬜';
    stepsHtml += '<div style="padding:4px 0">'+icon+' '+s.step_name+(s.detail?' - '+s.detail:'')+'</div>';
  });
  document.getElementById('wf-steps').innerHTML = stepsHtml;
  if(d.status === 'running' || d.status === 'pending') {
    setTimeout(function(){ pollWorkflow(taskId); }, 3000);
  } else if(d.status === 'completed') {
    document.getElementById('wf-progress-text').textContent = '✅ 完成! 耗时: '+(d.duration_ms/1000).toFixed(1)+'秒';
    showWorkflowResult(d.result);
  } else {
    document.getElementById('wf-progress-text').textContent = '❌ 失败: '+d.error;
  }
}
function showWorkflowResult(result) {
  const div = document.getElementById('wf-result');
  div.style.display = 'block';
  let html = '<div style="background:#1e293b;border-radius:8px;padding:15px;margin-top:10px">';
  html += '<h4 style="margin-bottom:10px">工作流结果</h4>';
  if(result.steps) {
    if(result.steps.recon) html += '<div>🌐 侦察: 发现'+result.steps.recon.port_count+'个开放端口</div>';
    if(result.steps.vuln_scan) html += '<div>🔍 漏洞扫描: 发现'+result.steps.vuln_scan.vuln_count+'个漏洞</div>';
    if(result.steps.risk_score) html += '<div>⚠️ 风险评分: '+result.steps.risk_score.score+'/100 ('+result.steps.risk_score.level+')</div>';
    if(result.steps.kill_chain && result.steps.kill_chain.risk_assessment) html += '<div>🔗 攻击链: 最大风险='+result.steps.kill_chain.risk_assessment.max_severity+', 可达阶段='+result.steps.kill_chain.risk_assessment.stages_reachable.join(',')+'</div>';
    if(result.steps.auto_inventory) html += '<div>📦 自动入库: 漏洞'+result.steps.auto_inventory.vuln_created+'条, 资产'+(result.steps.auto_inventory.asset_created?'已创建':'已存在')+', 审计'+(result.steps.auto_inventory.audit_logged?'已记录':'未记录')+'</div>';
  }
  html += '</div>';
  div.innerHTML = html;
}
async function loadWorkflowTasks() {
  const r = await api('/api/v1/workflow/tasks?limit=10');
  let html = '';
  (r.data.tasks||[]).forEach(function(t){
    const statusColor = t.status==='completed'?'#10b981':t.status==='running'?'#38bdf8':t.status==='failed'?'#ef4444':'#94a3b8';
    html += '<div style="padding:8px 0;border-bottom:1px solid #334155"><span style="color:'+statusColor+'">['+t.status+']</span> <b>#'+t.id+'</b> '+t.target+' ('+t.workflow_type+') 进度:'+t.progress+'% '+t.current_step+'</div>';
  });
  document.getElementById('wf-tasks').innerHTML = html || '暂无任务';
}
async function loadOverview() {
  const r = await api('/api/v1/workflow/dashboard/overview');
  const d = r.data;
  const health = d.overall || {};
  document.getElementById('overview-health').innerHTML =
    '<div style="background:#1e293b;padding:15px;border-radius:8px"><div style="font-size:28px;color:'+(health.health_score>=80?'#10b981':health.health_score>=60?'#f59e0b':'#ef4444')+'">'+health.health_score+'</div><div style="font-size:12px;color:#94a3b8">健康评分</div></div>'+
    '<div style="background:#1e293b;padding:15px;border-radius:8px"><div style="font-size:28px;color:#38bdf8">'+health.modules_online+'</div><div style="font-size:12px;color:#94a3b8">模块在线</div></div>'+
    '<div style="background:#1e293b;padding:15px;border-radius:8px"><div style="font-size:28px;color:'+(health.status==='healthy'?'#10b981':'#f59e0b')+'">'+health.status+'</div><div style="font-size:12px;color:#94a3b8">系统状态</div></div>';
  let modHtml = '<h4 style="margin:15px 0 8px">模块详情</h4><div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px">';
  const modNames = {workflow:'统一工作流',vuln_management:'漏洞管理',assets:'资产管理',scan_history:'扫描历史',audit:'审计日志',monitor:'持续监控',approvals:'人工审批'};
  for(const mod in d.modules) {
    const m = d.modules[mod];
    const name = modNames[mod] || mod;
    if(m.error) {
      modHtml += '<div style="background:#1e293b;padding:10px;border-radius:8px;border-left:3px solid #ef4444"><b>'+name+'</b><div style="font-size:12px;color:#ef4444">不可用</div></div>';
    } else {
      let detail = '';
      for(const k in m) detail += k+':'+m[k]+' ';
      modHtml += '<div style="background:#1e293b;padding:10px;border-radius:8px;border-left:3px solid #10b981"><b>'+name+'</b><div style="font-size:12px;color:#94a3b8">'+detail+'</div></div>';
    }
  }
  modHtml += '</div>';
  document.getElementById('overview-modules').innerHTML = modHtml;
}
loadWorkflowTasks();
loadOverview();
</script>'''
c = c.replace(script_end, new_funcs)

with open('api_server/console.html', 'w', encoding='utf-8') as f:
    f.write(c)
print("控制台增强完成: %d bytes, 16个Tab" % len(c))
