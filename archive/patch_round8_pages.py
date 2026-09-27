# -*- coding: utf-8 -*-
"""Patch 5 core HTML pages: add responsive.css, i18n.js, mobile-nav.js, lang switcher."""
import os, re

BASE = os.path.dirname(os.path.abspath(__file__))
SRV = os.path.join(BASE, "api_server")

FILES = [
    "workflow_console.html",
    "ai_assistant.html",
    "platform_console_v2.html",
    "unified_console.html",
    "defense_console.html",
]

CSS_LINK = '<link rel="stylesheet" href="/static/css/responsive.css">'
I18N_JS = '<script src="/static/js/i18n.js"></script>'
MOBILE_JS = '<script src="/static/js/mobile-nav.js"></script>'

# Injected block: language switcher + boot helpers. Goes before </body>.
BOOT_BLOCK = """
<!-- Round8: mobile + i18n boot -->
<div id="lang-switcher" style="position:fixed;top:10px;right:10px;z-index:1300;display:flex;gap:6px;">
  <button type="button" data-lang="zh-CN" class="lang-btn" style="min-height:44px;padding:8px 14px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;cursor:pointer;font-size:13px;">中文</button>
  <button type="button" data-lang="en-US" class="lang-btn" style="min-height:44px;padding:8px 14px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;cursor:pointer;font-size:13px;">EN</button>
</div>
<script>
(function(){
  function bindLangSwitch(){
    var btns = document.querySelectorAll('#lang-switcher .lang-btn');
    btns.forEach(function(b){
      b.addEventListener('click', function(){
        var lang = b.getAttribute('data-lang');
        if (window.i18n) window.i18n.setLanguage(lang);
      });
    });
    function highlight(){
      var cur = (window.i18n && window.i18n.getLanguage()) || 'zh-CN';
      btns.forEach(function(b){
        var active = b.getAttribute('data-lang') === cur;
        b.style.borderColor = active ? '#58a6ff' : '#30363d';
        b.style.color = active ? '#58a6ff' : '#c9d1d9';
      });
    }
    window.addEventListener('i18n:change', highlight);
    // initial highlight once i18n boots
    var tries = 0;
    var t = setInterval(function(){ if (window.i18n) { highlight(); clearInterval(t); } else if (++tries > 50) clearInterval(t); }, 100);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindLangSwitch);
  else bindLangSwitch();
})();
</script>
"""

def patch(path):
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    orig = html

    # 1) Ensure viewport meta
    if 'name="viewport"' not in html and "name='viewport'" not in html:
        html = html.replace("<head>", '<head>\n<meta name="viewport" content="width=device-width, initial-scale=1.0">', 1)

    # 2) Inject responsive.css before </head> if not already
    if "/static/css/responsive.css" not in html:
        html = html.replace("</head>", CSS_LINK + "\n</head>", 1)

    # 3) Inject i18n.js + mobile-nav.js before </body> if not already
    if "/static/js/i18n.js" not in html:
        inject = I18N_JS + "\n" + MOBILE_JS + "\n" + BOOT_BLOCK + "\n"
        html = html.replace("</body>", inject + "</body>", 1)

    # 4) Add class="main-content" to existing main wrapper if present and not already
    #    ai_assistant: <section id="main">
    #    platform_console_v2: <main ...> or .main
    #    others: no obvious wrapper; skip gracefully.
    if 'class="main-content"' not in html:
        html = re.sub(r'<section id="main">', '<section id="main" class="main-content">', html, count=1)
        # generic: add a wrapper class to <main ...> if exists
        html = re.sub(r'<main(?=[\s>])(?![^>]*class=)', '<main class="main-content"', html, count=1)

    if html != orig:
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return True, len(orig), len(html)
    return False, len(orig), len(html)

for name in FILES:
    p = os.path.join(SRV, name)
    changed, old, new = patch(p)
    print(f"{'PATCHED' if changed else 'SKIP   '} {name}: {old} -> {new} bytes")
