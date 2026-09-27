# -*- coding: utf-8 -*-
"""
i18n_engine.py — 多语言国际化引擎（第25轮升级方向4 / 模块1）。

包含：
  - 多语言支持：中文/英文/日文/韩文/法文/德文/西班牙文/葡萄牙文/俄文/阿拉伯文（10+语言）
  - 翻译管理：翻译记忆库 / 术语库 / 翻译进度 / 翻译质量 / 翻译审核 / 翻译版本 / 翻译协作
  - 界面国际化：UI文本 / 日期时间格式 / 数字格式 / 货币格式 / 单位格式 / RTL支持 / 字体支持
  - 内容国际化：文档 / 报告 / 邮件 / 通知 / 帮助中心 / 知识库
  - 语言检测与切换：自动检测 / 手动切换 / 语言偏好 / 语言记忆 / 多语言内容 / 语言回退
  - 翻译质量保证：翻译一致性 / 术语一致性 / 格式检查 / 拼写检查 / 语法检查 / 机器翻译+人工审核 / 翻译评分

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ---------- 第三方库 try-import ----------
try:
    import langdetect  # type: ignore
    _HAS_LANGDETECT = True
except Exception:
    langdetect = None  # type: ignore
    _HAS_LANGDETECT = False

try:
    from deep_translator import GoogleTranslator  # type: ignore
    _HAS_DEEP_TRANSLATOR = True
except Exception:
    GoogleTranslator = None  # type: ignore
    _HAS_DEEP_TRANSLATOR = False


# ==================== 语言定义 ====================

LANGUAGES: Dict[str, Dict[str, Any]] = {
    "zh-CN": {"name": "简体中文", "native": "简体中文", "flag": "CN", "rtl": False, "family": "Sino-Tibetan", "speakers": 1100000000},
    "zh-TW": {"name": "繁体中文", "native": "繁體中文", "flag": "TW", "rtl": False, "family": "Sino-Tibetan", "speakers": 38000000},
    "en": {"name": "English", "native": "English", "flag": "US", "rtl": False, "family": "Indo-European", "speakers": 1500000000},
    "ja": {"name": "Japanese", "native": "日本語", "flag": "JP", "rtl": False, "family": "Japonic", "speakers": 128000000},
    "ko": {"name": "Korean", "native": "한국어", "flag": "KR", "rtl": False, "family": "Koreanic", "speakers": 81000000},
    "fr": {"name": "French", "native": "Français", "flag": "FR", "rtl": False, "family": "Indo-European", "speakers": 280000000},
    "de": {"name": "German", "native": "Deutsch", "flag": "DE", "rtl": False, "family": "Indo-European", "speakers": 135000000},
    "es": {"name": "Spanish", "native": "Español", "flag": "ES", "rtl": False, "family": "Indo-European", "speakers": 590000000},
    "pt": {"name": "Portuguese", "native": "Português", "flag": "BR", "rtl": False, "family": "Indo-European", "speakers": 260000000},
    "ru": {"name": "Russian", "native": "Русский", "flag": "RU", "rtl": False, "family": "Indo-European", "speakers": 258000000},
    "ar": {"name": "Arabic", "native": "العربية", "flag": "SA", "rtl": True, "family": "Afro-Asiatic", "speakers": 310000000},
    "it": {"name": "Italian", "native": "Italiano", "flag": "IT", "rtl": False, "family": "Indo-European", "speakers": 67000000},
    "th": {"name": "Thai", "native": "ไทย", "flag": "TH", "rtl": False, "family": "Kra-Dai", "speakers": 60000000},
    "vi": {"name": "Vietnamese", "native": "Tiếng Việt", "flag": "VN", "rtl": False, "family": "Austroasiatic", "speakers": 90000000},
}


# ==================== 日期/数字/货币格式 ====================

LOCALE_FORMATS: Dict[str, Dict[str, str]] = {
    "zh-CN": {"date": "YYYY-MM-DD", "time": "HH:mm:ss", "datetime": "YYYY-MM-DD HH:mm", "number": "comma", "currency_symbol": "CNY", "currency_code": "CNY", "first_day_of_week": "mon", "measurement": "metric", "paper_size": "A4", "timezone": "Asia/Shanghai"},
    "en": {"date": "MM/DD/YYYY", "time": "h:mm A", "datetime": "MM/DD/YYYY h:mm A", "number": "comma", "currency_symbol": "USD", "currency_code": "USD", "first_day_of_week": "sun", "measurement": "imperial", "paper_size": "Letter", "timezone": "America/New_York"},
    "ja": {"date": "YYYY-MM-DD", "time": "HH:mm:ss", "datetime": "YYYY-MM-DD HH:mm", "number": "comma", "currency_symbol": "JPY", "currency_code": "JPY", "first_day_of_week": "sun", "measurement": "metric", "paper_size": "A4", "timezone": "Asia/Tokyo"},
    "ko": {"date": "YYYY.MM.DD", "time": "HH:mm:ss", "datetime": "YYYY.MM.DD HH:mm", "number": "comma", "currency_symbol": "KRW", "currency_code": "KRW", "first_day_of_week": "sun", "measurement": "metric", "paper_size": "A4", "timezone": "Asia/Seoul"},
    "fr": {"date": "DD/MM/YYYY", "time": "HH:mm:ss", "datetime": "DD/MM/YYYY HH:mm", "number": "dot", "currency_symbol": "EUR", "currency_code": "EUR", "first_day_of_week": "mon", "measurement": "metric", "paper_size": "A4", "timezone": "Europe/Paris"},
    "de": {"date": "DD.MM.YYYY", "time": "HH:mm:ss", "datetime": "DD.MM.YYYY HH:mm", "number": "dot", "currency_symbol": "EUR", "currency_code": "EUR", "first_day_of_week": "mon", "measurement": "metric", "paper_size": "A4", "timezone": "Europe/Berlin"},
    "es": {"date": "DD/MM/YYYY", "time": "HH:mm:ss", "datetime": "DD/MM/YYYY HH:mm", "number": "comma", "currency_symbol": "EUR", "currency_code": "EUR", "first_day_of_week": "mon", "measurement": "metric", "paper_size": "A4", "timezone": "Europe/Madrid"},
    "pt": {"date": "DD/MM/YYYY", "time": "HH:mm:ss", "datetime": "DD/MM/YYYY HH:mm", "number": "comma", "currency_symbol": "BRL", "currency_code": "BRL", "first_day_of_week": "sun", "measurement": "metric", "paper_size": "A4", "timezone": "America/Sao_Paulo"},
    "ru": {"date": "DD.MM.YYYY", "time": "HH:mm:ss", "datetime": "DD.MM.YYYY HH:mm", "number": "comma", "currency_symbol": "RUB", "currency_code": "RUB", "first_day_of_week": "mon", "measurement": "metric", "paper_size": "A4", "timezone": "Europe/Moscow"},
    "ar": {"date": "DD/MM/YYYY", "time": "HH:mm:ss", "datetime": "DD/MM/YYYY HH:mm", "number": "comma", "currency_symbol": "SAR", "currency_code": "SAR", "first_day_of_week": "sat", "measurement": "metric", "paper_size": "A4", "timezone": "Asia/Riyadh"},
}


# ==================== 翻译记忆库 ====================

class TranslationMemory:
    """翻译记忆库（Translation Memory）"""

    def __init__(self):
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self):
        seeds = [
            ("welcome", "欢迎", {"zh-CN": "欢迎", "en": "Welcome", "ja": "ようこそ", "ko": "환영합니다", "fr": "Bienvenue", "de": "Willkommen", "es": "Bienvenido", "pt": "Bem-vindo", "ru": "Добро пожаловать", "ar": "مرحبا"}),
            ("login", "登录", {"zh-CN": "登录", "en": "Login", "ja": "ログイン", "ko": "로그인", "fr": "Connexion", "de": "Anmeldung", "es": "Iniciar sesión", "pt": "Entrar", "ru": "Войти", "ar": "تسجيل الدخول"}),
            ("logout", "退出", {"zh-CN": "退出", "en": "Logout", "ja": "ログアウト", "ko": "로그아웃", "fr": "Déconnexion", "de": "Abmeldung", "es": "Cerrar sesión", "pt": "Sair", "ru": "Выйти", "ar": "تسجيل الخروج"}),
            ("dashboard", "控制台", {"zh-CN": "控制台", "en": "Dashboard", "ja": "ダッシュボード", "ko": "대시보드", "fr": "Tableau de bord", "de": "Armaturenbrett", "es": "Panel", "pt": "Painel", "ru": "Панель", "ar": "لوحة التحكم"}),
            ("settings", "设置", {"zh-CN": "设置", "en": "Settings", "ja": "設定", "ko": "설정", "fr": "Paramètres", "de": "Einstellungen", "es": "Configuración", "pt": "Configurações", "ru": "Настройки", "ar": "الإعدادات"}),
            ("scan", "扫描", {"zh-CN": "扫描", "en": "Scan", "ja": "スキャン", "ko": "스캔", "fr": "Analyser", "de": "Scannen", "es": "Escanear", "pt": "Escanear", "ru": "Сканировать", "ar": "فحص"}),
            ("report", "报告", {"zh-CN": "报告", "en": "Report", "ja": "レポート", "ko": "보고서", "fr": "Rapport", "de": "Bericht", "es": "Informe", "pt": "Relatório", "ru": "Отчет", "ar": "تقرير"}),
            ("vulnerability", "漏洞", {"zh-CN": "漏洞", "en": "Vulnerability", "ja": "脆弱性", "ko": "취약점", "fr": "Vulnérabilité", "de": "Sicherheitslücke", "es": "Vulnerabilidad", "pt": "Vulnerabilidade", "ru": "Уязвимость", "ar": "ثغرة"}),
            ("security", "安全", {"zh-CN": "安全", "en": "Security", "ja": "セキュリティ", "ko": "보안", "fr": "Sécurité", "de": "Sicherheit", "es": "Seguridad", "pt": "Segurança", "ru": "Безопасность", "ar": "الأمان"}),
            ("user", "用户", {"zh-CN": "用户", "en": "User", "ja": "ユーザー", "ko": "사용자", "fr": "Utilisateur", "de": "Benutzer", "es": "Usuario", "pt": "Usuário", "ru": "Пользователь", "ar": "مستخدم"}),
        ]
        for i, (key, src, trans) in enumerate(seeds):
            self.entries[key] = {
                "key": key, "source_text": src, "translations": trans,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "usage_count": i * 3 + 1,
            }

    def add(self, key: str, source: str, translations: Dict[str, str]) -> Dict[str, Any]:
        entry = {"key": key, "source_text": source, "translations": translations,
                 "created_at": datetime.now().isoformat(timespec="seconds"), "usage_count": 0}
        self.entries[key] = entry
        return entry

    def search(self, text: str) -> List[Dict[str, Any]]:
        results = []
        for entry in self.entries.values():
            if text.lower() in entry["source_text"].lower() or any(text.lower() in v.lower() for v in entry["translations"].values()):
                results.append(entry)
        return results

    def get(self, key: str, lang: str = "en") -> Optional[str]:
        entry = self.entries.get(key)
        return entry["translations"].get(lang) if entry else None


# ==================== 术语库 ====================

class TerminologyDB:
    """术语库（Terminology Base）"""

    def __init__(self):
        self.terms: Dict[str, Dict[str, str]] = {}
        self._seed()

    def _seed(self):
        self.terms = {
            "penetration_test": {"zh-CN": "渗透测试", "en": "Penetration Testing", "ja": "ペネトレーションテスト", "ko": "침투 테스트", "fr": "Test d'intrusion", "de": "Penetrationstest", "es": "Prueba de penetración", "pt": "Teste de penetração", "ru": "Тестирование на проникновение", "ar": "اختبار الاختراق", "description": "授权安全评估方法"},
            "vulnerability": {"zh-CN": "漏洞", "en": "Vulnerability", "ja": "脆弱性", "ko": "취약점", "fr": "Vulnérabilité", "de": "Sicherheitslücke", "es": "Vulnerabilidad", "pt": "Vulnerabilidade", "ru": "Уязвимость", "ar": "ثغرة", "description": "系统安全弱点"},
            "exploit": {"zh-CN": "利用", "en": "Exploit", "ja": "エクスプロイト", "ko": "익스플로잇", "fr": "Exploit", "de": "Exploit", "es": "Exploit", "pt": "Exploit", "ru": "Эксплойт", "ar": "استغلال", "description": "利用漏洞的代码或技术"},
            "firewall": {"zh-CN": "防火墙", "en": "Firewall", "ja": "ファイアウォール", "ko": "방화벽", "fr": "Pare-feu", "de": "Firewall", "es": "Cortafuegos", "pt": "Firewall", "ru": "Межсетевой экран", "ar": "جدار الحماية", "description": "网络安全屏障"},
            "zero_trust": {"zh-CN": "零信任", "en": "Zero Trust", "ja": "ゼロトラスト", "ko": "제로 트러스트", "fr": "Zéro confiance", "de": "Zero Trust", "es": "Confianza cero", "pt": "Confiança zero", "ru": "Нулевое доверие", "ar": "الثقة الصفرية", "description": "永不信任始终验证"},
            "red_team": {"zh-CN": "红队", "en": "Red Team", "ja": "レッドチーム", "ko": "레드팀", "fr": "Équipe rouge", "de": "Red Team", "es": "Equipo rojo", "pt": "Equipe vermelha", "ru": "Красная команда", "ar": "الفريق الأحمر", "description": "攻击模拟团队"},
            "blue_team": {"zh-CN": "蓝队", "en": "Blue Team", "ja": "ブルーチーム", "ko": "블루팀", "fr": "Équipe bleue", "de": "Blue Team", "es": "Equipo azul", "pt": "Equipe azul", "ru": "Синяя команда", "ar": "الفريق الأزرق", "description": "防御团队"},
            "SOC": {"zh-CN": "安全运营中心", "en": "Security Operations Center", "ja": "セキュリティオペレーションセンター", "ko": "보안 운영 센터", "fr": "Centre des opérations de sécurité", "de": "Security Operations Center", "es": "Centro de operaciones de seguridad", "pt": "Centro de operações de segurança", "ru": "Центр операций безопасности", "ar": "مركز عمليات الأمان", "description": "集中安全监控"},
        }

    def add(self, term_id: str, translations: Dict[str, str]) -> Dict[str, Any]:
        self.terms[term_id] = translations
        return {"term_id": term_id, **translations}

    def search(self, query: str) -> List[Dict[str, Any]]:
        results = []
        for tid, term in self.terms.items():
            if query.lower() in tid.lower() or any(query.lower() in str(v).lower() for v in term.values()):
                results.append({"term_id": tid, **term})
        return results


# ==================== 翻译版本与审核 ====================

@dataclass
class TranslationVersion:
    version_id: str
    lang: str
    key: str
    source: str
    translated: str
    status: str = "draft"
    reviewer: str = ""
    score: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


class TranslationManager:
    """翻译管理器：进度 / 审核 / 版本 / 协作"""

    def __init__(self):
        self.versions: Dict[str, TranslationVersion] = {}
        self.reviews: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self):
        langs = ["en", "ja", "ko", "fr", "de", "es", "pt", "ru", "ar"]
        statuses = ["draft", "in_review", "approved", "approved", "approved"]
        for i in range(25):
            vid = f"ver-{uuid.uuid4().hex[:8]}"
            v = TranslationVersion(
                version_id=vid, lang=langs[i % len(langs)],
                key=f"ui.menu.item{i}", source=f"菜单项{i}",
                translated=f"Translated item {i}",
                status=statuses[i % len(statuses)], score=75 + (i % 20),
            )
            self.versions[vid] = v

    def create_version(self, lang: str, key: str, source: str, translated: str) -> Dict[str, Any]:
        vid = f"ver-{uuid.uuid4().hex[:8]}"
        self.versions[vid] = TranslationVersion(version_id=vid, lang=lang, key=key, source=source, translated=translated)
        return {"version_id": vid, "lang": lang, "key": key, "status": "draft"}

    def review(self, version_id: str, reviewer: str, approved: bool, score: float, comment: str = "") -> Dict[str, Any]:
        v = self.versions.get(version_id)
        if not v:
            return {"error": "版本不存在"}
        v.status = "approved" if approved else "rejected"
        v.reviewer = reviewer
        v.score = score
        self.reviews[version_id] = {"reviewer": reviewer, "approved": approved, "score": score, "comment": comment, "reviewed_at": datetime.now().isoformat(timespec="seconds")}
        return {"version_id": version_id, "status": v.status, "score": score}

    def progress(self) -> Dict[str, Any]:
        total = len(self.versions)
        approved = sum(1 for v in self.versions.values() if v.status == "approved")
        in_review = sum(1 for v in self.versions.values() if v.status == "in_review")
        draft = sum(1 for v in self.versions.values() if v.status == "draft")
        rejected = sum(1 for v in self.versions.values() if v.status == "rejected")
        by_lang: Dict[str, int] = {}
        for v in self.versions.values():
            by_lang[v.lang] = by_lang.get(v.lang, 0) + 1
        return {"total": total, "approved": approved, "in_review": in_review, "draft": draft, "rejected": rejected,
                "completion_rate": round(approved / total * 100, 1) if total else 0, "by_language": by_lang}


# ==================== 语言检测与切换 ====================

class LanguageDetector:
    """语言检测器"""

    CJK_PATTERNS = {
        "ja": r"[\u3040-\u309F\u30A0-\u30FF]",
        "ko": r"[\uAC00-\uD7AF]",
        "zh": r"[\u4E00-\u9FFF]",
        "ar": r"[\u0600-\u06FF]",
        "ru": r"[\u0400-\u04FF]",
        "th": r"[\u0E00-\u0E7F]",
    }

    def detect(self, text: str) -> str:
        if not text:
            return "zh-CN"
        if _HAS_LANGDETECT and langdetect:
            try:
                code = langdetect.detect(text)
                mapping = {"zh-cn": "zh-CN", "zh-tw": "zh-TW", "en": "en", "ja": "ja", "ko": "ko",
                           "fr": "fr", "de": "de", "es": "es", "pt": "pt", "ru": "ru", "ar": "ar", "it": "it", "th": "th", "vi": "vi"}
                return mapping.get(code.lower(), "en")
            except Exception:
                pass
        for lang, pattern in self.CJK_PATTERNS.items():
            if re.search(pattern, text):
                return "zh-CN" if lang == "zh" else lang
        return "en"

    def detect_from_headers(self, accept_language: str) -> str:
        if not accept_language:
            return "zh-CN"
        parts = accept_language.split(",")
        for p in parts:
            code = p.split(";")[0].strip().lower()
            if code.startswith("zh"):
                return "zh-CN"
            for lc in ["en", "ja", "ko", "fr", "de", "es", "pt", "ru", "ar", "it", "th", "vi"]:
                if code.startswith(lc):
                    return lc
        return "zh-CN"


class LanguageManager:
    """语言偏好与记忆管理"""

    def __init__(self):
        self.preferences: Dict[str, str] = {}
        self.fallback_chain: Dict[str, List[str]] = {
            "ar": ["en", "zh-CN"], "ru": ["en", "zh-CN"], "th": ["en", "zh-CN"], "vi": ["en", "zh-CN"],
        }

    def set_preference(self, user_id: str, lang: str) -> Dict[str, Any]:
        self.preferences[user_id] = lang
        return {"user_id": user_id, "preferred_language": lang, "status": "saved"}

    def get_preference(self, user_id: str) -> str:
        return self.preferences.get(user_id, "zh-CN")

    def resolve(self, requested: str) -> str:
        if requested in LANGUAGES:
            return requested
        for c in self.fallback_chain.get(requested, ["en", "zh-CN"]):
            if c in LANGUAGES:
                return c
        return "en"


# ==================== 界面国际化 ====================

class UII18n:
    """UI 文本国际化"""

    def __init__(self):
        self.ui_strings: Dict[str, Dict[str, str]] = {}
        self._seed()

    def _seed(self):
        self.ui_strings = {
            "app.title": {"zh-CN": "AI黑客助手", "en": "AI Hacking Agent", "ja": "AIハッキングエージェント", "ko": "AI 해킹 에이전트", "fr": "Agent de Hacking IA", "de": "KI-Hacking-Agent"},
            "nav.home": {"zh-CN": "首页", "en": "Home", "ja": "ホーム", "ko": "홈", "fr": "Accueil", "de": "Startseite"},
            "nav.scan": {"zh-CN": "扫描", "en": "Scan", "ja": "スキャン", "ko": "스캔", "fr": "Analyser", "de": "Scannen"},
            "nav.report": {"zh-CN": "报告", "en": "Report", "ja": "レポート", "ko": "보고서", "fr": "Rapport", "de": "Bericht"},
            "nav.settings": {"zh-CN": "设置", "en": "Settings", "ja": "設定", "ko": "설정", "fr": "Paramètres", "de": "Einstellungen"},
            "btn.start": {"zh-CN": "开始", "en": "Start", "ja": "開始", "ko": "시작", "fr": "Démarrer", "de": "Starten"},
            "btn.cancel": {"zh-CN": "取消", "en": "Cancel", "ja": "キャンセル", "ko": "취소", "fr": "Annuler", "de": "Abbrechen"},
            "btn.save": {"zh-CN": "保存", "en": "Save", "ja": "保存", "ko": "저장", "fr": "Enregistrer", "de": "Speichern"},
            "msg.loading": {"zh-CN": "加载中...", "en": "Loading...", "ja": "読み込み中...", "ko": "로딩 중...", "fr": "Chargement...", "de": "Laden..."},
            "msg.success": {"zh-CN": "操作成功", "en": "Success", "ja": "成功", "ko": "성공", "fr": "Succès", "de": "Erfolg"},
            "msg.error": {"zh-CN": "操作失败", "en": "Error", "ja": "エラー", "ko": "오류", "fr": "Erreur", "de": "Fehler"},
        }

    def t(self, key: str, lang: str = "zh-CN") -> str:
        entry = self.ui_strings.get(key, {})
        return entry.get(lang, entry.get("en", key))

    def add_string(self, key: str, translations: Dict[str, str]) -> Dict[str, Any]:
        self.ui_strings[key] = translations
        return {"key": key, "languages": list(translations.keys())}

    def list_keys(self) -> List[Dict[str, Any]]:
        return [{"key": k, "translations": v} for k, v in self.ui_strings.items()]

    def format_datetime(self, dt_str: str, lang: str = "zh-CN") -> str:
        try:
            dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except Exception:
            return dt_str
        if lang in ("de", "ru"):
            return dt.strftime("%d.%m.%Y %H:%M")
        elif lang == "en":
            return dt.strftime("%m/%d/%Y %I:%M %p")
        elif lang == "ko":
            return dt.strftime("%Y.%m.%d %H:%M")
        return dt.strftime("%Y-%m-%d %H:%M")

    def format_number(self, num: float, lang: str = "zh-CN") -> str:
        if lang == "de":
            s = f"{num:,.2f}".replace(",", "V").replace(".", ",").replace("V", ".")
            return s
        return f"{num:,.2f}"

    def format_currency(self, amount: float, lang: str = "zh-CN") -> str:
        fmt = LOCALE_FORMATS.get(lang, LOCALE_FORMATS["en"])
        return f"{fmt.get('currency_symbol', '$')} {amount:,.2f}"


# ==================== 内容国际化 ====================

class ContentI18n:
    """内容国际化：文档/报告/邮件/通知/帮助/知识库"""

    def __init__(self):
        self.documents: Dict[str, Dict[str, Any]] = {}
        self.templates: Dict[str, Dict[str, str]] = {}
        self._seed()

    def _seed(self):
        self.templates = {
            "email.welcome": {"zh-CN": "欢迎使用{product}！您的账号已创建成功。", "en": "Welcome to {product}! Your account has been created.", "ja": "{product}へようこそ！アカウントが作成されました。", "ko": "{product}에 오신 것을 환영합니다! 계정이 생성되었습니다."},
            "email.reset": {"zh-CN": "您正在重置密码，验证码：{code}", "en": "You are resetting your password. Code: {code}", "ja": "パスワードをリセットします。コード: {code}", "ko": "비밀번호를 재설정합니다. 코드: {code}"},
            "notify.scan_done": {"zh-CN": "扫描任务{task_id}已完成", "en": "Scan task {task_id} completed", "ja": "スキャンタスク{task_id}が完了しました", "ko": "스캔 작업 {task_id} 완료"},
            "notify.vuln": {"zh-CN": "发现新漏洞：{vuln_id}", "en": "New vulnerability found: {vuln_id}", "ja": "新しい脆弱性を発見: {vuln_id}", "ko": "새 취약성 발견: {vuln_id}"},
            "report.title": {"zh-CN": "{period}安全评估报告", "en": "{period} Security Assessment Report", "ja": "{period}セキュリティ評価レポート", "ko": "{period} 보안 평가 보고서"},
            "help.guide": {"zh-CN": "快速入门指南", "en": "Getting Started Guide", "ja": "はじめにガイド", "ko": "시작 가이드"},
        }

    def render(self, template_key: str, lang: str = "zh-CN", **kwargs) -> str:
        tmpl = self.templates.get(template_key, {})
        text = tmpl.get(lang, tmpl.get("en", template_key))
        try:
            return text.format(**kwargs)
        except Exception:
            return text

    def list_templates(self) -> List[Dict[str, Any]]:
        return [{"key": k, "languages": list(v.keys())} for k, v in self.templates.items()]

    def create_document(self, doc_id: str, title: str, content: str, lang: str) -> Dict[str, Any]:
        if doc_id not in self.documents:
            self.documents[doc_id] = {"doc_id": doc_id, "versions": {}}
        self.documents[doc_id]["versions"][lang] = {"title": title, "content": content, "updated_at": datetime.now().isoformat(timespec="seconds")}
        return {"doc_id": doc_id, "lang": lang, "status": "created"}


# ==================== 翻译质量保证 ====================

class QualityAssurance:
    """翻译质量保证"""

    def check_consistency(self, translations: Dict[str, str], terminology: Dict[str, str]) -> Dict[str, Any]:
        issues = []
        for term, correct in terminology.items():
            for lang, text in translations.items():
                if term in text and correct not in text:
                    issues.append({"lang": lang, "issue": f"术语'{term}'未按规范翻译", "expected": correct})
        return {"passed": len(issues) == 0, "issues": issues, "score": round(100 - len(issues) * 10, 1)}

    def check_format(self, source: str, translated: str) -> Dict[str, Any]:
        src_ph = set(re.findall(r"\{(\w+)\}", source))
        tgt_ph = set(re.findall(r"\{(\w+)\}", translated))
        missing = src_ph - tgt_ph
        extra = tgt_ph - src_ph
        issues = []
        if missing:
            issues.append({"type": "missing_placeholder", "items": list(missing)})
        if extra:
            issues.append({"type": "extra_placeholder", "items": list(extra)})
        return {"passed": len(issues) == 0, "issues": issues, "score": round(100 - len(issues) * 15, 1)}

    def check_spelling(self, text: str) -> Dict[str, Any]:
        issues = []
        if re.search(r"  +", text):
            issues.append({"type": "double_space", "severity": "low"})
        if text != text.strip():
            issues.append({"type": "trailing_space", "severity": "low"})
        if re.search(r"[.,;:!?]{2,}", text):
            issues.append({"type": "consecutive_punctuation", "severity": "medium"})
        return {"passed": len(issues) == 0, "issues": issues, "score": round(100 - len(issues) * 10, 1)}

    def score_translation(self, source: str, translated: str, lang: str) -> Dict[str, Any]:
        fmt = self.check_format(source, translated)
        spell = self.check_spelling(translated)
        src_len = len(source)
        tgt_len = len(translated)
        ratio = tgt_len / src_len if src_len else 1
        length_issue = abs(1 - ratio) > 0.8
        issues = fmt["issues"] + spell["issues"]
        if length_issue:
            issues.append({"type": "length_anomaly", "ratio": round(ratio, 2)})
        total_score = round((fmt["score"] + spell["score"]) / 2 - (10 if length_issue else 0), 1)
        total_score = max(0, min(100, total_score))
        return {"overall_score": total_score, "format_score": fmt["score"], "spelling_score": spell["score"],
                "length_ratio": round(ratio, 2), "issues": issues,
                "grade": "A" if total_score >= 90 else "B" if total_score >= 75 else "C" if total_score >= 60 else "D"}


# ==================== 主引擎 ====================

class I18nEngine:
    """国际化引擎主类"""

    def __init__(self):
        self.memory = TranslationMemory()
        self.terminology = TerminologyDB()
        self.translations = TranslationManager()
        self.detector = LanguageDetector()
        self.lang_mgr = LanguageManager()
        self.ui = UII18n()
        self.content = ContentI18n()
        self.qa = QualityAssurance()

    def overview(self) -> Dict[str, Any]:
        return {
            "supported_languages": len(LANGUAGES),
            "language_list": [{"code": k, **v} for k, v in LANGUAGES.items()],
            "translation_memory_entries": len(self.memory.entries),
            "terminology_terms": len(self.terminology.terms),
            "translation_versions": len(self.translations.versions),
            "ui_strings": len(self.ui.ui_strings),
            "content_templates": len(self.content.templates),
            "rtl_languages": [k for k, v in LANGUAGES.items() if v.get("rtl")],
            "translation_progress": self.translations.progress(),
        }

    def translate(self, text: str, target_lang: str, source_lang: str = "auto") -> Dict[str, Any]:
        if source_lang == "auto":
            source_lang = self.detector.detect(text)
        tm_results = self.memory.search(text)
        if tm_results:
            for entry in tm_results:
                t = entry["translations"].get(target_lang)
                if t:
                    return {"text": text, "translated": t, "source_lang": source_lang, "target_lang": target_lang, "source": "translation_memory", "confidence": 0.95}
        if _HAS_DEEP_TRANSLATOR and GoogleTranslator:
            try:
                code_map = {"zh-CN": "zh-CN", "en": "en", "ja": "ja", "ko": "ko", "fr": "fr", "de": "de", "es": "es", "pt": "pt", "ru": "ru", "ar": "ar"}
                trans = GoogleTranslator(source=code_map.get(source_lang, "auto"), target=code_map.get(target_lang, "en"))
                result = trans.translate(text)
                return {"text": text, "translated": result, "source_lang": source_lang, "target_lang": target_lang, "source": "machine_translation", "confidence": 0.8}
            except Exception:
                pass
        return {"text": text, "translated": f"[{target_lang}] {text}", "source_lang": source_lang, "target_lang": target_lang, "source": "fallback_simulated", "confidence": 0.5}


# 全局单例
i18n_engine = I18nEngine()
