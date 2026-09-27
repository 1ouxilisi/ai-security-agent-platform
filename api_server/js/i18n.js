/* =========================================================
 * i18n.js — Frontend internationalization framework
 * - Language packs: zh-CN / en-US (extensible)
 * - t(key) / t(key, params) with {var} interpolation
 * - Runtime language switch without page reload
 * - Persist choice to localStorage under key `ai_hacking_lang`
 * - Auto-detect navigator.language
 * - Auto-translate elements via data-i18n attribute
 * - Attribute translation: data-i18n-placeholder / -title / -aria-label
 * - Plural handling: key_one / key_other
 * - Async fetch: /static/locales/${lang}.json
 * - Exposes window.i18n = { t, setLanguage, getLanguage, getMissingKeys, render }
 * ========================================================= */
(function (global) {
  'use strict';

  var STORAGE_KEY = 'ai_hacking_lang';
  var SUPPORTED = ['zh-CN', 'en-US'];
  var DEFAULT_LANG = 'zh-CN';

  var catalogs = {};        // { 'zh-CN': {key:val}, ... }
  var currentLang = null;
  var loadingPromises = {};

  // ---------- Helpers ----------
  function detectLanguage() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved && SUPPORTED.indexOf(saved) !== -1) return saved;
    } catch (e) {}
    var nav = (global.navigator && global.navigator.language) || '';
    if (nav.indexOf('zh') === 0) return 'zh-CN';
    if (nav.indexOf('en') === 0) return 'en-US';
    return DEFAULT_LANG;
  }

  function fetchLang(lang) {
    if (catalogs[lang]) return Promise.resolve(catalogs[lang]);
    if (loadingPromises[lang]) return loadingPromises[lang];
    loadingPromises[lang] = fetch('/static/locales/' + lang + '.json', { cache: 'no-cache' })
      .then(function (r) {
        if (!r.ok) throw new Error('Failed to load ' + lang + ': ' + r.status);
        return r.json();
      })
      .then(function (data) {
        catalogs[lang] = data || {};
        delete loadingPromises[lang];
        return catalogs[lang];
      })
      .catch(function (err) {
        console.warn('[i18n] load failed for', lang, err);
        catalogs[lang] = catalogs[lang] || {};
        delete loadingPromises[lang];
        return catalogs[lang];
      });
    return loadingPromises[lang];
  }

  // ---------- Interpolation ----------
  function interpolate(str, params) {
    if (!params) return str;
    return String(str).replace(/\{(\w+)\}/g, function (m, k) {
      return Object.prototype.hasOwnProperty.call(params, k) ? params[k] : m;
    });
  }

  // ---------- Plural resolution ----------
  function pluralKey(key, count) {
    if (typeof count === 'number') {
      var suf = (count === 1) ? '_one' : '_other';
      if (catalogs[currentLang] && (catalogs[currentLang][key + suf] !== undefined)) {
        return key + suf;
      }
    }
    return key;
  }

  // ---------- Public: t ----------
  function t(key, params) {
    var lang = currentLang || DEFAULT_LANG;
    var dict = catalogs[lang] || {};
    var resolvedKey = key;

    if (params && typeof params.count === 'number') {
      resolvedKey = pluralKey(key, params.count);
    }
    var val = dict[resolvedKey];

    // Fallback to base key, then default language, then key itself
    if (val === undefined && resolvedKey !== key) val = dict[key];
    if (val === undefined && lang !== DEFAULT_LANG) {
      val = (catalogs[DEFAULT_LANG] || {})[resolvedKey];
      if (val === undefined) val = (catalogs[DEFAULT_LANG] || {})[key];
    }
    if (val === undefined) return key;
    return interpolate(val, params);
  }

  // ---------- DOM rendering ----------
  function render(root) {
    root = root || document;
    // Text content
    root.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      if (key) el.textContent = t(key);
    });
    // Placeholder
    root.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      var key = el.getAttribute('data-i18n-placeholder');
      if (key) el.setAttribute('placeholder', t(key));
    });
    // Title
    root.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      var key = el.getAttribute('data-i18n-title');
      if (key) el.setAttribute('title', t(key));
    });
    // aria-label
    root.querySelectorAll('[data-i18n-aria-label]').forEach(function (el) {
      var key = el.getAttribute('data-i18n-aria-label');
      if (key) el.setAttribute('aria-label', t(key));
    });
    // <html lang>
    if (document.documentElement) document.documentElement.setAttribute('lang', currentLang);
  }

  // ---------- Language switch ----------
  function setLanguage(lang) {
    if (SUPPORTED.indexOf(lang) === -1) {
      console.warn('[i18n] unsupported language:', lang);
      return Promise.resolve(false);
    }
    return fetchLang(lang).then(function () {
      currentLang = lang;
      try { localStorage.setItem(STORAGE_KEY, lang); } catch (e) {}
      render();
      // notify listeners
      var evt = new CustomEvent('i18n:change', { detail: { lang: lang } });
      window.dispatchEvent(evt);
      return true;
    });
  }

  function getLanguage() { return currentLang; }

  function getMissingKeys(compareLang) {
    compareLang = compareLang || DEFAULT_LANG;
    var base = catalogs[compareLang] || {};
    var cur = catalogs[currentLang] || {};
    var missing = [];
    Object.keys(base).forEach(function (k) {
      if (cur[k] === undefined) missing.push(k);
    });
    return missing;
  }

  function getSupportedLanguages() { return SUPPORTED.slice(); }

  // ---------- Boot ----------
  function boot() {
    currentLang = detectLanguage();
    // Load both catalogs in parallel so coverage check is possible
    return Promise.all(SUPPORTED.map(fetchLang)).then(function () {
      render();
    });
  }

  // Expose public API
  global.i18n = {
    t: t,
    setLanguage: setLanguage,
    getLanguage: getLanguage,
    getMissingKeys: getMissingKeys,
    getSupportedLanguages: getSupportedLanguages,
    render: render,
    boot: boot,
    catalogs: catalogs
  };

  // Auto-boot when DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(window);
