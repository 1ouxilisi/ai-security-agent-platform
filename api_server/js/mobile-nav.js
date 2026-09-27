/* =========================================================
 * mobile-nav.js — Mobile navigation component
 * - Hamburger button (top-left, fixed)
 * - Sidebar slide-in/out via transform translateX
 * - Bottom nav bar (5 entries: Home / Scan / Workflow / Report / Settings)
 * - Touch gesture: swipe left to close sidebar
 * - Responsive breakpoint detection via window.resize
 * - Overlay click closes sidebar
 * ========================================================= */
(function (global) {
  'use strict';

  var BREAKPOINT = 768;
  var STORAGE_KEY = 'ai_hacking_mobile_state';

  var state = {
    isMobile: false,
    sidebar: null,
    hamburger: null,
    overlay: null,
    bottomNav: null,
    touchStartX: 0,
    touchStartY: 0
  };

  // ---- Locate sidebar by common selectors ----
  function findSidebar() {
    var sel = ['#sidebar', '#nav-sidebar', '.sidebar', 'aside#sidebar', 'nav.sidebar'];
    for (var i = 0; i < sel.length; i++) {
      var el = document.querySelector(sel[i]);
      if (el) return el;
    }
    return null;
  }

  // ---- Inject hamburger button ----
  function injectHamburger() {
    if (document.querySelector('.mn-hamburger')) return;
    var btn = document.createElement('button');
    btn.className = 'mn-hamburger';
    btn.setAttribute('aria-label', 'Toggle navigation');
    btn.setAttribute('data-i18n-aria-label', 'mobile.toggle_nav');
    btn.innerHTML = '&#9776;';
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      toggleSidebar();
    });
    document.body.appendChild(btn);
    state.hamburger = btn;
  }

  // ---- Inject overlay ----
  function injectOverlay() {
    if (document.querySelector('.mn-overlay')) return;
    var ov = document.createElement('div');
    ov.className = 'mn-overlay';
    ov.addEventListener('click', closeSidebar);
    document.body.appendChild(ov);
    state.overlay = ov;
  }

  // ---- Inject bottom nav ----
  function injectBottomNav() {
    if (document.querySelector('.mn-bottom-nav')) return;
    var nav = document.createElement('nav');
    nav.className = 'mn-bottom-nav';
    var items = [
      { href: '/', icon: '\u2302', label: 'nav.home', key: 'home' },
      { href: '/scan', icon: '\u{1F50D}', label: 'nav.scan', key: 'scan' },
      { href: '/workflow', icon: '\u2699', label: 'nav.workflow', key: 'workflow' },
      { href: '/report', icon: '\u{1F4CA}', label: 'nav.report', key: 'report' },
      { href: '/settings', icon: '\u2699', label: 'nav.settings', key: 'settings' }
    ];
    items.forEach(function (it) {
      var a = document.createElement('a');
      a.href = it.href;
      a.dataset.key = it.key;
      a.innerHTML = '<span class="icon">' + it.icon + '</span><span data-i18n="' + it.label + '"></span>';
      nav.appendChild(a);
    });
    document.body.appendChild(nav);
    state.bottomNav = nav;
  }

  // ---- Sidebar open/close ----
  function openSidebar() {
    if (!state.sidebar) return;
    state.sidebar.classList.add('mn-open');
    if (state.overlay) state.overlay.classList.add('visible');
    document.body.style.overflow = 'hidden';
    try { sessionStorage.setItem(STORAGE_KEY, 'open'); } catch (e) {}
  }

  function closeSidebar() {
    if (!state.sidebar) return;
    state.sidebar.classList.remove('mn-open');
    if (state.overlay) state.overlay.classList.remove('visible');
    document.body.style.overflow = '';
    try { sessionStorage.setItem(STORAGE_KEY, 'closed'); } catch (e) {}
  }

  function toggleSidebar() {
    if (!state.sidebar) return;
    if (state.sidebar.classList.contains('mn-open')) closeSidebar();
    else openSidebar();
  }

  // ---- Touch gestures: swipe left on sidebar closes it ----
  function bindGestures() {
    document.addEventListener('touchstart', function (e) {
      state.touchStartX = e.touches[0].clientX;
      state.touchStartY = e.touches[0].clientY;
    }, { passive: true });

    document.addEventListener('touchend', function (e) {
      var dx = e.changedTouches[0].clientX - state.touchStartX;
      var dy = e.changedTouches[0].clientY - state.touchStartY;
      // horizontal swipe dominant
      if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) {
        if (dx < 0) closeSidebar(); // swipe left closes
      }
    }, { passive: true });
  }

  // ---- Responsive detection ----
  function applyLayout() {
    var w = window.innerWidth;
    var mobile = w < BREAKPOINT;
    state.isMobile = mobile;

    if (mobile) {
      document.body.classList.add('mn-mobile');
      document.body.classList.add('has-bottom-nav');
      document.body.classList.add('force-fluid');
      // Auto-close on entering mobile
      closeSidebar();
    } else {
      document.body.classList.remove('mn-mobile');
      document.body.classList.remove('has-bottom-nav');
      document.body.classList.remove('force-fluid');
      if (state.sidebar) state.sidebar.classList.remove('mn-open');
      if (state.overlay) state.overlay.classList.remove('visible');
      document.body.style.overflow = '';
    }

    // Trigger i18n re-render if available
    if (global.i18n && typeof global.i18n.render === 'function') {
      try { global.i18n.render(); } catch (e) {}
    }
  }

  var resizeTimer = null;
  function onResize() {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(applyLayout, 150);
  }

  // ---- Init ----
  function init() {
    state.sidebar = findSidebar();
    injectHamburger();
    injectOverlay();
    injectBottomNav();
    bindGestures();
    applyLayout();
    window.addEventListener('resize', onResize);
    window.addEventListener('orientationchange', onResize);

    // Expose API
    global.MobileNav = {
      open: openSidebar,
      close: closeSidebar,
      toggle: toggleSidebar,
      isMobile: function () { return state.isMobile; },
      breakpoint: BREAKPOINT
    };
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})(window);
