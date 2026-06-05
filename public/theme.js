(function () {
  var THEME_KEY = 'musikquiz-theme';

  function getSaved() {
    try { return localStorage.getItem(THEME_KEY) || 'dark'; } catch (e) { return 'dark'; }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme === 'dark' ? '' : theme);

    // Swap logo src on all logo images
    var logos = { ua: '/logo-ua.svg', tpb: '/logo-tpb.svg', ph: '/logo-ph.svg' };
    var logoSrc = logos[theme] || '/logo.svg';
    document.querySelectorAll('.logo-img').forEach(function (img) {
      img.src = logoSrc;
    });

    // Sync dropdown value
    var sel = document.getElementById('theme-select');
    if (sel) sel.value = theme;
  }

  // Apply theme before first paint to prevent flash
  var saved = getSaved();
  if (saved !== 'dark') {
    document.documentElement.setAttribute('data-theme', saved);
  }

  document.addEventListener('DOMContentLoaded', function () {
    applyTheme(saved);

    var sel = document.getElementById('theme-select');
    if (sel) {
      sel.addEventListener('change', function () {
        var next = sel.value;
        try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
        applyTheme(next);
      });
    }
  });
})();
