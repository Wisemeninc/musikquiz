(function () {
  var THEME_KEY = 'musikquiz-theme';

  function getSaved() {
    try { return localStorage.getItem(THEME_KEY) || 'dark'; } catch (e) { return 'dark'; }
  }

  function applyTheme(theme) {
    var isUA = theme === 'ua';
    document.documentElement.setAttribute('data-theme', isUA ? 'ua' : '');

    // Swap logo src on all logo images
    document.querySelectorAll('.logo-img').forEach(function (img) {
      img.src = isUA ? '/logo-ua.svg' : '/logo.svg';
    });

    // Sync dropdown value
    var sel = document.getElementById('theme-select');
    if (sel) sel.value = theme;
  }

  // Apply theme before first paint to prevent flash
  var saved = getSaved();
  if (saved === 'ua') {
    document.documentElement.setAttribute('data-theme', 'ua');
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
