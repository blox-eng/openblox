// Progressive enhancement, and nothing else. The page is complete without this
// file: both controls it wires up ship hidden and are revealed only once they
// have behaviour, so neither can present a dead affordance.
//
// In its own file rather than inline so the Content-Security-Policy in
// _headers can be `script-src 'self'` with no 'unsafe-inline' escape hatch.
(function () {
  'use strict';

  var root = document.documentElement;

  // Site data can be unavailable or throw outright — a private window, blocked
  // storage — and a remembered theme is not worth a broken page.
  function store(v) { try { localStorage.setItem('theme', v); } catch (e) { /* ignore */ } }
  function read() { try { return localStorage.getItem('theme'); } catch (e) { return null; } }

  var saved = read();
  if (saved === 'dark' || saved === 'light') root.dataset.theme = saved;

  var toggle = document.querySelector('.theme');
  if (toggle) {
    toggle.hidden = false;

    var sync = function () {
      var dark = root.dataset.theme
        ? root.dataset.theme === 'dark'
        : window.matchMedia('(prefers-color-scheme: dark)').matches;
      toggle.textContent = dark ? 'Light' : 'Dark';
      toggle.setAttribute('aria-pressed', String(dark));
      toggle.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    };

    sync();
    toggle.addEventListener('click', function () {
      var next = toggle.getAttribute('aria-pressed') === 'true' ? 'light' : 'dark';
      root.dataset.theme = next;
      store(next);
      sync();
    });
  }

  if (navigator.clipboard) {
    Array.prototype.forEach.call(document.querySelectorAll('.copy'), function (btn) {
      var code = btn.parentNode.querySelector('code');
      if (!code) return;
      btn.hidden = false;
      btn.addEventListener('click', function () {
        navigator.clipboard.writeText(code.innerText).then(function () {
          btn.textContent = 'Copied';
          window.setTimeout(function () { btn.textContent = 'Copy'; }, 1600);
        });
      });
    });
  }
})();
