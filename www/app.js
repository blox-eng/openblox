(function () {
  'use strict';

  var root = document.documentElement;

  /* ---- install tabs -------------------------------------------------- */

  /* The runtime named in the subhead is a control: clicking it walks the
     approved runtimes, and the line under the install command follows.

     Both are attributed, because both are someone else's work. They are not
     presented as interchangeable: gVisor is the default and the only runtime
     CI gates on; Kata is measured on amd64 by a workflow that gates nothing,
     with one layer lost (SECURITY.md) — so the stronger option says as much
     rather than implying parity. runc is deliberately not in this list; it is
     not an option, it is the absence of one. */
  var RUNTIMES = [
    {
      name: 'gVisor',
      href: 'https://gvisor.dev',
      tail: '',
      hint: 'The default, and the runtime CI gates on.'
    },
    {
      name: 'Kata',
      href: 'https://katacontainers.io',
      tail: ' — a separate kernel per sandbox, stronger than the default; measured on amd64, not gated',
      hint: 'A separate kernel per sandbox, stronger than the default. Measured on amd64; CI gates on gVisor.'
    }
  ];
  var runtime = 0;

  var COMMANDS = {
    't-daemon': {
      cmd: 'curl -fsSL https://openblox.sh/install.sh | sh',
      note: 'Linux · amd64 or arm64 · needs Docker with ',
      runtime: true,
      read: true
    },
    't-source': {
      cmd: 'go install github.com/blox-eng/openblox/cmd/openbloxd@latest',
      note: 'The same daemon, built by your own toolchain. Go 1.25+',
      read: false
    },
    't-lib': {
      cmd: 'go get github.com/blox-eng/openblox',
      note: 'Your process holds the Docker socket. Fine to start; run the daemon in production.',
      read: false
    }
  };

  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]'));
  var cmdtext = document.getElementById('cmdtext');
  var panel = document.getElementById('cmdline');
  var platform = document.getElementById('platform');
  var readit = document.getElementById('readit');

  var current = 't-daemon';
  var runtimeBtn = document.getElementById('runtime');

  /* Built from nodes rather than innerHTML: the note carries a link, and a
     string assembled with markup is a habit that outlives the one safe case. */
  function renderNote(c) {
    platform.textContent = c.note;
    if (!c.runtime) return;
    var r = RUNTIMES[runtime];
    var a = document.createElement('a');
    a.href = r.href;
    a.rel = 'noopener';
    a.textContent = r.name;
    platform.appendChild(a);
    if (r.tail) platform.appendChild(document.createTextNode(r.tail));
  }

  function select(id) {
    current = id;
    tabs.forEach(function (t) { t.setAttribute('aria-selected', String(t.id === id)); });
    var c = COMMANDS[id];
    cmdtext.textContent = c.cmd;
    renderNote(c);
    readit.hidden = !c.read;
    panel.setAttribute('aria-labelledby', id);
  }

  /* The caveat travels with the control, not only with the install note: the
     note renders on the Daemon tab alone, but the subhead names the runtime on
     every tab, and a claim the page cannot qualify is one it should not make.
     The note is left alone where it would not have changed, so the live region
     announces the runtime and nothing else. */
  function renderRuntime() {
    var r = RUNTIMES[runtime];
    runtimeBtn.textContent = r.name;
    runtimeBtn.title = r.hint;
  }

  runtimeBtn.addEventListener('click', function () {
    runtime = (runtime + 1) % RUNTIMES.length;
    renderRuntime();
    if (COMMANDS[current].runtime) renderNote(COMMANDS[current]);
  });
  tabs.forEach(function (t) {
    t.addEventListener('click', function () { select(t.id); });
    t.addEventListener('keydown', function (e) {
      var i = tabs.indexOf(t), n = null;
      if (e.key === 'ArrowRight') n = tabs[(i + 1) % tabs.length];
      if (e.key === 'ArrowLeft') n = tabs[(i - 1 + tabs.length) % tabs.length];
      if (n) { e.preventDefault(); n.focus(); select(n.id); }
    });
  });
  renderRuntime();
  select('t-daemon');

  var copy = document.getElementById('copy');
  copy.addEventListener('click', function () {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(cmdtext.textContent).then(function () {
      copy.textContent = 'Copied';
      copy.dataset.done = '1';
      setTimeout(function () { copy.textContent = 'Copy'; copy.dataset.done = '0'; }, 1600);
    }, function () {});
  });

  /* ---- theme --------------------------------------------------------- */

  var SUN = '<path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6Zm0-8.5a.6.6 0 0 1-.6-.6V.6a.6.6 0 0 1 1.2 0v1.3a.6.6 0 0 1-.6.6Zm0 13a.6.6 0 0 1-.6-.6v-1.3a.6.6 0 0 1 1.2 0v1.3a.6.6 0 0 1-.6.6ZM15.4 8.6h-1.3a.6.6 0 0 1 0-1.2h1.3a.6.6 0 0 1 0 1.2Zm-13.5 0H.6a.6.6 0 0 1 0-1.2h1.3a.6.6 0 0 1 0 1.2Zm11.3-4.9-.9.9a.6.6 0 0 1-.85-.85l.9-.9a.6.6 0 0 1 .85.85ZM4.05 13.1l-.9.9a.6.6 0 0 1-.85-.85l.9-.9a.6.6 0 0 1 .85.85Zm9.15.9-.9-.9a.6.6 0 0 1 .85-.85l.9.9a.6.6 0 0 1-.85.85ZM3.15 4.6l-.9-.9a.6.6 0 0 1 .85-.85l.9.9a.6.6 0 0 1-.85.85Z"/>';
  var MOON = '<path d="M13.9 9.6A6.2 6.2 0 0 1 6.4 2.1a.6.6 0 0 0-.83-.67 7.4 7.4 0 1 0 9 9 .6.6 0 0 0-.67-.83Z"/>';

  var themeBtn = document.getElementById('theme');
  var themeIcon = document.getElementById('theme-icon');
  function isDark() {
    return root.dataset.theme
      ? root.dataset.theme === 'dark'
      : window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  function syncTheme() {
    var d = isDark();
    themeIcon.innerHTML = d ? SUN : MOON;
    themeBtn.setAttribute('aria-label', d ? 'Switch to light theme' : 'Switch to dark theme');
  }
  themeBtn.addEventListener('click', function () {
    root.dataset.theme = isDark() ? 'light' : 'dark';
    syncTheme();
  });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncTheme);
  syncTheme();

  /* ---- the box -------------------------------------------------------
     Isometric 2:1, the same projection as openblox-mark.svg.

     Geometry is a well, not a slab: a solid 4x4 floor, then two courses of
     wall around its edge, leaving a 2x2 shaft you look down into. The
     tenant sits on that floor in the accent colour, below the rim and
     plainly visible through the opening — which is the whole argument, so
     it must not need a hover to be seen.

     Two things make it read as one structure rather than a heap of cubes:
     faces with a settled neighbour behind them are not drawn at all, and
     every drawn face is stroked in the page ground.
  -------------------------------------------------------------------- */

  var host = document.getElementById('blocks');
  var canvas = document.getElementById('stage');
  var ctx = canvas.getContext('2d');
  var reduceQ = window.matchMedia('(prefers-reduced-motion: reduce)');

  var N = 4;                          // 4x4 footprint, rim top at z = 3
  var PIECES = [], tenant = null;

  (function build() {
    var step = 34, t = 0;

    // The floor lands first, back to front.
    for (var s = 0; s <= (N - 1) * 2; s++) {
      for (var x = 0; x < N; x++) {
        var y = s - x;
        if (y < 0 || y >= N) continue;
        PIECES.push({ x: x, y: y, z: 0, delay: t, land: t + 520 });
        t += step;
      }
    }

    // Then the walls wind up around it, one course at a time.
    var ring = [];
    for (var i = 0; i < N; i++) ring.push([i, 0]);
    for (var j = 1; j < N; j++) ring.push([N - 1, j]);
    for (var k = N - 2; k >= 0; k--) ring.push([k, N - 1]);
    for (var m = N - 2; m >= 1; m--) ring.push([0, m]);

    for (var z = 1; z <= 2; z++) {
      for (var r = 0; r < ring.length; r++) {
        PIECES.push({ x: ring[r][0], y: ring[r][1], z: z, delay: t, land: t + 520 });
        t += step;
      }
    }

    tenant = { x: (N - 1) / 2, y: (N - 1) / 2, z: 1, scale: 1.3,
               delay: t + 320, land: t + 320 + 560 };
  })();

  var T = 22, DPR = 1, w = 0, h = 0, open = 0, openTarget = 0;

  function resize() {
    var r = canvas.getBoundingClientRect();
    if (!r.width) return;
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    w = r.width; h = r.height;
    canvas.width = Math.round(w * DPR);
    canvas.height = Math.round(h * DPR);
    T = Math.max(10, Math.min(w, h) / 10.4);
  }

  function poly(pts, fill, stroke) {
    ctx.beginPath();
    ctx.moveTo(pts[0][0], pts[0][1]);
    for (var i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
    if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = 1; ctx.stroke(); }
  }

  // openblox-mark.svg puts the most ink on the top face — correct for a 24px
  // glyph that has to read as a silhouette, wrong for a lit solid this size,
  // where it turns every top into one black plane. Here the light comes from
  // above, so the ramp is a real one and flips with the theme: on a light
  // ground more ink means darker, on a dark ground more ink means brighter.
  var RAMP = { top: 0.26, left: 0.58, right: 0.76 };
  var TENANT_RAMP = { top: 1.0, left: 0.78, right: 0.58 };

  function cube(gx, gy, gz, scale, ink, a, squash, lift, edge, ao, hide, ramp) {
    var sx = (gx - gy) * T;
    var sy = (gx + gy) * T * 0.5 - gz * T;
    var W = T * scale;
    var H = T * scale * squash;
    var c = 'rgba(' + ink + ',';
    var r = ramp || RAMP;
    var k = a * lift * (ao || 1);
    hide = hide || 0;
    // Faces with a settled neighbour behind them are inside the solid. Drawing
    // them is what turned this into a grid of cubes instead of one structure.
    if (!(hide & 1))
      poly([[sx, sy], [sx + W, sy + W / 2], [sx, sy + W], [sx - W, sy + W / 2]],
           c + Math.min(1, r.top * k) + ')', edge);
    if (!(hide & 2))
      poly([[sx - W, sy + W / 2], [sx, sy + W], [sx, sy + W + H], [sx - W, sy + W / 2 + H]],
           c + Math.min(1, r.left * k) + ')', edge);
    if (!(hide & 4))
      poly([[sx + W, sy + W / 2], [sx, sy + W], [sx, sy + W + H], [sx + W, sy + W / 2 + H]],
           c + Math.min(1, r.right * k) + ')', edge);
  }

  // Occupancy, for the face test above. Keyed on the final resting position.
  var AT = {};
  PIECES.forEach(function (b) { AT[b.x + ',' + b.y + ',' + b.z] = b; });
  function settledAt(x, y, z, t) {
    var n = AT[x + ',' + y + ',' + z];
    return n && t >= n.land;
  }

  var t0 = null, looked = false, lastPulse = -1e9;

  function draw(now) {
    if (!w || !h) { resize(); if (!w) return; }

    var cs = getComputedStyle(root);
    var ink = cs.getPropertyValue('--ink-rgb').trim() || '14,17,19';
    var acc = cs.getPropertyValue('--accent-rgb').trim() || '81,75,160';
    var bg = cs.getPropertyValue('--bg').trim() || '#f4f5f1';
    var still = reduceQ.matches;
    var t = still ? 1e6 : (t0 === null ? 0 : now - t0);
    var dark = isDark();

    RAMP = dark ? { top: 0.60, left: 0.34, right: 0.20 }
                : { top: 0.26, left: 0.58, right: 0.76 };
    var AO_IN = dark ? 0.55 : 1.45;          // the well is in shadow, either way

    open += (openTarget - open) * (still ? 1 : 0.14);

    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(w / 2, h / 2 - T * 1.6);

    // A contact shadow on the footprint, not a shadow per block: the ellipses
    // that produced read as saucers parked under the structure.
    var cy = (N - 1) * T * 0.5 + T * 1.25;
    poly([[0, cy - T * N * 0.5], [T * N, cy], [0, cy + T * N * 0.5], [-T * N, cy]],
         'rgba(' + ink + ',0.055)', null);

    var settled = tenant.land;
    var alive = t > settled;
    var breath = alive ? (Math.sin((t - settled) / 1400 * Math.PI * 2) + 1) / 2 : 0;
    if (alive) {
      var ph = Math.floor((t - settled) / 2800);
      if (ph * 2800 + settled > lastPulse) lastPulse = ph * 2800 + settled;
    }

    var items = [];

    PIECES.forEach(function (b) {
      var p = still ? 1 : Math.max(0, Math.min(1, (t - b.delay) / 520));
      var z = b.z + (1 - p * p) * 9;
      var dt = t - b.land;
      var squash = (!still && dt >= 0 && dt < 200) ? 1 - 0.24 * (1 - dt / 200) : 1;

      // The tenant's breath travels outward through the structure.
      var d = Math.abs(b.x - tenant.x) + Math.abs(b.y - tenant.y) + b.z * 0.5;
      var since = t - lastPulse - d * 70;
      var lift = (!still && since > 0 && since < 480)
        ? 1 + 0.26 * Math.sin(since / 480 * Math.PI) : 1;

      items.push({ x: b.x, y: b.y, z: z, s: 1, a: Math.min(1, p * 1.8),
                   squash: squash, lift: lift, tenant: false,
                   landed: p >= 1, t: t });
    });

    (function () {
      var b = tenant;
      var p = still ? 1 : Math.max(0, Math.min(1, (t - b.delay) / 560));
      var z = b.z + (1 - p * p) * 9;
      if (p >= 1 && !still) {
        z += breath * 0.16;                                  // it breathes
        var cyc = ((t - b.land) % 7600) / 7600;
        if (cyc > 0.03 && cyc < 0.22) {                      // and tries the rim
          z = b.z + Math.sin((cyc - 0.03) / 0.19 * Math.PI) * 1.35;
        }
      }
      items.push({ x: b.x, y: b.y, z: z, s: b.scale, a: Math.min(1, p * 1.8),
                   squash: 1, lift: 1 + breath * 0.10, tenant: true,
                   landed: p >= 1, t: t });
    })();

    items.sort(function (a, b) { return (a.x + a.y) - (b.x + b.y) || a.z - b.z; });

    items.forEach(function (b) {
      if (b.a <= 0.01) return;
      // Looking in turns the near courses to glass. The far walls never move:
      // the box opens to you, it does not open for what is inside it.
      var near = !b.tenant && b.z > 0 && (b.x + b.y) > (N - 1);
      var a = b.a * (near ? 1 - open * 0.86 : 1);
      if (a <= 0.01) return;
      // Cells at the bottom of the shaft sit in their own shadow.
      var inShaft = !b.tenant && b.z === 0 &&
                    b.x > 0 && b.x < N - 1 && b.y > 0 && b.y < N - 1;

      var hide = 0;
      if (!b.tenant && b.landed) {
        if (settledAt(b.x, b.y, b.z + 1, b.t)) hide |= 1;
        if (settledAt(b.x, b.y + 1, b.z, b.t)) hide |= 2;
        if (settledAt(b.x + 1, b.y, b.z, b.t)) hide |= 4;
      }

      cube(b.x, b.y, b.z, b.s, b.tenant ? acc : ink, a, b.squash, b.lift,
           near && open > 0.2 ? null : bg, inShaft ? AO_IN : 1, hide,
           b.tenant ? TENANT_RAMP : null);
    });

    ctx.restore();

    if (!still && t > tenant.land + 1400 && !looked) host.dataset.hint = '1';
  }

  function frame(now) {
    if (t0 === null) t0 = now;
    draw(now);
    requestAnimationFrame(frame);
  }

  function lookIn(on) {
    openTarget = on ? 1 : 0;
    host.dataset.open = on ? '1' : '0';
    if (on) { looked = true; host.dataset.hint = '0'; }
  }
  host.addEventListener('pointerenter', function () { lookIn(true); });
  host.addEventListener('pointerleave', function () { lookIn(false); });
  host.addEventListener('focus', function () { lookIn(true); });
  host.addEventListener('blur', function () { lookIn(false); });
  host.addEventListener('click', function () { t0 = null; lastPulse = -1e9; });

  if (window.ResizeObserver) new ResizeObserver(resize).observe(canvas);
  window.addEventListener('resize', resize);
  resize();
  if (reduceQ.matches) { draw(0); } else { requestAnimationFrame(frame); }
})();
