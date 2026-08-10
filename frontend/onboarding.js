/*
 * onboarding.js — Gamified first-run wizard + Basic/Advanced environment control.
 *
 * Loaded AFTER the main inline script, so it can use its globals (API, and — after
 * finishing — loadLakeraConfig / loadLlmConfig to refresh the header badges) and
 * the window.Scenarios helper from scenarios.js.
 *
 * Flow: Welcome → Lakera key + region → LLM provider/URL/key → pick model →
 * defense-in-depth tutorial (CP0–CP3) → choose Basic or Advanced environment.
 * The wizard talks to the same REST endpoints the Settings panels use, so nothing
 * about the backend needs to know it exists.
 */
(function () {
  'use strict';

  var API = window.API || window.location.origin;
  var LS_ENV = 'ai-demo-env';          // 'basic' | 'advanced'
  var LS_ONBOARDED = 'ai-demo-onboarded';

  var state = {
    step: 0,
    lakeraKey: '', lakeraEndpoint: '',
    provider: '', baseUrl: '', apiKey: '', model: '',
    models: [], regions: [], presets: {}, connectionOk: false,
  };

  // Step metadata for the progress stepper. The tutorial + env choice are the
  // reward at the end, so they carry an XP flourish.
  var STEP_LABELS = ['Welcome', 'Lakera', 'Model', 'Learn', 'Launch'];
  var TOTAL_XP = 100;

  var overlay = null, elBody = null, elNav = null, elProgress = null, elSteps = null, elXp = null;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function ico(name) { return '<svg class="ic"><use href="#i-' + name + '"></use></svg>'; }
  function byId(id) { return document.getElementById(id); }

  // ── Shell ──────────────────────────────────────────────────────────────────
  function build() {
    overlay = document.createElement('div');
    overlay.className = 'ob-overlay';
    overlay.id = 'ob-overlay';
    overlay.innerHTML =
      '<div class="ob-modal" role="dialog" aria-modal="true" aria-label="Setup wizard">' +
        '<div class="ob-header">' +
          '<div class="ob-header-top">' +
            '<div class="ob-title">' + ico('shield-check') + '<span>Guardrails Setup</span></div>' +
            '<div class="ob-xp" id="ob-xp">0 XP</div>' +
          '</div>' +
          '<div class="ob-steps" id="ob-steps"></div>' +
          '<div class="ob-progress"><div class="ob-progress-bar" id="ob-progress"></div></div>' +
        '</div>' +
        '<div class="ob-body" id="ob-body"></div>' +
        '<div class="ob-nav" id="ob-nav"></div>' +
      '</div>';
    document.body.appendChild(overlay);
    elBody = byId('ob-body'); elNav = byId('ob-nav');
    elProgress = byId('ob-progress'); elSteps = byId('ob-steps'); elXp = byId('ob-xp');
  }

  // ── Step definitions ────────────────────────────────────────────────────────
  // Each returns { title, sub, body(), onEnter?(), canNext?(), onNext?() (async) }.
  var STEPS = [
    // 0 — Welcome
    {
      title: 'Welcome to the Lakera Guardrails demo',
      sub: 'A three-minute setup, then a quick tour of how Lakera Guard stops AI attacks. Let’s harden your assistant.',
      body: function () {
        return '<div class="ob-welcome">' +
          '<div class="ob-welcome-badge">' + ico('shield-check') + '</div>' +
          '<div class="ob-perks">' +
            perk('key', 'Connect Lakera Guard', 'Your key + region secure every checkpoint.') +
            perk('cpu', 'Wire up your LLM', 'Any OpenAI-compatible provider — cloud or local.') +
            perk('activity', 'Learn defense-in-depth', 'See CP0–CP3 stop real OWASP attacks live.') +
          '</div></div>';
      },
    },
    // 1 — Lakera key + region
    {
      title: 'Step 1 · Connect Lakera Guard',
      sub: 'Your Lakera key authenticates every Guard scan. Pick the region closest to you.',
      onEnter: loadRegions,
      body: function () {
        var opts = state.regions.map(function (r) {
          return '<option value="' + esc(r.url) + '"' + (r.url === state.lakeraEndpoint ? ' selected' : '') + '>' + esc(r.label) + '</option>';
        }).join('');
        return field('Lakera Guard API key', '<input type="password" id="ob-lakera-key" autocomplete="off" spellcheck="false" placeholder="lk_…" value="' + esc(state.lakeraKey) + '" oninput="Onboarding._set(\'lakeraKey\', this.value)">',
          'Stored server-side and never echoed back.') +
          field('Guard region (base URL)', '<select id="ob-lakera-region" onchange="Onboarding._set(\'lakeraEndpoint\', this.value)">' + (opts || '<option>Loading…</option>') + '</select>',
            'Community is the default; regional endpoints reduce latency.') +
          '<div class="ob-status" id="ob-lakera-status"></div>';
      },
      canNext: function () { return state.lakeraKey.trim().length > 0; },
      onNext: async function () {
        setStatus('ob-lakera-status', 'loading', 'Saving…');
        var body = { api_key: state.lakeraKey, endpoint: state.lakeraEndpoint || null };
        var res = await fetch(API + '/api/lakera-config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        if (!res.ok) { var e = await res.json().catch(function () { return {}; }); throw new Error(e.detail || 'Could not save Lakera config.'); }
      },
    },
    // 2 — LLM provider + base URL + key
    {
      title: 'Step 2 · Choose your model provider',
      sub: 'Point the assistant at any OpenAI-compatible endpoint. Local providers (LM Studio, Ollama, oMLX) need no key.',
      onEnter: loadPresets,
      body: function () {
        var opts = Object.keys(state.presets).map(function (id) {
          var p = state.presets[id];
          return '<option value="' + esc(id) + '"' + (id === state.provider ? ' selected' : '') + '>' + esc(p.label || id) + '</option>';
        }).join('');
        return field('Provider', '<select id="ob-provider" onchange="Onboarding._onProvider(this.value)">' + (opts || '<option>Loading…</option>') + '</select>') +
          field('Base URL', '<input type="text" id="ob-base-url" spellcheck="false" placeholder="https://…/v1" value="' + esc(state.baseUrl) + '" oninput="Onboarding._set(\'baseUrl\', this.value)">',
            providerHint()) +
          field('API key', '<input type="password" id="ob-api-key" autocomplete="off" spellcheck="false" placeholder="Required for cloud · blank for local" value="' + esc(state.apiKey) + '" oninput="Onboarding._set(\'apiKey\', this.value)">') +
          '<button type="button" class="ob-btn" id="ob-test-conn" onclick="Onboarding._testConnection()">' + ico('plug') + ' Test connection</button>' +
          '<div class="ob-status" id="ob-conn-status">' +
            (state.connectionOk ? '<span class="ob-status-ok">' + ico('shield-check') + ' Connected ✓</span>' : '') +
          '</div>';
      },
      // The Model step stays locked until a successful (200 OK) connection (req 3).
      canNext: function () { return state.baseUrl.trim().length > 0 && state.connectionOk === true; },
    },
    // 3 — Fetch + pick a model
    {
      title: 'Step 3 · Pick a model',
      sub: 'Load the models your provider serves, then choose the one to test.',
      body: function () {
        return '<button type="button" class="ob-btn" id="ob-fetch-models" onclick="Onboarding._fetchModels()">' + ico('download') + ' Load available models</button>' +
          '<div class="ob-status" id="ob-model-status"></div>' +
          '<div class="ob-models" id="ob-model-list"></div>';
      },
      onEnter: function () { if (state.models.length) renderModels(); },
      canNext: function () { return state.model.trim().length > 0; },
      onNext: async function () {
        setStatus('ob-model-status', 'loading', 'Saving provider…');
        var body = { provider: state.provider, base_url: state.baseUrl, model: state.model, api_key: state.apiKey === '' ? null : state.apiKey };
        var res = await fetch(API + '/api/llm-config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        if (!res.ok) { var e = await res.json().catch(function () { return {}; }); throw new Error(e.detail || 'Could not save the LLM provider.'); }
      },
    },
    // 4 — Educational scenarios (defense-in-depth)
    {
      title: 'Defense-in-depth · the four checkpoints',
      sub: 'Lakera Guard scans four control points. Pick an attack below and watch where each one gets mitigated.',
      onEnter: function () { if (window.Scenarios) window.Scenarios.initFlow(); },
      body: function () {
        if (!window.Scenarios) return '<div class="ob-hint">Scenario content unavailable.</div>';
        return window.Scenarios.renderCards() + window.Scenarios.renderFlow();
      },
    },
    // 5 — Environment choice
    {
      title: 'You’re all set 🎉',
      sub: 'Choose how you want to work. You can switch anytime from the header.',
      body: function () {
        return '<div class="ob-env-grid">' +
          '<button type="button" class="ob-env-card" onclick="Onboarding._finish(\'basic\')">' +
            ico('shield-check') + '<b>Stay in Basic</b><p>A focused view: chat, the Guard toggle, and the live CP1–CP3 pipeline. Perfect for demos and learning.</p></button>' +
          '<button type="button" class="ob-env-card" onclick="Onboarding._finish(\'advanced\')">' +
            ico('sliders') + '<b>Enter Advanced</b><p>The full workbench: one-shot testing, datasets, strategies, per-checkpoint projects, and system-prompt tools.</p></button>' +
        '</div>';
      },
    },
  ];

  function perk(icon, title, sub) {
    return '<div class="ob-perk">' + ico(icon) + '<span><b>' + esc(title) + '</b>' + esc(sub) + '</span></div>';
  }
  function field(label, control, hint) {
    return '<div class="ob-field"><label>' + esc(label) + '</label>' + control +
      (hint ? '<div class="ob-hint">' + esc(hint) + '</div>' : '') + '</div>';
  }
  function providerHint() {
    var p = state.presets[state.provider];
    return p && p.hint ? p.hint : 'OpenAI-compatible /chat/completions endpoint.';
  }
  function setStatus(id, kind, msg) {
    var el = byId(id); if (!el) return;
    el.className = 'ob-status ' + kind;
    el.innerHTML = (kind === 'loading' ? ico('loader') : kind === 'error' ? ico('alert-triangle') : ico('shield-check')) + '<span>' + esc(msg) + '</span>';
  }

  // ── Data loaders ─────────────────────────────────────────────────────────────
  async function loadRegions() {
    if (state.regions.length) return;
    try {
      var d = await (await fetch(API + '/api/lakera-config')).json();
      state.regions = Array.isArray(d.regions) ? d.regions : [];
      if (!state.lakeraEndpoint && d.endpoint) state.lakeraEndpoint = d.endpoint;
      var sel = byId('ob-lakera-region');
      if (sel) sel.innerHTML = state.regions.map(function (r) {
        return '<option value="' + esc(r.url) + '"' + (r.url === state.lakeraEndpoint ? ' selected' : '') + '>' + esc(r.label) + '</option>';
      }).join('');
    } catch (e) { /* offline — leave the select empty, key entry still works */ }
  }
  async function loadPresets() {
    if (Object.keys(state.presets).length) return;
    try {
      var d = await (await fetch(API + '/api/llm-config')).json();
      state.presets = d.presets || {};
      if (!state.provider) {
        var first = Object.keys(state.presets)[0] || '';
        setProvider(first);
      }
      render();
    } catch (e) { /* offline — user can still type a base URL */ }
  }
  function setProvider(id) {
    state.provider = id;
    var p = state.presets[id] || {};
    if (p.base_url) state.baseUrl = p.base_url;
    state.models = []; state.model = '';
    state.connectionOk = false;         // provider changed → must re-test (req 3)
    pushToAppState();
  }

  // Push the (non-empty) wizard values into the global store so Advanced Mode and
  // the One-Shot Test see them without re-entry.
  function pushToAppState() {
    if (!window.AppState) return;
    var p = {};
    if (state.lakeraEndpoint) p.lakeraBaseUrl = state.lakeraEndpoint;
    if (state.lakeraKey) p.lakeraKey = state.lakeraKey;
    if (state.provider) p.provider = state.provider;
    if (state.baseUrl) p.providerUrl = state.baseUrl;
    if (state.apiKey) p.providerKey = state.apiKey;
    if (state.model) p.model = state.model;
    window.AppState.set(p);
  }

  function refreshNext() {
    var btn = byId('ob-next'), s = STEPS[state.step];
    if (btn && s.canNext) btn.disabled = !s.canNext();
  }

  // req 3: probe the provider (POST /api/llm-config/test). Only a 200 OK unlocks
  // the Model step. Reuses the returned model list so Step 3 is pre-populated.
  async function testConnection() {
    setStatus('ob-conn-status', 'loading', 'Testing ' + (state.baseUrl || 'provider') + '…');
    state.connectionOk = false; refreshNext();
    try {
      var body = { provider: state.provider, base_url: state.baseUrl, model: state.model,
                   api_key: state.apiKey === '' ? null : state.apiKey };
      var res = await fetch(API + '/api/llm-config/test', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      var d = await res.json();
      if (!res.ok || !d.ok) {
        setStatus('ob-conn-status', 'error', d.detail || d.error || 'Provider unreachable.');
        return;
      }
      state.connectionOk = true;
      state.models = d.models || [];
      setStatus('ob-conn-status', 'success',
        'Connected ✓' + (state.models.length ? ' — ' + state.models.length + ' models available.' : ''));
      refreshNext();
    } catch (e) {
      setStatus('ob-conn-status', 'error', e.message);
    }
  }

  async function fetchModels() {
    setStatus('ob-model-status', 'loading', 'Contacting ' + (state.baseUrl || 'provider') + '…');
    try {
      var body = { provider: state.provider, base_url: state.baseUrl, model: state.model, api_key: state.apiKey === '' ? null : state.apiKey };
      var res = await fetch(API + '/api/llm-config/test', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      var d = await res.json();
      if (!res.ok) { setStatus('ob-model-status', 'error', d.detail || 'Provider unreachable.'); return; }
      if (!d.ok) { setStatus('ob-model-status', 'error', d.error || 'Provider unreachable.'); return; }
      state.models = d.models || [];
      if (!state.models.length) { setStatus('ob-model-status', 'error', 'Connected, but no models were advertised. You can type a model id in Advanced mode.'); return; }
      setStatus('ob-model-status', 'success', state.models.length + ' models found — pick one.');
      renderModels();
    } catch (e) { setStatus('ob-model-status', 'error', e.message); }
  }
  function renderModels() {
    var list = byId('ob-model-list'); if (!list) return;
    // Built with DOM APIs, NOT innerHTML. These ids come from whatever
    // OpenAI-compatible endpoint the user pointed us at, and an onclick=""
    // attribute is not a context esc() can protect: the HTML parser decodes
    // &#39; back to a quote before the handler is compiled as JS, so an id
    // could close the string literal and run in our origin — which would hand
    // that endpoint the Lakera key too, not just its own. textContent and
    // addEventListener have no such parsing step.
    list.textContent = '';
    state.models.forEach(function (m) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ob-model' + (m === state.model ? ' active' : '');
      btn.title = m;
      btn.textContent = m;
      btn.addEventListener('click', function () { window.Onboarding._pickModel(m); });
      list.appendChild(btn);
    });
  }

  // ── Render ───────────────────────────────────────────────────────────────────
  function renderStepper() {
    elSteps.innerHTML = STEP_LABELS.map(function (lbl, i) {
      var cls = i === state.step ? 'active' : (i < state.step ? 'done' : '');
      var inner = i < state.step ? ico('shield-check') : (i + 1);
      var sep = i < STEP_LABELS.length - 1 ? '<span class="ob-step-sep"></span>' : '';
      return '<span class="ob-step-dot ' + cls + '"><span class="num">' + inner + '</span>' + esc(lbl) + '</span>' + sep;
    }).join('');
    var pct = Math.round((state.step / (STEPS.length - 1)) * 100);
    elProgress.style.width = pct + '%';
    elXp.textContent = Math.round((state.step / (STEPS.length - 1)) * TOTAL_XP) + ' / ' + TOTAL_XP + ' XP';
  }
  function render() {
    if (!overlay) return;
    var s = STEPS[state.step];
    renderStepper();
    elBody.innerHTML = '<h3 class="ob-step-title">' + esc(s.title) + '</h3>' +
      '<p class="ob-step-sub">' + esc(s.sub) + '</p>' + s.body();
    renderNav();
    if (s.onEnter) s.onEnter();
    if (window.AppState) window.AppState.apply();   // prefill fields from the global store
  }
  function renderNav() {
    var s = STEPS[state.step];
    var isLast = state.step === STEPS.length - 1;
    var backBtn = state.step > 0
      ? '<button type="button" class="ob-btn ghost" onclick="Onboarding._back()">Back</button>' : '';
    var nextBtn = '';
    if (!isLast) {
      var label = state.step === 0 ? 'Get started' : (state.step === STEPS.length - 2 ? 'Finish tour' : 'Continue');
      var disabled = (s.canNext && !s.canNext()) ? ' disabled' : '';
      nextBtn = '<button type="button" class="ob-btn primary" id="ob-next" onclick="Onboarding._next()"' + disabled + '>' + esc(label) + ' ' + ico('zap') + '</button>';
    }
    elNav.innerHTML = backBtn + '<span class="spacer"></span>' + nextBtn;
  }

  // ── Navigation ───────────────────────────────────────────────────────────────
  async function next() {
    var s = STEPS[state.step];
    if (s.canNext && !s.canNext()) return;
    if (s.onNext) {
      var btn = byId('ob-next'); if (btn) btn.disabled = true;
      try { await s.onNext(); }
      catch (e) {
        if (byId(stepStatusId())) setStatus(stepStatusId(), 'error', e.message);
        if (btn) btn.disabled = false;
        return;
      }
    }
    state.step = Math.min(state.step + 1, STEPS.length - 1);
    render();
  }
  function stepStatusId() {
    return state.step === 1 ? 'ob-lakera-status' : state.step === 3 ? 'ob-model-status' : '';
  }
  function back() { state.step = Math.max(state.step - 1, 0); render(); }

  // ── Environment mode ─────────────────────────────────────────────────────────
  function applyEnvironment(mode) {
    var basic = mode === 'basic';
    document.body.classList.toggle('env-basic', basic);
    document.body.classList.toggle('env-advanced', !basic);
    localStorage.setItem(LS_ENV, basic ? 'basic' : 'advanced');
    var sw = byId('env-switch');
    if (sw) {
      var span = sw.querySelector('.env-mode');
      if (span) span.textContent = basic ? 'Basic' : 'Advanced';
      sw.title = basic ? 'Basic view — click for Advanced' : 'Advanced view — click for Basic';
    }
  }
  function toggleEnv() {
    var basic = document.body.classList.contains('env-basic');
    applyEnvironment(basic ? 'advanced' : 'basic');
  }
  function finish(mode) {
    localStorage.setItem(LS_ONBOARDED, '1');
    applyEnvironment(mode);
    close();
    // Refresh the app's own settings badges with what the wizard configured.
    try { if (typeof loadLakeraConfig === 'function') loadLakeraConfig(); } catch (e) {}
    try { if (typeof loadLlmConfig === 'function') loadLlmConfig(); } catch (e) {}
  }

  // Seed the wizard from the global store so values entered in Advanced Mode (or a
  // previous run) don't have to be re-typed here.
  function seedFromAppState() {
    if (!window.AppState) return;
    var a = window.AppState.getAll();
    if (a.lakeraBaseUrl) state.lakeraEndpoint = a.lakeraBaseUrl;
    if (a.lakeraKey) state.lakeraKey = a.lakeraKey;
    if (a.provider) state.provider = a.provider;
    if (a.providerUrl) state.baseUrl = a.providerUrl;
    if (a.providerKey) state.apiKey = a.providerKey;
    if (a.model) state.model = a.model;
  }

  function open() { if (!overlay) build(); seedFromAppState(); state.step = 0; render(); overlay.classList.add('open'); }
  function close() { if (overlay) overlay.classList.remove('open'); }
  function restart() { open(); }

  // ── Boot ─────────────────────────────────────────────────────────────────────
  function boot() {
    applyEnvironment(localStorage.getItem(LS_ENV) || 'advanced');
    if (!localStorage.getItem(LS_ONBOARDED)) open();
  }

  // Public API (also the target of inline onclick handlers).
  window.Onboarding = {
    open: open, restart: restart, toggleEnv: toggleEnv, applyEnvironment: applyEnvironment,
    _next: next, _back: back, _finish: finish,
    _set: function (k, v) {
      state[k] = v;
      // Any change to the endpoint or key invalidates a prior successful test.
      if (k === 'baseUrl' || k === 'apiKey') state.connectionOk = false;
      if (window.AppState) pushToAppState();
      refreshNext();
    },
    _onProvider: function (id) { setProvider(id); render(); },
    _testConnection: testConnection,
    _fetchModels: fetchModels,
    _pickModel: function (m) { state.model = m; pushToAppState(); renderModels(); var btn = byId('ob-next'); if (btn) btn.disabled = false; },
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
