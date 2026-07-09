/*
 * appstate.js — Global API-config store shared across Basic Mode (onboarding
 * wizard), Advanced Mode (Settings panels), and the One-Shot Test.
 *
 * The four values — Lakera API Key, Lakera Base URL, Model Provider URL, Model
 * Provider Key (+ provider/model) — live in one place so a user never re-enters
 * them when moving between surfaces. Typing in any field mirrors to its twin in
 * the other surface automatically (event delegation, so it also covers the
 * onboarding fields that are created on the fly).
 *
 * SECURITY: raw API keys are NEVER written to localStorage (XSS-exfiltration
 * risk). Secrets are held in memory for the session and persisted server-side
 * (the source of truth, which never echoes them back). Only non-secret values
 * (base URLs, provider, model) persist to localStorage for cross-reload recall.
 */
(function () {
  'use strict';

  var API = window.API || window.location.origin;
  var LS_KEY = 'ai-demo-appstate';
  var SECRET = { lakeraKey: 1, providerKey: 1 };     // never persisted to localStorage

  // Which input fields (Advanced + onboarding) map to which state value. Twins
  // stay in sync; when one changes, the other is updated silently.
  var FIELD_MAP = {
    'lakera-endpoint': 'lakeraBaseUrl', 'ob-lakera-region': 'lakeraBaseUrl',
    'lakera-key': 'lakeraKey', 'ob-lakera-key': 'lakeraKey',
    'llm-base-url': 'providerUrl', 'ob-base-url': 'providerUrl',
    'llm-api-key': 'providerKey', 'ob-api-key': 'providerKey',
    'llm-provider': 'provider', 'ob-provider': 'provider',
    'llm-model': 'model',
  };
  // Reverse: state value → [field ids] to mirror into.
  var TWINS = {};
  Object.keys(FIELD_MAP).forEach(function (id) {
    (TWINS[FIELD_MAP[id]] = TWINS[FIELD_MAP[id]] || []).push(id);
  });

  var data = {
    lakeraKey: '', lakeraBaseUrl: '', providerUrl: '', providerKey: '',
    provider: '', model: '', lakeraKeySet: false, providerKeySet: false,
  };
  var subs = [];

  function persist() {
    try {
      var out = {};
      Object.keys(data).forEach(function (k) { if (!SECRET[k]) out[k] = data[k]; });
      localStorage.setItem(LS_KEY, JSON.stringify(out));
    } catch (e) { /* private mode / quota — non-fatal */ }
  }
  function restore() {
    try {
      var saved = JSON.parse(localStorage.getItem(LS_KEY) || '{}');
      Object.keys(saved).forEach(function (k) { if (k in data && !SECRET[k]) data[k] = saved[k]; });
    } catch (e) { /* ignore */ }
  }

  // Write a value into every twin field except the one that originated it (so
  // typing in field A fills field B without firing another input event → no loop).
  function mirror(stateKey, exceptId) {
    (TWINS[stateKey] || []).forEach(function (id) {
      if (id === exceptId) return;
      var el = document.getElementById(id);
      if (el && el.value !== data[stateKey]) el.value = data[stateKey];
    });
  }
  function mirrorAll() { Object.keys(TWINS).forEach(function (k) { mirror(k, null); }); }

  function setInternal(stateKey, value, sourceId, notify) {
    if (data[stateKey] === value) { if (sourceId) mirror(stateKey, sourceId); return; }
    data[stateKey] = value;
    if (!SECRET[stateKey]) persist();
    mirror(stateKey, sourceId);
    if (notify !== false) subs.forEach(function (fn) { try { fn(stateKey, value, data); } catch (e) {} });
  }

  function onFieldEvent(e) {
    var stateKey = FIELD_MAP[e.target && e.target.id];
    if (!stateKey) return;
    setInternal(stateKey, e.target.value, e.target.id, true);
  }

  // Pull the authoritative config from the server and seed the store.
  async function hydrate() {
    try {
      var llm = await (await fetch(API + '/api/llm-config')).json();
      if (llm && llm.config) {
        setInternal('provider', llm.config.provider || '', null, false);
        setInternal('providerUrl', llm.config.base_url || '', null, false);
        setInternal('model', llm.config.model || '', null, false);
        data.providerKeySet = !!llm.config.api_key_set;
      }
    } catch (e) { /* offline — keep restored localStorage values */ }
    try {
      var lak = await (await fetch(API + '/api/lakera-config')).json();
      if (lak) {
        if (lak.endpoint) setInternal('lakeraBaseUrl', lak.endpoint, null, false);
        data.lakeraKeySet = !!lak.api_key_set;
      }
    } catch (e) { /* offline */ }
    mirrorAll();
  }

  window.AppState = {
    get: function (k) { return data[k]; },
    getAll: function () { return Object.assign({}, data); },
    // Programmatic update (used by onboarding + save flows). Mirrors + notifies.
    set: function (patch) {
      Object.keys(patch || {}).forEach(function (k) {
        if (k in data) setInternal(k, patch[k], null, true);
      });
    },
    subscribe: function (fn) { subs.push(fn); return function () { subs = subs.filter(function (f) { return f !== fn; }); }; },
    apply: mirrorAll,           // push the store into any fields currently in the DOM
    hydrate: hydrate,
    fields: FIELD_MAP,
  };

  // Self-wire: capture-phase delegation covers fields created later (onboarding).
  document.addEventListener('input', onFieldEvent, true);
  document.addEventListener('change', onFieldEvent, true);

  restore();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', hydrate);
  else hydrate();
})();
